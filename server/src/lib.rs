use std::collections::HashMap;

use migration::MigratorTrait;
use sea_orm::{prelude::Uuid, Database, DatabaseConnection};
use serde::Deserialize;
use tokio::sync::Mutex;

mod entities;

#[derive(Deserialize)]
pub struct Config {
    pub database_uri: String,
}

type ConnectionsTable = Mutex<HashMap<Uuid, i32>>;

pub struct ServerState {
    db: DatabaseConnection,
    connections: ConnectionsTable,
}

impl ServerState {
    async fn inc_conn(&self, id: Uuid) {
        let mut conns_lock = self.connections.lock().await;
        *conns_lock.entry(id).or_default() += 1;
    }
    async fn dec_conn(&self, id: Uuid) {
        let mut conns_lock = self.connections.lock().await;
        conns_lock.entry(id).and_modify(|v| {
            if *v > 0 {
                *v -= 1
            }
        });
    }

    pub async fn new(config: Config) -> eyre::Result<ServerState> {
        let connection = Database::connect(config.database_uri).await?;

        migration::Migrator::up(&connection, None).await?;

        Ok(Self {
            db: connection,
            connections: Mutex::new(HashMap::new()),
        })
    }
}

pub mod v1_server {
    use std::sync::Arc;

    use proto::software::v1::{self, authority_server::AuthorityServer, ServerMessage};

    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;

    use crate::ServerState;

    const CHANNEL_BUFFER: usize = 100;

    mod connection {
        use chrono::Utc;
        use proto::software::v1::{
            client_message, info_request, info_response, server_message, ChronoExt, InfoResponse,
            LicenseError, ServerHearthbeat, ServerHearthbeatData, SigningKey,
        };
        use sea_orm::{prelude::Uuid, EntityTrait};
        use tokio::sync::mpsc;

        use crate::{
            entities::{self, license},
            ServerState,
        };

        use super::v1;
        use std::sync::Arc;
        use v1::{ClientMessage, ServerMessage};

        type ServerTX = mpsc::Sender<Result<ServerMessage, tonic::Status>>;
        type ServerRX = tonic::Streaming<v1::ClientMessage>;

        pub struct ConnectionData {
            signing_key: SigningKey,
            license: license::Model,
        }

        pub struct Connection {
            rx: ServerRX,
            tx: ServerTX,
            data: ConnectionData,
        }

        impl Connection {
            async fn work(mut self) {
                loop {
                    let Ok(Ok(Some(ClientMessage {
                        data: Some(client_message::Data::Hearthbeat(client_msg)),
                    }))) =
                        tokio::time::timeout(v1::PING_PERIOD + v1::PING_GRACE, self.rx.message())
                            .await
                    else {
                        return;
                    };

                    let err = match check_permission(&self.data.license) {
                        Ok(_) => None,
                        Err(e) => Some(e.into()),
                    };

                    let hearthbeat_data = ServerHearthbeatData { error: err };

                    let signature = v1::SignatureSchema::sign(
                        &hearthbeat_data,
                        client_msg.nonce,
                        &mut self.data.signing_key,
                    );

                    let response = ServerMessage {
                        data: Some(server_message::Data::Heathbeat(ServerHearthbeat {
                            nonce: client_msg.nonce,
                            signature,
                            data: Some(hearthbeat_data),
                        })),
                    };

                    let _ = self.tx.send(Ok(response)).await;
                }
            }
        }

        async fn try_get_request(
            rx: &mut ServerRX,
        ) -> Result<(info_request::Request, u64), tonic::Status> {
            let Ok(Ok(Some(msg))) = tokio::time::timeout(v1::HANDSHAKE_TIMEOUT, rx.message()).await
            else {
                return Err(tonic::Status::deadline_exceeded("took too long to connect"));
            };

            let v1::ClientMessage {
                data: Some(v1::client_message::Data::Auth(auth)),
            } = msg
            else {
                return Err(tonic::Status::invalid_argument(
                    "expected auth request first",
                ));
            };

            let Some(request) = auth.req else {
                return Err(tonic::Status::invalid_argument("expected auth request"));
            };
            Ok((request, auth.nonce))
        }

        pub fn check_permission(license: &license::Model) -> Result<(), LicenseError> {
            if Utc::now() > license.expiry {
                return Err(LicenseError::Expired);
            }

            Ok(())
        }
        pub async fn check_permission_connect(
            license: &license::Model,
            state: &ServerState,
        ) -> Result<(), LicenseError> {
            check_permission(license)?;
            if let Some(connections_limit) = license.policy_limit_connections {
                let mut connections_lock = state.connections.lock().await;

                let key_entry = connections_lock.entry(license.id.clone()).or_insert(0);

                if *key_entry > connections_limit {
                    return Err(LicenseError::TooManySessions);
                }
            }
            Ok(())
        }

        async fn try_get_license(
            state: &ServerState,
            request: info_request::Request,
        ) -> Result<license::Model, LicenseError> {
            let license = entities::license::Entity::find_by_id(
                request
                    .key_id
                    .parse::<Uuid>()
                    .map_err(|_| LicenseError::InvalidKey)?,
            )
            .one(&state.db)
            .await
            .map_err(|_| LicenseError::Internal)?;

            let Some(license) = license else {
                return Err(LicenseError::InvalidKey);
            };

            check_permission_connect(&license, state).await?;

            Ok(license)
        }

        pub async fn handle(state: Arc<ServerState>, tx: ServerTX, mut rx: ServerRX) {
            let (request, nonce) = match try_get_request(&mut rx).await {
                Ok(inner) => inner,

                Err(err) => {
                    let _ = tx.send(Err(err)).await;
                    return;
                } // if connection closed meanwhile, we don't care
            };

            let license = match try_get_license(state.as_ref(), request).await {
                Ok(license) => license,
                Err(err) => {
                    let _ = tx
                        .send(Ok(ServerMessage {
                            data: Some(server_message::Data::Auth(InfoResponse {
                                nonce,
                                signature: Vec::new(),
                                result: Some(info_response::Result::Error(err.into())),
                            })),
                        }))
                        .await;

                    return;
                }
            };

            let Ok(Some(app)) = entities::app::Entity::find_by_id(license.app)
                .one(&state.db)
                .await
            else {
                let _ = tx
                    .send(Err(tonic::Status::internal("database error")))
                    .await;
                return;
            };

            let Ok(mut key) = SigningKey::try_from(app.private_key.as_slice()) else {
                let _ = tx
                    .send(Err(tonic::Status::internal("database error")))
                    .await;
                return;
            };

            let response = info_response::Response {
                expiry: Some(license.expiry.to_protobuf()),
                extra_data: license.extra_data.to_string(),
            };

            let signature = v1::SignatureSchema::sign(&response, nonce, &mut key);

            let response = ServerMessage {
                data: Some(server_message::Data::Auth(InfoResponse {
                    nonce,
                    signature,
                    result: Some(info_response::Result::Ok(response)),
                })),
            };

            if tx.send(Ok(response)).await.is_err() {
                return;
            }

            // mark new connection
            let license_id = license.id.clone();
            state.inc_conn(license_id.clone()).await;

            let connection = Connection {
                rx,
                tx,
                data: ConnectionData {
                    signing_key: key,
                    license,
                },
            };

            connection.work().await;

            state.dec_conn(license_id).await;
        }
    }

    pub struct SoftwareV1 {
        state: Arc<ServerState>,
    }

    impl SoftwareV1 {
        pub fn new(state: ServerState) -> AuthorityServer<Self> {
            AuthorityServer::new(Self {
                state: Arc::new(state),
            })
        }
    }

    #[tonic::async_trait]
    impl v1::authority_server::Authority for SoftwareV1 {
        type HearthbeatStream = ReceiverStream<Result<ServerMessage, tonic::Status>>;

        async fn hearthbeat(
            &self,
            request: tonic::Request<tonic::Streaming<v1::ClientMessage>>,
        ) -> std::result::Result<tonic::Response<Self::HearthbeatStream>, tonic::Status> {
            let stream = request.into_inner();

            let (server_tx, server_rx) = mpsc::channel(CHANNEL_BUFFER);

            tokio::task::spawn(connection::handle(self.state.clone(), server_tx, stream));

            Ok(tonic::Response::new(ReceiverStream::new(server_rx)))
        }
    }
}
