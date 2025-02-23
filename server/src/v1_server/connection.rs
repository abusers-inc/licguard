use chrono::{DateTime, Utc};
use migration::ExprTrait;
use proto::{
    software::v1::{
        client_message, info_request, info_response, server_message, InfoResponse, LicenseError,
        ServerHearthbeat, ServerHearthbeatData, SigningKey,
    },
    ChronoExt,
};
use sea_orm::{prelude::Uuid, ActiveModelTrait, EntityTrait, Set};
use serde_json::json;
use tokio::sync::mpsc;

use crate::{
    entities::{self, app, license},
    ServerState,
};

use super::v1;
use std::{str::FromStr, sync::Arc};
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
            }))) = tokio::time::timeout(v1::PING_PERIOD + v1::PING_GRACE, self.rx.message()).await
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

async fn try_get_request(rx: &mut ServerRX) -> Result<(info_request::Request, u64), tonic::Status> {
    let Ok(Ok(Some(msg))) = tokio::time::timeout(v1::HANDSHAKE_TIMEOUT, rx.message()).await else {
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

        // this function is called before incrementing connection counter
        if (*key_entry) + 1 > connections_limit {
            return Err(LicenseError::TooManySessions);
        }
    }
    Ok(())
}

async fn try_get_license(
    state: &ServerState,
    request: info_request::Request,
) -> Result<license::Model, LicenseError> {
    println!("'{}'", request.key_id);
    let license =
        entities::license::Entity::find_by_id(request.key_id.parse::<Uuid>().map_err(|_| {
            // tracing::info!("key.invalid");
            println!("key.invalid");

            LicenseError::InvalidKey
        })?)
        .one(&state.db)
        .await
        .map_err(|_| LicenseError::Internal)?;

    let Some(license) = license else {
        println!("key.not_found");
        // entities::license::Entity::find()
        //     .all(&state.db)
        //     .await
        //     .unwrap()
        //     .iter()
        //     .inspect(|a| println!("{:#?}", a));

        return Err(LicenseError::InvalidKey);
    };

    check_permission_connect(&license, state).await?;

    Ok(license)
}

pub async fn handle(state: Arc<ServerState>, tx: ServerTX, mut rx: ServerRX) {
    tracing::info!("server.conn");

    // let _app = app::ActiveModel {
    //     name: Set("netsharesoft".to_owned()),
    //     private_key: Set(hex::decode(
    //         "a03a0327de44f0d47f2e062cd504191532d7b07ba51aae78730bc66cac8c54b3",
    //     )
    //     .unwrap()),
    //     public_key: Set(hex::decode(
    //         "34fd6ff70f4f452c191cfc23dbf9f9e6dcdb23d0be01fee0f724a2182f76aee0",
    //     )
    //     .unwrap()),
    //     data_schema: Set(serde_json::json!({})),
    // }
    // .insert(&state.db)
    // .await
    // .unwrap();

    // let _license = license::ActiveModel {
    //     id: Set(Uuid::from_str("bf024a65-2a58-45d9-b480-5a1795becd90").unwrap()),
    //     holder: Set("me".to_string()),
    //     expiry: Set(Utc::now() + chrono::Duration::days(10)),
    //     extra_data: Set(json!({})),
    //     policy_limit_connections: Set(Some(1)),
    //     app: Set("netsharesoft".to_owned()),
    // }
    // .insert(&state.db)
    // .await
    // .unwrap();

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

    let Ok(Some(app)) = entities::app::Entity::find_by_id(&license.app)
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
