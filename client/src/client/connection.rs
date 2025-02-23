use std::convert::Infallible;
use std::marker::PhantomData;
use std::sync::Arc;

use fatality::fatality;
use proto::software::v1::VerifyingKey;
use proto::software::v1::{
    self, authority_client::AuthorityClient, client_message, info_request, server_message,
    ClientHearthbeat, ClientMessage, InfoRequest, LicenseError, ServerHearthbeat, ServerMessage,
};
use rand::Rng;
use tokio::sync::mpsc::Sender;
use tonic::{transport::Channel, Streaming};

use crate::DataVerifier;

use crate::gui::{Dispatcher, GUIBackend};

#[fatality]
pub enum ConnectionError {
    #[error("License error")]
    LicenseError(v1::LicenseError),

    #[fatal]
    #[error("Connection error: {0}")]
    ConnectionError(#[from] tonic::Status),

    #[fatal]
    #[error("Send error: {0}")]
    SendError(#[from] tokio::sync::mpsc::error::SendError<ClientMessage>),

    #[fatal]
    #[error("Timeout")]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[fatal]
    #[error("Invalid response")]
    InvalidResponse,

    #[fatal]
    #[error("Data verification error")]
    DataVerificationError,

    #[fatal]
    #[error("Invalid signature")]
    InvalidSignature,
}

pub struct ConnectionState<D: DataVerifier> {
    pub client: AuthorityClient<Channel>,
    pub rng: rand::rngs::StdRng,
    pub verification_key: VerifyingKey,
    pub gui: Arc<Dispatcher>,

    pub license_key: String,

    pub data_verifier: D,
}

pub struct Authorized;
pub struct NotAuthorized;

pub struct Connection<D: DataVerifier, State> {
    pub state: ConnectionState<D>,
    tx: Sender<ClientMessage>,
    rx: Streaming<ServerMessage>,
    _s: PhantomData<State>,
}

impl<D: DataVerifier> Connection<D, NotAuthorized> {
    pub async fn new(mut state: ConnectionState<D>) -> Result<Self, ConnectionError> {
        let (tx, client_rx) = tokio::sync::mpsc::channel(1);
        let rx = state
            .client
            .hearthbeat(tokio_stream::wrappers::ReceiverStream::new(client_rx))
            .await?
            .into_inner();

        Ok(Self {
            state,
            tx,
            rx,
            _s: Default::default(),
        })
    }

    pub async fn authorize(mut self) -> Result<Connection<D, Authorized>, ConnectionError> {
        let info_request = info_request::Request {
            key_id: self.state.license_key.trim().to_owned(),
        };

        let auth_nonce = self.state.rng.random();
        self.tx
            .send(ClientMessage {
                data: Some(client_message::Data::Auth(InfoRequest {
                    req: Some(info_request.clone()),
                    nonce: auth_nonce,
                })),
            })
            .await?;

        let Ok(Some(msg)) = tokio::time::timeout(v1::HANDSHAKE_TIMEOUT, self.rx.message()).await?
        else {
            return Err(ConnectionError::InvalidResponse);
        };

        let ServerMessage {
            data: Some(server_message::Data::Auth(response)),
        } = msg
        else {
            return Err(ConnectionError::InvalidResponse);
        };

        let v1::InfoResponse {
            nonce,
            signature,
            result: Some(result),
        } = response
        else {
            return Err(ConnectionError::InvalidResponse);
        };

        match result {
            v1::info_response::Result::Ok(info) => {
                if !v1::SignatureSchema::verify(
                    &info,
                    nonce,
                    &self.state.verification_key,
                    &signature,
                ) {
                    return Err(ConnectionError::InvalidSignature);
                }

                let extra_data: serde_json::Value = serde_json::from_str(&info.extra_data)
                    .map_err(|_| ConnectionError::DataVerificationError)?;
                self.state
                    .data_verifier
                    .verify(extra_data)
                    .then(|| ())
                    .ok_or(ConnectionError::DataVerificationError)?;

                self.state.gui.show_license_details(info);
            }
            v1::info_response::Result::Error(e) => {
                return Err(ConnectionError::LicenseError(
                    LicenseError::try_from(e).unwrap_or(LicenseError::Internal),
                ));
            }
        }

        Ok(Connection {
            state: self.state,
            tx: self.tx,
            rx: self.rx,
            _s: Default::default(),
        })
    }
}

impl<D: DataVerifier> Connection<D, Authorized> {
    pub async fn work(mut self) -> Result<Infallible, ConnectionError> {
        loop {
            tokio::time::sleep(v1::PING_PERIOD).await;
            let nonce = self.state.rng.random();
            self.tx
                .send(ClientMessage {
                    data: Some(client_message::Data::Hearthbeat(ClientHearthbeat { nonce })),
                })
                .await?;

            let Ok(Some(msg)) =
                tokio::time::timeout(v1::HANDSHAKE_TIMEOUT, self.rx.message()).await?
            else {
                return Err(ConnectionError::InvalidResponse);
            };

            let ServerMessage {
                data:
                    Some(server_message::Data::Heathbeat(ServerHearthbeat {
                        nonce,
                        signature,
                        data: Some(data),
                    })),
            } = msg
            else {
                return Err(ConnectionError::InvalidResponse);
            };

            if !v1::SignatureSchema::verify(&data, nonce, &self.state.verification_key, &signature)
            {
                return Err(ConnectionError::InvalidSignature);
            }

            if let Some(error) = data.error {
                return Err(ConnectionError::LicenseError(
                    LicenseError::try_from(error).unwrap_or(LicenseError::Internal),
                ));
            }
        }
    }
}
