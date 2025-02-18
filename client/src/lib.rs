use std::{
    convert::Infallible,
    marker::PhantomData,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use client::{
    connection::{Connection, ConnectionError, ConnectionState},
    ErrorDispatcher,
};
use gui::GUIBackend;
use proto::software::v1::{authority_client::AuthorityClient, ClientHearthbeat, VerifyingKey};
use rand::{rngs::StdRng, SeedableRng};
use serde::de::DeserializeOwned;

pub trait DataVerifier: Send + 'static {
    fn verify(&self, data: serde_json::Value) -> bool;
}

pub struct FuncVerifier<T, Functor> {
    functor: Functor,
    _p: PhantomData<T>,
}

impl<T, Functor> FuncVerifier<T, Functor> {
    pub fn new(functor: Functor) -> Self {
        Self {
            functor,
            _p: Default::default(),
        }
    }
}

impl<T: DeserializeOwned + Send + 'static, Functor: Send + 'static> DataVerifier
    for FuncVerifier<T, Functor>
where
    Functor: Fn(T) -> bool,
{
    fn verify(&self, data: serde_json::Value) -> bool {
        serde_json::from_value(data)
            .map(|data| (&self.functor)(data))
            .unwrap_or(false)
    }
}

impl DataVerifier for () {
    fn verify(&self, _: serde_json::Value) -> bool {
        true
    }
}

#[derive(derive_builder::Builder)]
pub struct ClientInput<Verifier: DataVerifier = ()> {
    #[builder(setter(custom))]
    verifier: Verifier,
    addr: String,
    verifying_key: String,
}

impl<Verifier: DataVerifier> ClientInputBuilder<Verifier> {
    pub fn verifier<V: DataVerifier>(self, v: V) -> ClientInputBuilder<V> {
        ClientInputBuilder {
            verifier: Some(v),
            addr: self.addr,
            verifying_key: self.verifying_key,
        }
    }
}

const LICFILE_PATH: &str = "./license.data";

pub struct Connector;

impl Connector {
    fn try_load_key() -> Result<String, ()> {
        std::fs::read_to_string(LICFILE_PATH).map_err(|_| ())
    }

    fn prompt_and_save_key(gui: &impl GUIBackend) -> String {
        let key = gui.prompt_license();
        let _ = std::fs::write(LICFILE_PATH, key.as_str());
        key
    }

    pub fn load_key(gui: &impl GUIBackend) -> String {
        match Self::try_load_key() {
            Ok(key) => key,
            Err(_) => Self::prompt_and_save_key(gui),
        }
    }

    // this function is allowed to panic because we need to crash if something is wrong
    async fn new<V: DataVerifier>(input: ClientInput<V>) -> client::connection::ConnectionState<V> {
        let endpoint = tonic::transport::channel::Endpoint::from_shared(input.addr).unwrap();
        let client = AuthorityClient::connect(endpoint).await.unwrap();

        let gui = crate::gui::Dispatcher::new();

        let verifying_key = VerifyingKey::from_str(&input.verifying_key).unwrap();
        let license_key = Self::load_key(&gui);

        let gui = Arc::new(gui);

        let state = ConnectionState {
            client,
            license_key,
            rng: StdRng::from_os_rng(),
            verification_key: verifying_key,
            data_verifier: input.verifier,
            gui,
        };
        state
    }

    pub async fn setup<V: DataVerifier>(input: ClientInput<V>) -> Result<(), ConnectionError> {
        let state = Self::new(input).await;
        let gui = state.gui.clone();
        let connection = client::connection::Connection::new(state).await.unwrap();

        let connection = match connection.authorize().await {
            Ok(conn) => conn,

            Err(err) => return ErrorDispatcher::dispatch(err),
        };

        tokio::task::spawn(async move {
            let Err(e) = connection.work().await;
            ErrorDispatcher::dispatch(e).unwrap();
        });

        Ok(())
    }
}

pub mod gui;
pub mod client {
    use crate::gui::{Dispatcher, GUIBackend};
    use connection::ConnectionError;
    use std::sync::Arc;

    pub struct ErrorDispatcher {
        gui: Arc<Dispatcher>,
    }

    impl ErrorDispatcher {
        #[allow(unused)]
        fn break_stack() {
            unsafe {
                std::ptr::read_volatile(std::ptr::null::<i32>());
            }
        }

        #[allow(unused)]
        fn handle_release(&self, error: ConnectionError) -> Result<(), ConnectionError> {
            if let ConnectionError::LicenseError(licerror) = error {
                self.gui.show_license_error(licerror);
            }
            loop {
                std::process::exit(100); // in case this function is hooked
                Self::break_stack();
            }
        }

        pub fn dispatch(error: ConnectionError) -> Result<(), ConnectionError> {
            #[cfg(debug_assertions)]
            return Err(error);
            #[cfg(not(debug_assertions))]
            return self.handle_release(e);
        }
    }

    pub mod connection {
        use std::convert::Infallible;
        use std::marker::PhantomData;
        use std::sync::Arc;

        use fatality::fatality;
        use proto::software::v1::VerifyingKey;
        use proto::software::v1::{
            self, authority_client::AuthorityClient, client_message, info_request, server_message,
            ClientHearthbeat, ClientMessage, InfoRequest, LicenseError, ServerHearthbeat,
            ServerMessage,
        };
        use rand::Rng;
        use tokio::sync::mpsc::Sender;
        use tonic::{transport::Channel, Streaming};

        use crate::DataVerifier;

        use crate::gui::{Dispatcher, GUIBackend, TUI};

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
                    key_id: self.state.license_key.clone(),
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

                let Ok(Some(msg)) =
                    tokio::time::timeout(v1::HANDSHAKE_TIMEOUT, self.rx.message()).await?
                else {
                    return Err(ConnectionError::InvalidResponse);
                };

                let ServerMessage {
                    data:
                        Some(server_message::Data::Auth(v1::InfoResponse {
                            nonce,
                            signature,
                            result: Some(result),
                        })),
                } = msg
                else {
                    return Err(ConnectionError::InvalidResponse);
                };

                if !v1::SignatureSchema::verify(
                    &info_request,
                    nonce,
                    &self.state.verification_key,
                    &signature,
                ) {
                    return Err(ConnectionError::InvalidSignature);
                }

                match result {
                    v1::info_response::Result::Ok(info) => {
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
                            data: Some(client_message::Data::Hearthbeat(ClientHearthbeat {
                                nonce,
                            })),
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

                    if !v1::SignatureSchema::verify(
                        &data,
                        nonce,
                        &self.state.verification_key,
                        &signature,
                    ) {
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
    }
}
