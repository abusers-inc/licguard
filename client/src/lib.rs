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
    pub verifier: Verifier,
    pub addr: String,
    pub verifying_key: String,
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

        let err_dispatcher = ErrorDispatcher { gui };

        let connection = match connection.authorize().await {
            Ok(conn) => conn,

            Err(err) => return err_dispatcher.dispatch(err),
        };

        tokio::task::spawn(async move {
            let Err(e) = connection.work().await;
            err_dispatcher.dispatch(e).unwrap();
        });

        Ok(())
    }
}

pub mod client;
pub mod gui;
