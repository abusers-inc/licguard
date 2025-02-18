use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use proto::software::v1;
use serde::Deserialize;
use server::ServerState;
const CONFIG_PATH: &str = "config.toml";

#[derive(Deserialize)]
pub struct Config {
    pub socket_addr: IpAddr,
    #[serde(flatten)]
    pub server_config: server::Config,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();

    let config: Config = Figment::new()
        .merge(Env::raw())
        .merge(Toml::file(CONFIG_PATH))
        .extract()?;

    let server_state = ServerState::new(config.server_config).await?;

    let server = server::v1_server::SoftwareV1::new(server_state);

    tonic::transport::Server::builder()
        .add_service(server)
        .serve((config.socket_addr, v1::PORT).into())
        .await?;

    Ok(())
}
