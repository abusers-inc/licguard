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
        tracing_subscriber::fmt::init();

        let connection = Database::connect(config.database_uri).await?;

        migration::Migrator::up(&connection, None).await?;

        Ok(Self {
            db: connection,
            connections: Mutex::new(HashMap::new()),
        })
    }
}

pub mod v1_server;
