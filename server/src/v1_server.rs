use std::sync::Arc;

use proto::software::v1::{self, authority_server::AuthorityServer, ServerMessage};

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::ServerState;

const CHANNEL_BUFFER: usize = 100;

mod connection;

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
