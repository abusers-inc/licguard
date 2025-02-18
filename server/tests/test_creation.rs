#[tokio::test]
async fn test_creation() -> eyre::Result<()> {
    let config = server::Config {
        database_uri: "sqlite://db.data?mode=rwc".to_owned(),
    };
    let server = server::ServerState::new(config).await?;
    drop(server);

    // tokio::fs::remove_file("db.data").await?;
    Ok(())
}
