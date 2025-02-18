use migration::MigratorTrait;

#[tokio::test]
async fn test_creation() {
    let config = "sqlite://db.data?mode=rwc".to_owned();

    let conn = sea_orm::Database::connect(config).await.unwrap();

    migration::Migrator::up(&conn, None).await.unwrap();
}
