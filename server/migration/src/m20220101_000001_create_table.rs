use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(App::Table)
                    .if_not_exists()
                    .col(pk_uuid(App::Id))
                    .col(string(App::Name))
                    .col(blob(App::PrivateKey))
                    .col(blob(App::PublicKey))
                    .col(json_binary(App::DataSchema))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(License::Table)
                    .if_not_exists()
                    .col(pk_uuid(License::Id))
                    .col(string(License::Holder))
                    .col(timestamp(License::Expiry).default(Expr::current_timestamp()))
                    .col(json_binary(License::ExtraData))
                    .col(integer_null(License::PolicyLimitConnections))
                    .col(uuid(License::App))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_license_app")
                            .from(License::Table, License::App)
                            .to(App::Table, App::Id),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(LicenseLog::Table)
                    .if_not_exists()
                    .col(pk_auto(LicenseLog::Id))
                    .col(string(LicenseLog::Kind))
                    .col(uuid(LicenseLog::License))
                    .col(json_binary(LicenseLog::Data))
                    .col(timestamp(LicenseLog::Timestamp).default(Expr::current_timestamp()))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_liclog_license")
                            .from(LicenseLog::Table, LicenseLog::License)
                            .to(License::Table, License::Id),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(AdminKey::Table)
                    .if_not_exists()
                    .col(pk_uuid(AdminKey::Id))
                    .col(string(AdminKey::Owner))
                    .col(uuid(AdminKey::App))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_adminkey_app")
                            .from(AdminKey::Table, AdminKey::App)
                            .to(App::Table, App::Id),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(LicenseLog::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(License::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(App::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum License {
    Table,
    Id,
    Holder,
    Expiry,
    ExtraData,
    App,

    PolicyLimitConnections,
}

#[derive(DeriveIden)]
enum LicenseLog {
    Table,
    Id,
    Kind,
    Data,
    License,
    Timestamp,
}

#[derive(DeriveIden)]
enum App {
    Table,
    Id,
    Name,
    PrivateKey,
    PublicKey,
    DataSchema,
}

#[derive(DeriveIden)]
enum AdminKey {
    Table,
    Id,
    Owner,
    App,
}
