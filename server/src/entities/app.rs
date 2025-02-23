//! `SeaORM` Entity, @generated by sea-orm-codegen 1.1.4

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "app")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub name: String,
    #[sea_orm(column_type = "Blob")]
    pub private_key: Vec<u8>,
    #[sea_orm(column_type = "Blob")]
    pub public_key: Vec<u8>,
    #[sea_orm(column_type = "JsonBinary")]
    pub data_schema: Json,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::admin_key::Entity")]
    AdminKey,
    #[sea_orm(has_many = "super::license::Entity")]
    License,
}

impl Related<super::admin_key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::AdminKey.def()
    }
}

impl Related<super::license::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::License.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
