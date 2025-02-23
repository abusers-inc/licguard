use chrono::{DateTime, TimeZone, Utc};
use prost_types::Timestamp;

pub trait ChronoExt {
    fn to_protobuf(&self) -> Timestamp;
    fn from_protobuf(ts: &Timestamp) -> Self;
}

impl ChronoExt for DateTime<Utc> {
    fn to_protobuf(&self) -> Timestamp {
        Timestamp {
            seconds: self.timestamp(),
            nanos: self.timestamp_subsec_nanos() as i32,
        }
    }

    fn from_protobuf(ts: &Timestamp) -> Self {
        Utc.timestamp_opt(ts.seconds, ts.nanos as u32)
            .single()
            .expect("Invalid timestamp")
    }
}

pub mod software;

pub mod admin_client {
    pub mod v1 {
        tonic::include_proto!("admin_client.v1");
    }
}
