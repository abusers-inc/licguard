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

pub mod software {
    use serde::{de::DeserializeOwned, Deserialize, Serialize};

    pub mod v1 {
        use std::{fmt::Display, str::FromStr, time::Duration};

        use ed25519_dalek::{ed25519::signature::SignerMut, Signature, SignatureError};

        tonic::include_proto!("software.v1");

        pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

        pub const PING_PERIOD: Duration = Duration::from_secs(30);
        pub const PING_GRACE: Duration = Duration::from_secs(15);

        pub const PORT: u16 = 5050;

        #[derive(Debug)]
        pub struct KeyError;

        #[derive(serde::Deserialize, serde::Serialize)]
        #[serde(transparent)]
        pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

        impl Display for VerifyingKey {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&hex::encode(self.0.as_bytes()))
            }
        }

        impl hex::FromHex for VerifyingKey {
            type Error = KeyError;

            fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
                let array = hex.as_ref().try_into().map_err(|_| KeyError)?;
                let key = ed25519_dalek::VerifyingKey::from_bytes(array).map_err(|_| KeyError)?;
                Ok(Self(key))
            }
        }
        impl FromStr for VerifyingKey {
            type Err = KeyError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let bytearray = hex::decode(s).map_err(|_| KeyError)?;
                let bytearray = bytearray.as_slice().try_into().map_err(|_| KeyError)?;

                Ok(Self(
                    ed25519_dalek::VerifyingKey::from_bytes(bytearray).map_err(|_| KeyError)?,
                ))
            }
        }

        #[derive(serde::Deserialize, serde::Serialize)]
        #[serde(transparent)]
        pub struct SigningKey(ed25519_dalek::SigningKey);
        impl SigningKey {
            pub fn try_from(bytes: &[u8]) -> Result<Self, KeyError> {
                ed25519_dalek::SigningKey::try_from(bytes)
                    .map(Self)
                    .map_err(|_| KeyError)
            }
        }

        impl ed25519_dalek::Signer<Signature> for SigningKey {
            fn try_sign(&self, message: &[u8]) -> Result<Signature, SignatureError> {
                <ed25519_dalek::SigningKey as ed25519_dalek::Signer<Signature>>::try_sign(
                    &self.0, message,
                )
            }
        }

        pub type SignatureKeypair = SigningKey;

        pub struct SignatureSchema;

        impl SignatureSchema {
            fn encode<T: prost::Message>(data: &T, nonce: u64) -> Vec<u8> {
                let mut data = data.encode_to_vec();
                data.extend_from_slice(nonce.to_le_bytes().as_slice());
                data
            }

            pub fn sign<T: prost::Message>(
                data: &T,
                nonce: u64,
                signer: &mut SigningKey,
            ) -> Vec<u8> {
                let data = Self::encode(data, nonce);

                let signature = (signer.0).sign(&data);

                signature.to_vec()
            }

            pub fn verify<T: prost::Message>(
                data: &T,
                nonce: u64,
                key: &VerifyingKey,
                signature: &[u8],
            ) -> bool {
                let data = Self::encode(data, nonce);

                let Ok(signature) = Signature::from_slice(signature) else {
                    return false;
                };

                (key.0).verify_strict(&data, &signature).is_ok()
            }
        }
    }
}

pub mod admin_client {
    pub mod v1 {
        tonic::include_proto!("admin_client.v1");
    }
}
