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
pub struct VerifyingKey(pub ed25519_dalek::VerifyingKey);

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

impl std::ops::Deref for SigningKey {
    type Target = ed25519_dalek::SigningKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl SigningKey {
    pub fn try_from(bytes: &[u8]) -> Result<Self, KeyError> {
        ed25519_dalek::SigningKey::try_from(bytes)
            .map(Self)
            .map_err(|_| KeyError)
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

    pub fn sign<T: prost::Message>(data: &T, nonce: u64, signer: &mut SigningKey) -> Vec<u8> {
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
