use proto::software::v1;
use rand::SeedableRng;
fn main() {
    let mut rng = rand::rngs::OsRng;
    let key = ed25519_dalek::SigningKey::generate(&mut rng);

    println!("Veryfing: {}", hex::encode(&key.verifying_key().to_bytes()));
    println!("Signing: {}", hex::encode(&key.to_bytes()));

    println!("Verifying soft: {}", v1::VerifyingKey(key.verifying_key()));
}
