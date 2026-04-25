use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::SecretKey;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

/// Sign an Authenticated Atomic Action (AAA) payload and return a Coz envelope.
///
/// This function constructs the JSON payload in memory with deterministic
/// byte ordering, signs the raw bytes, and returns the complete Coz message
/// as a JSON string. This is critical for Coz integrity — JavaScript's
/// JSON.stringify does not guarantee key ordering.
///
/// # Arguments
/// * `private_key_hex` - Hex-encoded P-256 private key (64 hex chars = 32 bytes)
/// * `nonce` - Challenge nonce from the bridge (32-byte hex string)
/// * `thumbprint` - Key thumbprint (tmb) for the principal root
///
/// # Returns
/// JSON string: `{"pay":{...},"sig":"..."}`
#[wasm_bindgen]
pub fn sign_action(private_key_hex: &str, nonce: &str, thumbprint: &str) -> String {
    let now = now_timestamp();

    // Construct the payload with deterministic key ordering
    let pay = serde_json::json!({
        "alg": "ES256",
        "tmb": thumbprint,
        "typ": "cyphr/auth/challenge",
        "now": now,
        "nonce": nonce
    });

    // Serialize to get the exact bytes that will be signed
    let pay_bytes = serde_json::to_vec(&pay).expect("failed to serialize payload");

    // Sign the payload bytes
    let signature = sign_bytes(&pay_bytes, private_key_hex);

    // Construct the Coz envelope
    let envelope = serde_json::json!({
        "pay": pay,
        "sig": signature
    });

    serde_json::to_string(&envelope).expect("failed to serialize envelope")
}

/// Sign raw bytes using the P-256 private key and return base64url-encoded signature.
fn sign_bytes(data: &[u8], private_key_hex: &str) -> String {
    let key_bytes = hex::decode(private_key_hex).expect("invalid hex in private key");

    let secret_key = SecretKey::from_slice(&key_bytes).expect("invalid P-256 private key");

    let signing_key = SigningKey::from(secret_key);

    // Hash the data first (ES256 = ECDSA + SHA-256)
    let hash = Sha256::digest(data);

    let signature: Signature = signing_key.sign(&hash);

    // Encode as base64url (r || s concatenation)
    let sig_bytes = signature.to_bytes();
    URL_SAFE_NO_PAD.encode(&sig_bytes)
}

/// Compute the thumbprint (tmb) for a P-256 public key.
/// Uses JWK thumbprint per RFC 7638.
#[wasm_bindgen]
pub fn compute_thumbprint(public_key_x_hex: &str, public_key_y_hex: &str) -> String {
    let x_bytes = hex::decode(public_key_x_hex).expect("invalid hex in x");
    let y_bytes = hex::decode(public_key_y_hex).expect("invalid hex in y");

    let x_b64 = URL_SAFE_NO_PAD.encode(&x_bytes);
    let y_b64 = URL_SAFE_NO_PAD.encode(&y_bytes);

    // JWK for thumbprint computation (keys in alphabetical order per RFC 7638)
    let jwk = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        x_b64, y_b64
    );

    let hash = Sha256::digest(jwk.as_bytes());
    URL_SAFE_NO_PAD.encode(&hash)
}

/// Generate a new P-256 keypair and return JSON with private key and public coordinates.
#[wasm_bindgen]
pub fn generate_keypair() -> String {
    use p256::EncodedPoint;

    let secret_key = SecretKey::random(&mut rand::thread_rng());
    let public_key = secret_key.public_key();
    let point = EncodedPoint::from(&public_key);

    let private_hex = hex::encode(secret_key.to_bytes());
    let x_hex = hex::encode(&point.as_bytes()[1..33]);
    let y_hex = hex::encode(&point.as_bytes()[33..65]);

    serde_json::json!({
        "private_key": private_hex,
        "public_key_x": x_hex,
        "public_key_y": y_hex
    })
    .to_string()
}

/// Derive the public key coordinates from a P-256 private key.
/// Returns JSON with public_key_x, public_key_y, and the JWK thumbprint.
#[wasm_bindgen]
pub fn derive_public_key(private_key_hex: &str) -> String {
    use p256::EncodedPoint;

    let key_bytes = hex::decode(private_key_hex).expect("invalid hex in private key");
    let secret_key = SecretKey::from_slice(&key_bytes).expect("invalid P-256 private key");
    let public_key = secret_key.public_key();
    let point = EncodedPoint::from(&public_key);

    let x_hex = hex::encode(&point.as_bytes()[1..33]);
    let y_hex = hex::encode(&point.as_bytes()[33..65]);
    let thumbprint = compute_thumbprint(&x_hex, &y_hex);

    serde_json::json!({
        "public_key_x": x_hex,
        "public_key_y": y_hex,
        "thumbprint": thumbprint
    })
    .to_string()
}

/// Get the current Unix timestamp. Uses js_sys on wasm32, std otherwise.
fn now_timestamp() -> i64 {
    #[cfg(target_arch = "wasm32")]
    {
        (js_sys::Date::now() / 1000.0) as i64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_produces_valid_envelope() {
        let priv_hex = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let pub_x = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let pub_y = "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3";
        let thumbprint = compute_thumbprint(pub_x, pub_y);

        let coz = sign_action(priv_hex, "test-nonce-123", &thumbprint);
        let envelope: serde_json::Value = serde_json::from_str(&coz).unwrap();

        assert!(envelope.get("pay").is_some());
        assert!(envelope.get("sig").is_some());

        let pay = envelope.get("pay").unwrap();
        assert_eq!(pay.get("alg").unwrap().as_str().unwrap(), "ES256");
        assert_eq!(
            pay.get("typ").unwrap().as_str().unwrap(),
            "cyphr/auth/challenge"
        );
    }

    #[test]
    fn test_thumbprint_deterministic() {
        let pub_x = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let pub_y = "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3";

        let tp1 = compute_thumbprint(pub_x, pub_y);
        let tp2 = compute_thumbprint(pub_x, pub_y);

        assert_eq!(tp1, tp2);
    }
}
