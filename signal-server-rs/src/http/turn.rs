use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// Generate ephemeral TURN credentials (RFC 5766 REST API style).
/// Username: "{expiry}:{random}" Password: HMAC-SHA1(secret, username)
pub fn generate_turn_credentials(secret: &str, ttl_secs: u64) -> (String, String) {
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + ttl_secs;

    let username = format!("{expiry}");

    let mut mac = HmacSha1::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(username.as_bytes());
    let password = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        mac.finalize().into_bytes(),
    );

    (username, password)
}
