use std::collections::HashSet;
use std::net::IpAddr;

#[derive(Clone, Debug)]
pub struct Config {
    pub port: u16,
    pub relay_port: u16,
    pub api_secret: String,
    pub ice_servers: Vec<String>,
    pub turn_server: Option<String>,
    pub turn_secret: String,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub allowed_origins: Vec<String>,
    pub trusted_proxies: HashSet<IpAddr>,
    pub tidecloak_url: Option<String>,
    pub relay_host: String,
    pub max_connections_per_ip: usize,
    pub max_messages_per_sec: usize,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            port: env_or("PORT", "9090").parse().unwrap_or(9090),
            relay_port: env_or("RELAY_PORT", "7893").parse().unwrap_or(7893),
            api_secret: env_or("API_SECRET", ""),
            ice_servers: env_or("ICE_SERVERS", "")
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.trim().to_string())
                .collect(),
            turn_server: std::env::var("TURN_SERVER").ok().filter(|s| !s.is_empty()),
            turn_secret: env_or("TURN_SECRET", ""),
            tls_cert_path: std::env::var("TLS_CERT_PATH").ok().filter(|s| !s.is_empty()),
            tls_key_path: std::env::var("TLS_KEY_PATH").ok().filter(|s| !s.is_empty()),
            allowed_origins: env_or("ALLOWED_ORIGINS", "")
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.trim().to_string())
                .collect(),
            trusted_proxies: env_or("TRUSTED_PROXIES", "")
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect(),
            tidecloak_url: std::env::var("TIDECLOAK_URL").ok().filter(|s| !s.is_empty()),
            relay_host: env_or("RELAY_HOST", "punchd.keylessh.com"),
            max_connections_per_ip: 20,
            max_messages_per_sec: 100,
        }
    }

    pub fn use_tls(&self) -> bool {
        self.tls_cert_path.is_some() && self.tls_key_path.is_some()
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
