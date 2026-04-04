use std::collections::HashSet;
use std::sync::Arc;

use dashmap::DashMap;
use serde::Serialize;
use tokio::sync::mpsc;

#[derive(Debug, Clone, Serialize)]
pub struct GatewayMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backends: Option<Vec<BackendInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackendInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
}

pub type WsSender = mpsc::UnboundedSender<axum::extract::ws::Message>;

pub struct Gateway {
    pub id: String,
    pub addresses: Vec<String>,
    pub sender: WsSender,
    pub registered_at: u64,
    pub paired_clients: HashSet<String>,
    pub metadata: GatewayMetadata,
    pub public_ip: Option<String>,
}

pub struct Client {
    pub id: String,
    pub sender: WsSender,
    pub registered_at: u64,
    pub reflexive_address: Option<String>,
    pub paired_gateway_id: Option<String>,
    pub token: String,
    pub connection_type: String,
}

pub struct Registry {
    gateways: DashMap<String, Gateway>,
    clients: DashMap<String, Client>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            gateways: DashMap::new(),
            clients: DashMap::new(),
        }
    }

    pub fn register_gateway(
        &self,
        id: String,
        addresses: Vec<String>,
        sender: WsSender,
        metadata: GatewayMetadata,
        public_ip: Option<String>,
    ) {
        // If gateway already exists, update it
        if let Some(mut existing) = self.gateways.get_mut(&id) {
            existing.addresses = addresses;
            existing.sender = sender;
            existing.metadata = metadata;
            existing.public_ip = public_ip;
            tracing::info!("[Signal] Gateway re-registered: {id}");
        } else {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.gateways.insert(id.clone(), Gateway {
                id: id.clone(),
                addresses,
                sender,
                registered_at: now,
                paired_clients: HashSet::new(),
                metadata,
                public_ip,
            });
            tracing::info!("[Signal] Gateway registered: {id}");
        }
    }

    pub fn register_client(&self, id: String, sender: WsSender, token: String) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.clients.insert(id.clone(), Client {
            id,
            sender,
            registered_at: now,
            reflexive_address: None,
            paired_gateway_id: None,
            token,
            connection_type: "relay".to_string(),
        });
    }

    pub fn update_client_reflexive(&self, id: &str, addr: &str) {
        if let Some(mut client) = self.clients.get_mut(id) {
            client.reflexive_address = Some(addr.to_string());
        }
    }

    pub fn get_gateway(&self, id: &str) -> Option<dashmap::mapref::one::Ref<String, Gateway>> {
        self.gateways.get(id)
    }

    pub fn get_client(&self, id: &str) -> Option<dashmap::mapref::one::Ref<String, Client>> {
        self.clients.get(id)
    }

    pub fn get_client_mut(&self, id: &str) -> Option<dashmap::mapref::one::RefMut<String, Client>> {
        self.clients.get_mut(id)
    }

    pub fn get_gateway_mut(&self, id: &str) -> Option<dashmap::mapref::one::RefMut<String, Gateway>> {
        self.gateways.get_mut(id)
    }

    pub fn get_available_gateway(&self) -> Option<String> {
        let mut best_id = None;
        let mut min_clients = usize::MAX;
        for entry in self.gateways.iter() {
            if entry.paired_clients.len() < min_clients {
                min_clients = entry.paired_clients.len();
                best_id = Some(entry.id.clone());
            }
        }
        best_id
    }

    pub fn get_gateway_by_backend(&self, backend_name: &str) -> Option<String> {
        for entry in self.gateways.iter() {
            if let Some(ref backends) = entry.metadata.backends {
                for b in backends {
                    if b.name.eq_ignore_ascii_case(backend_name) {
                        return Some(entry.id.clone());
                    }
                }
            }
        }
        None
    }

    pub fn get_gateway_by_realm(&self, realm: &str) -> Option<String> {
        for entry in self.gateways.iter() {
            if let Some(ref r) = entry.metadata.realm {
                if r.eq_ignore_ascii_case(realm) {
                    return Some(entry.id.clone());
                }
            }
        }
        None
    }

    pub fn get_all_gateways(&self) -> Vec<String> {
        self.gateways.iter().map(|e| e.id.clone()).collect()
    }

    pub fn remove_gateway(&self, id: &str) {
        self.gateways.remove(id);
        tracing::info!("[Signal] Gateway unregistered: {id}");
    }

    pub fn remove_client(&self, id: &str) {
        // Remove from paired gateway
        if let Some(client) = self.clients.get(id) {
            if let Some(ref gw_id) = client.paired_gateway_id {
                if let Some(mut gw) = self.gateways.get_mut(gw_id) {
                    gw.paired_clients.remove(id);
                }
            }
        }
        self.clients.remove(id);
    }

    pub fn send_to_gateway(&self, id: &str, msg: axum::extract::ws::Message) -> bool {
        if let Some(gw) = self.gateways.get(id) {
            gw.sender.send(msg).is_ok()
        } else {
            false
        }
    }

    pub fn send_to_client(&self, id: &str, msg: axum::extract::ws::Message) -> bool {
        if let Some(client) = self.clients.get(id) {
            client.sender.send(msg).is_ok()
        } else {
            false
        }
    }

    pub fn gateway_count(&self) -> usize {
        self.gateways.len()
    }

    pub fn client_count(&self) -> usize {
        self.clients.len()
    }
}
