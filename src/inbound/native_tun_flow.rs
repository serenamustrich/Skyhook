use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::RwLock;
use std::time::Duration;

use serde::Serialize;

use crate::routing::{AppIdentity, RouteDecision};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash)]
pub enum FlowProtocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub protocol: FlowProtocol,
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowMetadata {
    pub key: FlowKey,
    pub host: Option<String>,
    pub app: Option<AppIdentity>,
    pub packet_count: u64,
    pub byte_count: u64,
    pub decision: Option<RouteDecision>,
}

pub struct FlowTable {
    flows: RwLock<HashMap<FlowKey, FlowMetadata>>,
    max_flows: usize,
    flow_timeout: Duration,
}

impl FlowTable {
    pub fn new(max_flows: usize, flow_timeout: Duration) -> Self {
        Self {
            flows: RwLock::new(HashMap::new()),
            max_flows,
            flow_timeout,
        }
    }

    pub fn get_or_create_flow(
        &self,
        key: FlowKey,
        host: Option<String>,
        app: Option<AppIdentity>,
    ) -> FlowMetadata {
        let mut flows = self.flows.write().unwrap();

        if let Some(flow) = flows.get_mut(&key) {
            flow.packet_count += 1;
            return flow.clone();
        }

        if flows.len() >= self.max_flows {
            self.evict_expired_flows(&mut flows);
        }

        let flow = FlowMetadata {
            key: key.clone(),
            host,
            app,
            packet_count: 1,
            byte_count: 0,
            decision: None,
        };
        flows.insert(key, flow.clone());
        flow
    }

    pub fn update_flow(&self, key: &FlowKey, bytes: u64) {
        if let Some(flow) = self.flows.write().unwrap().get_mut(key) {
            flow.byte_count += bytes;
        }
    }

    pub fn set_decision(&self, key: &FlowKey, decision: RouteDecision) {
        if let Some(flow) = self.flows.write().unwrap().get_mut(key) {
            flow.decision = Some(decision);
        }
    }

    pub fn get_flow(&self, key: &FlowKey) -> Option<FlowMetadata> {
        self.flows.read().unwrap().get(key).cloned()
    }

    pub fn snapshot(&self) -> Vec<FlowMetadata> {
        self.flows.read().unwrap().values().cloned().collect()
    }

    pub fn active_flow_count(&self) -> usize {
        self.flows.read().unwrap().len()
    }

    fn evict_expired_flows(&self, flows: &mut HashMap<FlowKey, FlowMetadata>) {
        let _ = self.flow_timeout;
        if flows.len() > self.max_flows {
            let excess = flows.len() - self.max_flows;
            let keys_to_remove: Vec<_> = flows.keys().take(excess).cloned().collect();
            for key in keys_to_remove {
                flows.remove(&key);
            }
        }
    }

    pub fn cleanup_expired(&self) {
        let mut flows = self.flows.write().unwrap();
        self.evict_expired_flows(&mut flows);
    }
}

pub fn classify_ip_protocol(protocol: u8) -> FlowProtocol {
    match protocol {
        6 => FlowProtocol::Tcp,
        17 => FlowProtocol::Udp,
        1 => FlowProtocol::Icmp,
        _ => FlowProtocol::Other(protocol),
    }
}

pub fn extract_tls_sni(payload: &[u8]) -> Option<String> {
    if payload.len() < 5 {
        return None;
    }

    if payload[0] != 0x16 {
        return None;
    }

    if payload[1] != 0x03 {
        return None;
    }

    let mut pos = 5;
    if pos >= payload.len() {
        return None;
    }

    if pos + 4 > payload.len() {
        return None;
    }

    pos += 4;

    while pos + 4 <= payload.len() {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let ext_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > payload.len() {
            return None;
        }

        if ext_type == 0x0000 {
            return parse_sni_extension(&payload[pos..pos + ext_len]);
        }

        pos += ext_len;
    }

    None
}

fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }

    let sni_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + sni_len {
        return None;
    }

    if data[5] != 0x00 {
        return None;
    }

    let hostname = std::str::from_utf8(&data[6..5 + sni_len]).ok()?;
    Some(hostname.to_string())
}

pub fn extract_http_host(payload: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(payload).ok()?;

    let lines: Vec<&str> = text.split("\r\n").collect();
    for line in lines.iter().skip(1) {
        if line.to_lowercase().starts_with("host:") {
            let host = line[5..].trim();
            if let Some((hostname, _)) = host.rsplit_once(':') {
                return Some(hostname.to_string());
            }
            return Some(host.to_string());
        }
    }

    None
}

#[derive(Debug, Clone)]
pub struct DnsMapping {
    ip_to_domain: HashMap<std::net::IpAddr, String>,
    max_entries: usize,
}

impl DnsMapping {
    pub fn new(max_entries: usize) -> Self {
        Self {
            ip_to_domain: HashMap::new(),
            max_entries,
        }
    }

    pub fn add_mapping(&mut self, ip: std::net::IpAddr, domain: String) {
        if self.ip_to_domain.len() >= self.max_entries {
            self.evict_oldest();
        }
        self.ip_to_domain.insert(ip, domain);
    }

    pub fn lookup(&self, ip: &std::net::IpAddr) -> Option<&String> {
        self.ip_to_domain.get(ip)
    }

    fn evict_oldest(&mut self) {
        if let Some(first_key) = self.ip_to_domain.keys().next().cloned() {
            self.ip_to_domain.remove(&first_key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

    #[test]
    fn flow_key_creation() {
        let key = FlowKey {
            protocol: FlowProtocol::Tcp,
            src: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 12345)),
            dst: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 443)),
        };
        assert_eq!(key.protocol, FlowProtocol::Tcp);
    }

    #[test]
    fn flow_table_get_or_create() {
        let table = FlowTable::new(100, Duration::from_secs(60));
        let key = FlowKey {
            protocol: FlowProtocol::Tcp,
            src: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 12345)),
            dst: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 443)),
        };

        let flow = table.get_or_create_flow(key.clone(), None, None);
        assert_eq!(flow.packet_count, 1);

        let flow2 = table.get_or_create_flow(key.clone(), None, None);
        assert_eq!(flow2.packet_count, 2);
    }

    #[test]
    fn flow_table_update() {
        let table = FlowTable::new(100, Duration::from_secs(60));
        let key = FlowKey {
            protocol: FlowProtocol::Tcp,
            src: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 12345)),
            dst: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 443)),
        };

        table.get_or_create_flow(key.clone(), None, None);
        table.update_flow(&key, 1024);

        let flow = table.get_flow(&key).unwrap();
        assert_eq!(flow.byte_count, 1024);
    }

    #[test]
    fn classify_ip_protocol_works() {
        assert_eq!(classify_ip_protocol(6), FlowProtocol::Tcp);
        assert_eq!(classify_ip_protocol(17), FlowProtocol::Udp);
        assert_eq!(classify_ip_protocol(1), FlowProtocol::Icmp);
        assert_eq!(classify_ip_protocol(47), FlowProtocol::Other(47));
    }

    #[test]
    fn dns_mapping_add_and_lookup() {
        let mut mapping = DnsMapping::new(100);
        let ip = IpAddr::V4(Ipv4Addr::new(142, 250, 80, 46));
        mapping.add_mapping(ip, "google.com".to_string());

        assert_eq!(mapping.lookup(&ip), Some(&"google.com".to_string()));
        assert_eq!(mapping.lookup(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))), None);
    }

    #[test]
    fn extract_http_host_works() {
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let host = extract_http_host(payload);
        assert_eq!(host, Some("example.com".to_string()));
    }

    #[test]
    fn extract_http_host_with_port() {
        let payload = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        let host = extract_http_host(payload);
        assert_eq!(host, Some("example.com".to_string()));
    }
}
