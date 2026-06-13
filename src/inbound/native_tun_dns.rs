use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::fake_ip::{FakeIpConfig, FakeIpPool};

const DEFAULT_TTL: Duration = Duration::from_secs(60);
const MAX_ENTRIES: usize = 10000;

#[derive(Debug, Clone)]
struct DnsCacheEntry {
    domain: String,
    inserted_at: Instant,
    ttl: Duration,
}

pub struct DnsCache {
    entries: RwLock<HashMap<IpAddr, DnsCacheEntry>>,
    fake_ip_pool: Option<FakeIpPool>,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            fake_ip_pool: None,
        }
    }

    pub fn with_fake_ip(config: FakeIpConfig) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            fake_ip_pool: Some(FakeIpPool::new(config)),
        }
    }

    pub fn insert(&self, ip: IpAddr, domain: String) {
        self.insert_with_ttl(ip, domain, DEFAULT_TTL);
    }

    pub fn insert_with_ttl(&self, ip: IpAddr, domain: String, ttl: Duration) {
        let mut entries = match self.entries.write() {
            Ok(guard) => guard,
            Err(_) => return,
        };

        if entries.len() >= MAX_ENTRIES {
            self.evict_expired_locked(&mut entries);
        }

        entries.insert(
            ip,
            DnsCacheEntry {
                domain,
                inserted_at: Instant::now(),
                ttl,
            },
        );
    }

    pub fn allocate_fake_ip(&self, domain: &str) -> Option<Ipv4Addr> {
        self.fake_ip_pool.as_ref()?.allocate(domain)
    }

    pub fn reverse_lookup(&self, ip: &IpAddr) -> Option<String> {
        // First check fake-IP pool
        if let IpAddr::V4(v4) = ip {
            if let Some(pool) = &self.fake_ip_pool {
                if pool.is_fake_ip(v4) {
                    return pool.reverse_lookup(v4);
                }
            }
        }

        // Then check regular DNS cache
        let entries = match self.entries.read() {
            Ok(guard) => guard,
            Err(_) => return None,
        };

        entries.get(ip).and_then(|entry| {
            if entry.inserted_at.elapsed() < entry.ttl {
                Some(entry.domain.clone())
            } else {
                None
            }
        })
    }

    pub fn is_fake_ip(&self, ip: &Ipv4Addr) -> bool {
        self.fake_ip_pool
            .as_ref()
            .map(|pool| pool.is_fake_ip(ip))
            .unwrap_or(false)
    }

    pub fn lookup(&self, ip: &IpAddr) -> Option<String> {
        self.reverse_lookup(ip)
    }

    pub fn evict_expired(&self) {
        let mut entries = match self.entries.write() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        self.evict_expired_locked(&mut entries);

        if let Some(pool) = &self.fake_ip_pool {
            pool.evict_expired();
        }
    }

    fn evict_expired_locked(&self, entries: &mut HashMap<IpAddr, DnsCacheEntry>) {
        entries.retain(|_, entry| entry.inserted_at.elapsed() < entry.ttl);
    }

    pub fn len(&self) -> usize {
        self.entries.read().map(|e| e.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.write() {
            entries.clear();
        }
    }
}

pub fn parse_dns_response_to_cache(query: &[u8], response: &[u8], cache: &Arc<DnsCache>) {
    if response.len() < 12 {
        return;
    }

    let question_count = u16::from_be_bytes([response[4], response[5]]) as usize;
    let answer_count = u16::from_be_bytes([response[6], response[7]]) as usize;

    if answer_count == 0 {
        return;
    }

    let query_domain = extract_domain_from_query(query);

    let mut offset = 12;

    for _ in 0..question_count {
        offset = skip_name(response, offset);
        offset += 4;
    }

    for _ in 0..answer_count {
        if offset >= response.len() {
            break;
        }

        offset = skip_name(response, offset);

        if offset + 10 > response.len() {
            break;
        }

        let rtype = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let rdlength = u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
        offset += 10;

        if rtype == 1 && rdlength == 4 && offset + 4 <= response.len() {
            let ip = IpAddr::V4(Ipv4Addr::new(
                response[offset],
                response[offset + 1],
                response[offset + 2],
                response[offset + 3],
            ));

            if let Some(ref domain) = query_domain {
                cache.insert(ip, domain.clone());
            }
        }

        offset += rdlength;
    }
}

fn extract_domain_from_query(query: &[u8]) -> Option<String> {
    if query.len() < 12 {
        return None;
    }

    let mut domain = String::new();
    let mut offset = 12;

    loop {
        if offset >= query.len() {
            return None;
        }
        let label_len = query[offset] as usize;
        if label_len == 0 {
            break;
        }
        offset += 1;
        if offset + label_len > query.len() {
            return None;
        }
        if let Ok(label) = std::str::from_utf8(&query[offset..offset + label_len]) {
            if !domain.is_empty() {
                domain.push('.');
            }
            domain.push_str(label);
        }
        offset += label_len;
    }

    if domain.is_empty() {
        None
    } else {
        Some(domain)
    }
}

fn skip_name(data: &[u8], mut offset: usize) -> usize {
    loop {
        if offset >= data.len() {
            return offset;
        }
        let byte = data[offset];
        if byte == 0 {
            return offset + 1;
        }
        if byte & 0xC0 == 0xC0 {
            return offset + 2;
        }
        offset += 1 + byte as usize;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn insert_and_lookup() {
        let cache = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        cache.insert(ip, "example.com".to_string());
        assert_eq!(cache.lookup(&ip), Some("example.com".to_string()));
    }

    #[test]
    fn lookup_expired_returns_none() {
        let cache = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        cache.insert_with_ttl(ip, "example.com".to_string(), Duration::from_millis(0));
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(cache.lookup(&ip), None);
    }

    #[test]
    fn evict_expired() {
        let cache = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        cache.insert_with_ttl(ip, "example.com".to_string(), Duration::from_millis(0));
        std::thread::sleep(Duration::from_millis(10));
        cache.evict_expired();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn lookup_nonexistent_returns_none() {
        let cache = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(cache.lookup(&ip), None);
    }

    #[test]
    fn overwrite_existing_entry() {
        let cache = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        cache.insert(ip, "first.com".to_string());
        cache.insert(ip, "second.com".to_string());
        assert_eq!(cache.lookup(&ip), Some("second.com".to_string()));
    }

    #[test]
    fn parse_dns_response_basic() {
        let query = build_test_query("example.com");
        let response = build_test_response("example.com", "93.184.216.34");
        let cache = Arc::new(DnsCache::new());

        parse_dns_response_to_cache(&query, &response, &cache);

        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        assert_eq!(cache.lookup(&ip), Some("example.com".to_string()));
    }

    fn build_test_query(domain: &str) -> Vec<u8> {
        let mut query = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in domain.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0x00);
        query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        query
    }

    fn build_test_response(domain: &str, ip: &str) -> Vec<u8> {
        let mut resp = vec![
            0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];

        for label in domain.split('.') {
            resp.push(label.len() as u8);
            resp.extend_from_slice(label.as_bytes());
        }
        resp.push(0x00);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C]);
        resp.extend_from_slice(&[0x00, 0x04]);

        let parts: Vec<u8> = ip.split('.').map(|p| p.parse().unwrap()).collect();
        resp.extend_from_slice(&parts);

        resp
    }
}
