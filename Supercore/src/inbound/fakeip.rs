use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

use crate::config::FakeIpFilterMode;

const FAKE_IP_RANGE_START: u32 = 0xC6120001; // 198.18.0.1
const FAKE_IP_RANGE_END: u32 = 0xC613FFFF;   // 198.19.255.255

#[derive(Debug, Clone)]
struct FakeIpEntry {
    ip: Ipv4Addr,
    domain: String,
    created_at: Instant,
    ttl: Duration,
}

impl FakeIpEntry {
    fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.ttl
    }
}

#[derive(Clone)]
pub struct FakeIpStore {
    inner: Arc<RwLock<FakeIpInner>>,
}

struct FakeIpInner {
    domain_to_ip: HashMap<String, FakeIpEntry>,
    ip_to_domain: HashMap<Ipv4Addr, FakeIpEntry>,
    next_ip: u32,
    ttl: Duration,
    filter: Vec<String>,
    filter_mode: FakeIpFilterMode,
}

impl FakeIpStore {
    pub fn new(ttl_secs: u64, filter: Vec<String>, filter_mode: FakeIpFilterMode) -> Self {
        Self {
            inner: Arc::new(RwLock::new(FakeIpInner {
                domain_to_ip: HashMap::new(),
                ip_to_domain: HashMap::new(),
                next_ip: FAKE_IP_RANGE_START,
                ttl: Duration::from_secs(ttl_secs.max(10)),
                filter,
                filter_mode,
            })),
        }
    }

    pub async fn lookup_or_create(&self, domain: &str) -> Option<Ipv4Addr> {
        let mut inner = self.inner.write().await;
        let filter_matches = inner
            .filter
            .iter()
            .any(|item| domain_matches_filter(domain, item));
        let should_fake = match inner.filter_mode {
            FakeIpFilterMode::Blacklist | FakeIpFilterMode::Rule => !filter_matches,
            FakeIpFilterMode::Whitelist => filter_matches,
        };
        if !should_fake {
            return None;
        }

        if let Some(entry) = inner.domain_to_ip.get(domain) {
            if !entry.is_expired() {
                return Some(entry.ip);
            }
        }

        loop {
            let ip = Ipv4Addr::from(inner.next_ip);
            inner.next_ip = if inner.next_ip >= FAKE_IP_RANGE_END {
                FAKE_IP_RANGE_START
            } else {
                inner.next_ip + 1
            };

            let expired = inner.ip_to_domain.get(&ip).map(|e| e.is_expired()).unwrap_or(true);
            if !expired {
                continue;
            }

            if let Some(old_domain) = inner.ip_to_domain.get(&ip).map(|e| e.domain.clone()) {
                inner.domain_to_ip.remove(&old_domain);
            }

            let entry = FakeIpEntry {
                ip,
                domain: domain.to_string(),
                created_at: Instant::now(),
                ttl: inner.ttl,
            };
            inner.domain_to_ip.insert(domain.to_string(), entry.clone());
            inner.ip_to_domain.insert(ip, entry);
            return Some(ip);
        }
    }

    pub async fn reverse_lookup(&self, ip: &Ipv4Addr) -> Option<String> {
        let inner = self.inner.read().await;
        inner.ip_to_domain.get(ip).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some(entry.domain.clone())
            }
        })
    }

    pub async fn is_fake_ip(&self, ip: &Ipv4Addr) -> bool {
        let num: u32 = (*ip).into();
        num >= FAKE_IP_RANGE_START && num <= FAKE_IP_RANGE_END
    }

    pub async fn cleanup_expired(&self) {
        let mut inner = self.inner.write().await;
        let expired_domains: Vec<String> = inner
            .domain_to_ip
            .iter()
            .filter(|(_, e)| e.is_expired())
            .map(|(d, _)| d.clone())
            .collect();
        for domain in expired_domains {
            if let Some(entry) = inner.domain_to_ip.remove(&domain) {
                inner.ip_to_domain.remove(&entry.ip);
            }
        }
    }

    pub async fn len(&self) -> usize {
        self.inner.read().await.domain_to_ip.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.inner.read().await.domain_to_ip.is_empty()
    }

    pub async fn clear(&self) {
        let mut inner = self.inner.write().await;
        inner.domain_to_ip.clear();
        inner.ip_to_domain.clear();
    }
}

fn domain_matches_filter(domain: &str, filter: &str) -> bool {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    let filter = filter.trim().trim_end_matches('.').to_ascii_lowercase();
    if filter.is_empty() {
        return false;
    }
    if filter == "*" {
        return true;
    }
    let suffix = filter
        .strip_prefix("*.")
        .or_else(|| filter.strip_prefix("+."))
        .unwrap_or(filter.trim_start_matches('.'));
    domain == suffix || domain.ends_with(&format!(".{suffix}"))
}

pub fn build_fake_ip_dns_response(
    query: &[u8],
    domain: &str,
    fake_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut response = Vec::with_capacity(query.len() + 32);

    let Some(query_domain) = extract_domain_from_dns_query(query) else {
        return Vec::new();
    };
    if !query_domain.eq_ignore_ascii_case(domain) {
        return Vec::new();
    }

    if query.len() < 12 {
        return Vec::new();
    }

    response.extend_from_slice(&query[0..2]);
    response.extend_from_slice(&[0x81, 0x80]);
    response.extend_from_slice(&query[4..6]);
    response.extend_from_slice(&query[4..6]);
    response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    response.extend_from_slice(&query[12..]);

    let ip = fake_ip.octets();
    response.extend_from_slice(&[0xC0, 0x0C]);
    response.extend_from_slice(&[0x00, 0x01]);
    response.extend_from_slice(&[0x00, 0x01]);
    response.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]);
    response.extend_from_slice(&[0x00, 0x04]);
    response.extend_from_slice(&ip);

    response
}

pub fn extract_domain_from_dns_query(query: &[u8]) -> Option<String> {
    if query.len() < 12 {
        return None;
    }

    let mut pos = 12;
    let mut domain = String::new();

    loop {
        if pos >= query.len() {
            return None;
        }
        let len = query[pos] as usize;
        if len == 0 {
            break;
        }
        if len >= 192 {
            return None;
        }
        pos += 1;
        if pos + len > query.len() {
            return None;
        }
        if let Ok(label) = std::str::from_utf8(&query[pos..pos + len]) {
            if !domain.is_empty() {
                domain.push('.');
            }
            domain.push_str(label);
        }
        pos += len;
    }

    if pos + 4 <= query.len() {
        let qtype = u16::from_be_bytes([query[pos + 1], query[pos + 2]]);
        if qtype == 1 {
            Some(domain)
        } else {
            None
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn blacklist_filter_bypasses_fake_ip_for_matching_domain() {
        let store = FakeIpStore::new(
            60,
            vec!["+.example.com".to_string()],
            FakeIpFilterMode::Blacklist,
        );

        assert_eq!(store.lookup_or_create("api.example.com").await, None);
        assert!(store.lookup_or_create("example.net").await.is_some());
    }

    #[tokio::test]
    async fn whitelist_filter_only_fakes_matching_domain() {
        let store = FakeIpStore::new(
            60,
            vec!["*.example.com".to_string()],
            FakeIpFilterMode::Whitelist,
        );

        assert!(store.lookup_or_create("api.example.com").await.is_some());
        assert_eq!(store.lookup_or_create("example.net").await, None);
    }
}
