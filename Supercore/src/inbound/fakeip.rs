use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, Instant},
};
use anyhow::anyhow;
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
    range_start: u32,
    range_end: u32,
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
                range_start: FAKE_IP_RANGE_START,
                range_end: FAKE_IP_RANGE_END,
                next_ip: FAKE_IP_RANGE_START,
                ttl: Duration::from_secs(ttl_secs.max(10)),
                filter,
                filter_mode,
            })),
        }
    }

    /// Apply DNS Fake-IP policy changes without replacing the shared store.
    /// Existing mappings are discarded whenever policy changes so a mapping
    /// created under the previous filter cannot survive a reload.
    pub fn reconfigure(
        &self,
        ttl_secs: u64,
        filter: Vec<String>,
        filter_mode: FakeIpFilterMode,
    ) -> anyhow::Result<()> {
        let mut inner = self
            .inner
            .try_write()
            .map_err(|_| anyhow!("fake-ip store is busy during reconfiguration"))?;
        let ttl = Duration::from_secs(ttl_secs.max(10));
        if inner.ttl != ttl || inner.filter != filter || inner.filter_mode != filter_mode {
            inner.domain_to_ip.clear();
            inner.ip_to_domain.clear();
        }
        inner.ttl = ttl;
        inner.filter = filter;
        inner.filter_mode = filter_mode;
        Ok(())
    }

    pub async fn lookup_or_create(&self, domain: &str) -> Option<Ipv4Addr> {
        let domain = canonical_domain(domain)?;
        let mut inner = self.inner.write().await;
        let filter_matches = inner
            .filter
            .iter()
            .any(|item| domain_matches_filter(&domain, item));
        let should_fake = match inner.filter_mode {
            FakeIpFilterMode::Blacklist | FakeIpFilterMode::Rule => !filter_matches,
            FakeIpFilterMode::Whitelist => filter_matches,
        };
        if !should_fake {
            return None;
        }

        if let Some(entry) = inner.domain_to_ip.get(&domain) {
            if !entry.is_expired() {
                return Some(entry.ip);
            }
            let old_ip = entry.ip;
            inner.domain_to_ip.remove(&domain);
            if inner
                .ip_to_domain
                .get(&old_ip)
                .is_some_and(|current| current.domain == domain)
            {
                inner.ip_to_domain.remove(&old_ip);
            }
        }

        let range_size = inner.range_end - inner.range_start + 1;
        for _ in 0..range_size {
            let ip = Ipv4Addr::from(inner.next_ip);
            inner.next_ip = if inner.next_ip >= inner.range_end {
                inner.range_start
            } else {
                inner.next_ip + 1
            };

            let expired = inner.ip_to_domain.get(&ip).map(|e| e.is_expired()).unwrap_or(true);
            if !expired {
                continue;
            }

            if let Some(old_domain) = inner.ip_to_domain.get(&ip).map(|e| e.domain.clone()) {
                if inner
                    .domain_to_ip
                    .get(&old_domain)
                    .is_some_and(|current| current.ip == ip)
                {
                    inner.domain_to_ip.remove(&old_domain);
                }
                inner.ip_to_domain.remove(&ip);
            }

            let entry = FakeIpEntry {
                ip,
                domain: domain.clone(),
                created_at: Instant::now(),
                ttl: inner.ttl,
            };
            inner.domain_to_ip.insert(domain.clone(), entry.clone());
            inner.ip_to_domain.insert(ip, entry);
            return Some(ip);
        }

        None
    }

    pub async fn reverse_lookup(&self, ip: &Ipv4Addr) -> Option<String> {
        let mut inner = self.inner.write().await;
        let entry = inner.ip_to_domain.get(ip).cloned()?;
        if entry.is_expired() {
            inner.ip_to_domain.remove(ip);
            if inner
                .domain_to_ip
                .get(&entry.domain)
                .is_some_and(|current| current.ip == *ip)
            {
                inner.domain_to_ip.remove(&entry.domain);
            }
            None
        } else {
            Some(entry.domain)
        }
    }

    pub async fn is_fake_ip(&self, ip: &Ipv4Addr) -> bool {
        let num: u32 = (*ip).into();
        (FAKE_IP_RANGE_START..=FAKE_IP_RANGE_END).contains(&num)
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
    if let Some(suffix) = filter
        .strip_prefix("*.")
        .or_else(|| filter.strip_prefix("+."))
        .or_else(|| filter.strip_prefix('.'))
    {
        return domain == suffix || domain.ends_with(&format!(".{suffix}"));
    }
    domain == filter
}

fn canonical_domain(value: &str) -> Option<String> {
    let domain = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() || domain.len() > 253 || domain.starts_with('.') || domain.ends_with('.') {
        return None;
    }
    if domain.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte >= 0x80)
    }) {
        return None;
    }
    Some(domain)
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

    #[tokio::test]
    async fn reconfigure_replaces_policy_and_invalidates_old_mappings() {
        let store = FakeIpStore::new(
            60,
            vec!["+.example.com".to_string()],
            FakeIpFilterMode::Blacklist,
        );

        assert_eq!(store.lookup_or_create("api.example.com").await, None);
        let old_ip = store.lookup_or_create("example.net").await.unwrap();
        assert_eq!(store.reverse_lookup(&old_ip).await.as_deref(), Some("example.net"));

        store.reconfigure(
            120,
            vec!["+.example.net".to_string()],
            FakeIpFilterMode::Blacklist,
        )
        .expect("reconfigure");

        assert_eq!(store.len().await, 0);
        assert_eq!(store.lookup_or_create("example.net").await, None);
        assert!(store.lookup_or_create("api.example.com").await.is_some());
    }

    #[tokio::test]
    async fn domain_keys_are_canonical_and_exact_filters_stay_exact() {
        let store = FakeIpStore::new(60, vec!["example.com".to_string()], FakeIpFilterMode::Blacklist);

        assert_eq!(store.lookup_or_create("Example.COM.").await, None);
        let first = store.lookup_or_create("Example.NET.").await.unwrap();
        assert_eq!(store.lookup_or_create("example.net").await, Some(first));
        assert_eq!(store.lookup_or_create("api.example.net").await, Some(Ipv4Addr::new(198, 18, 0, 2)));
    }

    #[tokio::test]
    async fn expired_entries_are_removed_from_both_indexes() {
        let store = FakeIpStore::new(60, Vec::new(), FakeIpFilterMode::Blacklist);
        let ip = store.lookup_or_create("expired.example").await.unwrap();
        {
            let mut inner = store.inner.write().await;
            inner.domain_to_ip.get_mut("expired.example").unwrap().ttl = Duration::ZERO;
            inner.ip_to_domain.get_mut(&ip).unwrap().ttl = Duration::ZERO;
            assert!(inner.ip_to_domain.contains_key(&ip));
        }
        assert_eq!(store.reverse_lookup(&ip).await, None);
        assert_eq!(store.len().await, 0);
    }

    #[tokio::test]
    async fn full_pool_returns_none_without_overwriting_live_entries() {
        let store = FakeIpStore {
            inner: Arc::new(RwLock::new(FakeIpInner {
                domain_to_ip: HashMap::new(),
                ip_to_domain: HashMap::new(),
                range_start: 1,
                range_end: 1,
                next_ip: 1,
                ttl: Duration::from_secs(60),
                filter: Vec::new(),
                filter_mode: FakeIpFilterMode::Blacklist,
            })),
        };
        let first = store.lookup_or_create("one.example").await.unwrap();
        assert_eq!(store.lookup_or_create("two.example").await, None);
        assert_eq!(store.reverse_lookup(&first).await.as_deref(), Some("one.example"));
    }
}
