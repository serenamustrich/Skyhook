use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

const DEFAULT_TTL_SECS: u64 = 300;
const DEFAULT_POOL_START: u32 = 0x01000001; // 1.0.0.1
const DEFAULT_POOL_END: u32 = 0x01FFFFFE; // 1.255.255.254

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FakeIpConfig {
    pub enabled: bool,
    pub pool_start: Ipv4Addr,
    pub pool_end: Ipv4Addr,
    pub ttl_secs: u64,
    pub filter_mode: FakeIpFilterMode,
    pub filter_domains: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FakeIpFilterMode {
    Blacklist,
    Whitelist,
}

impl Default for FakeIpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            pool_start: Ipv4Addr::from(DEFAULT_POOL_START),
            pool_end: Ipv4Addr::from(DEFAULT_POOL_END),
            ttl_secs: DEFAULT_TTL_SECS,
            filter_mode: FakeIpFilterMode::Blacklist,
            filter_domains: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct FakeIpEntry {
    domain: String,
    allocated_at: Instant,
    ttl: Duration,
}

#[derive(Debug)]
pub struct FakeIpPool {
    config: FakeIpConfig,
    ip_to_domain: RwLock<HashMap<Ipv4Addr, FakeIpEntry>>,
    domain_to_ip: RwLock<HashMap<String, Ipv4Addr>>,
    next_ip: RwLock<u32>,
}

impl FakeIpPool {
    pub fn new(config: FakeIpConfig) -> Self {
        let start = u32::from(config.pool_start);
        Self {
            config,
            ip_to_domain: RwLock::new(HashMap::new()),
            domain_to_ip: RwLock::new(HashMap::new()),
            next_ip: RwLock::new(start),
        }
    }

    pub fn allocate(&self, domain: &str) -> Option<Ipv4Addr> {
        if !self.config.enabled {
            return None;
        }

        // Check filter
        if !self.should_allocate(domain) {
            return None;
        }

        // Check if already allocated
        if let Some(ip) = self.domain_to_ip.read().ok()?.get(domain) {
            return Some(*ip);
        }

        // Allocate new IP
        let ip = self.next_available_ip()?;
        let entry = FakeIpEntry {
            domain: domain.to_string(),
            allocated_at: Instant::now(),
            ttl: Duration::from_secs(self.config.ttl_secs),
        };

        self.ip_to_domain.write().ok()?.insert(ip, entry);
        self.domain_to_ip
            .write()
            .ok()?
            .insert(domain.to_string(), ip);

        Some(ip)
    }

    pub fn reverse_lookup(&self, ip: &Ipv4Addr) -> Option<String> {
        let entries = self.ip_to_domain.read().ok()?;
        let entry = entries.get(ip)?;

        // Check TTL
        if entry.allocated_at.elapsed() > entry.ttl {
            return None;
        }

        Some(entry.domain.clone())
    }

    pub fn evict_expired(&self) {
        let now = Instant::now();
        let mut expired_ips = Vec::new();

        if let Ok(entries) = self.ip_to_domain.read() {
            for (ip, entry) in entries.iter() {
                if now.duration_since(entry.allocated_at) > entry.ttl {
                    expired_ips.push((*ip, entry.domain.clone()));
                }
            }
        }

        if let Ok(mut ip_map) = self.ip_to_domain.write() {
            for (ip, _) in &expired_ips {
                ip_map.remove(ip);
            }
        }

        if let Ok(mut domain_map) = self.domain_to_ip.write() {
            for (_, domain) in &expired_ips {
                domain_map.remove(domain);
            }
        }
    }

    pub fn is_fake_ip(&self, ip: &Ipv4Addr) -> bool {
        let ip_u32 = u32::from(*ip);
        ip_u32 >= u32::from(self.config.pool_start) && ip_u32 <= u32::from(self.config.pool_end)
    }

    fn should_allocate(&self, domain: &str) -> bool {
        match self.config.filter_mode {
            FakeIpFilterMode::Blacklist => !self
                .config
                .filter_domains
                .iter()
                .any(|d| domain.ends_with(d)),
            FakeIpFilterMode::Whitelist => self
                .config
                .filter_domains
                .iter()
                .any(|d| domain.ends_with(d)),
        }
    }

    fn next_available_ip(&self) -> Option<Ipv4Addr> {
        let mut next = self.next_ip.write().ok()?;
        let start = *next;
        let end = u32::from(self.config.pool_end);

        loop {
            let ip = Ipv4Addr::from(*next);

            // Check if IP is available
            if let Ok(entries) = self.ip_to_domain.read() {
                if !entries.contains_key(&ip) {
                    return Some(ip);
                }
            }

            // Move to next IP
            *next = if *next >= end {
                u32::from(self.config.pool_start)
            } else {
                *next + 1
            };

            // Check if we've wrapped around
            if *next == start {
                return None; // Pool exhausted
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fake_ip_allocate() {
        let config = FakeIpConfig {
            enabled: true,
            ..Default::default()
        };
        let pool = FakeIpPool::new(config);

        let ip1 = pool.allocate("example.com").unwrap();
        let ip2 = pool.allocate("example.com").unwrap();
        assert_eq!(ip1, ip2); // Same domain gets same IP

        let ip3 = pool.allocate("other.com").unwrap();
        assert_ne!(ip1, ip3); // Different domain gets different IP
    }

    #[test]
    fn test_fake_ip_reverse_lookup() {
        let config = FakeIpConfig {
            enabled: true,
            ..Default::default()
        };
        let pool = FakeIpPool::new(config);

        let ip = pool.allocate("example.com").unwrap();
        let domain = pool.reverse_lookup(&ip).unwrap();
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn test_fake_ip_is_fake() {
        let config = FakeIpConfig {
            enabled: true,
            ..Default::default()
        };
        let pool = FakeIpPool::new(config);

        let ip = pool.allocate("example.com").unwrap();
        assert!(pool.is_fake_ip(&ip));
        assert!(!pool.is_fake_ip(&Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn test_fake_ip_filter() {
        let config = FakeIpConfig {
            enabled: true,
            filter_mode: FakeIpFilterMode::Blacklist,
            filter_domains: vec!["local".to_string()],
            ..Default::default()
        };
        let pool = FakeIpPool::new(config);

        assert!(pool.allocate("example.com").is_some());
        assert!(pool.allocate("test.local").is_none());
    }

    #[test]
    fn test_fake_ip_disabled() {
        let config = FakeIpConfig {
            enabled: false,
            ..Default::default()
        };
        let pool = FakeIpPool::new(config);

        assert!(pool.allocate("example.com").is_none());
    }
}
