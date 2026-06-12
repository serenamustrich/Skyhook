use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

const CACHE_TTL: Duration = Duration::from_secs(5);
const MAX_ENTRIES: usize = 5000;

#[derive(Debug, Clone)]
pub struct ProcessMetadata {
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub bundle_id: Option<String>,
    pub executable_path: Option<String>,
}

#[derive(Debug, Clone)]
struct CachedProcess {
    metadata: ProcessMetadata,
    inserted_at: Instant,
}

pub struct ProcessResolver {
    cache: RwLock<HashMap<SocketAddr, CachedProcess>>,
}

impl ProcessResolver {
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
        }
    }

    pub fn lookup(&self, addr: &SocketAddr) -> Option<ProcessMetadata> {
        let cache = match self.cache.read() {
            Ok(guard) => guard,
            Err(_) => return None,
        };

        cache.get(addr).and_then(|entry| {
            if entry.inserted_at.elapsed() < CACHE_TTL {
                Some(entry.metadata.clone())
            } else {
                None
            }
        })
    }

    pub fn resolve(&self, addr: &SocketAddr) -> Option<ProcessMetadata> {
        if let Some(cached) = self.lookup(addr) {
            return Some(cached);
        }

        let metadata = self.query_process_for_addr(addr)?;

        let mut cache = match self.cache.write() {
            Ok(guard) => guard,
            Err(_) => return Some(metadata),
        };

        if cache.len() >= MAX_ENTRIES {
            cache.retain(|_, entry| entry.inserted_at.elapsed() < CACHE_TTL);
        }

        cache.insert(
            *addr,
            CachedProcess {
                metadata: metadata.clone(),
                inserted_at: Instant::now(),
            },
        );

        Some(metadata)
    }

    #[cfg(target_os = "macos")]
    fn query_process_for_addr(&self, addr: &SocketAddr) -> Option<ProcessMetadata> {
        use std::process::Command;

        let port = addr.port();
        let output = Command::new("lsof")
            .args(["-nP", "-iTCP", &format!(":{}", port)])
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_lsof_output(&stdout, port)
    }

    #[cfg(target_os = "macos")]
    fn parse_lsof_output(&self, output: &str, port: u16) -> Option<ProcessMetadata> {
        for line in output.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 9 {
                continue;
            }

            let process_name = parts.get(0).map(|s| s.to_string());
            let pid: Option<u32> = parts.get(1).and_then(|s| s.parse().ok());

            let has_port = parts.iter().any(|p| p.contains(&format!(":{}", port)));
            if !has_port {
                continue;
            }

            return Some(ProcessMetadata {
                pid,
                process_name,
                bundle_id: None,
                executable_path: parts.get(8).map(|s| s.to_string()),
            });
        }

        None
    }

    #[cfg(target_os = "linux")]
    fn query_process_for_addr(&self, addr: &SocketAddr) -> Option<ProcessMetadata> {
        use std::process::Command;

        let output = Command::new("ss")
            .args(["-tlnp", &format!("sport = :{}", addr.port())])
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_ss_output(&stdout)
    }

    #[cfg(target_os = "linux")]
    fn parse_ss_output(&self, output: &str) -> Option<ProcessMetadata> {
        for line in output.lines().skip(1) {
            if let Some(pid_str) = line.split("pid=").nth(1) {
                let pid: Option<u32> = pid_str
                    .split(',')
                    .next()
                    .and_then(|s| s.trim().parse().ok());

                let process_name = pid.and_then(|p| {
                    std::fs::read_to_string(format!("/proc/{}/comm", p))
                        .ok()
                        .map(|s| s.trim().to_string())
                });

                return Some(ProcessMetadata {
                    pid,
                    process_name,
                    bundle_id: None,
                    executable_path: None,
                });
            }
        }

        None
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn query_process_for_addr(&self, _addr: &SocketAddr) -> Option<ProcessMetadata> {
        None
    }

    pub fn evict_expired(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.retain(|_, entry| entry.inserted_at.elapsed() < CACHE_TTL);
        }
    }

    pub fn len(&self) -> usize {
        self.cache.read().map(|c| c.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_creation() {
        let resolver = ProcessResolver::new();
        assert!(resolver.is_empty());
    }

    #[test]
    fn lookup_nonexistent_returns_none() {
        let resolver = ProcessResolver::new();
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        assert!(resolver.lookup(&addr).is_none());
    }

    #[test]
    fn cache_insert_and_lookup() {
        let resolver = ProcessResolver::new();
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let metadata = ProcessMetadata {
            pid: Some(1234),
            process_name: Some("test_process".to_string()),
            bundle_id: None,
            executable_path: None,
        };

        let mut cache = resolver.cache.write().unwrap();
        cache.insert(
            addr,
            CachedProcess {
                metadata: metadata.clone(),
                inserted_at: Instant::now(),
            },
        );
        drop(cache);

        let result = resolver.lookup(&addr);
        assert!(result.is_some());
        assert_eq!(result.unwrap().pid, Some(1234));
    }

    #[test]
    fn cache_expired_returns_none() {
        let resolver = ProcessResolver::new();
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let metadata = ProcessMetadata {
            pid: Some(1234),
            process_name: Some("test_process".to_string()),
            bundle_id: None,
            executable_path: None,
        };

        let mut cache = resolver.cache.write().unwrap();
        cache.insert(
            addr,
            CachedProcess {
                metadata,
                inserted_at: Instant::now() - Duration::from_secs(10),
            },
        );
        drop(cache);

        assert!(resolver.lookup(&addr).is_none());
    }
}
