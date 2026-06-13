use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use skyhook::{
    config::{OutboundConfig, RuleTarget, SuperConfig},
    subscription_store::{SubscriptionStore, SubscriptionUpdateOptions},
};

const FIRST_SUB: &str = r#"
proxies:
  - name: HK-01
    type: ss
    server: hk.example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
proxy-groups:
  - name: First Group
    type: select
    proxies:
      - HK-01
rules:
  - DOMAIN-SUFFIX,first.example,First Group
  - MATCH,HK-01
"#;

const SECOND_SUB: &str = r#"
proxies:
  - name: SG-01
    type: trojan
    server: sg.example.com
    port: 443
    password: secret
    sni: sg.example.com
proxy-groups:
  - name: Second Group
    type: url-test
    proxies:
      - SG-01
rules:
  - DOMAIN-SUFFIX,second.example,Second Group
  - MATCH,SG-01
"#;

#[test]
fn subscription_first_import_auto_switches_and_later_import_does_not() {
    let root = unique_store_dir("switch-policy");
    let store = SubscriptionStore::new(&root);

    let first = store
        .import_text(
            Some("First".to_string()),
            Some("https://example.com/first".to_string()),
            FIRST_SUB,
            false,
        )
        .expect("first import");
    let second = store
        .import_text(
            Some("Second".to_string()),
            Some("https://example.com/second".to_string()),
            SECOND_SUB,
            false,
        )
        .expect("second import");

    assert!(first.active_changed, "first import should become active");
    assert!(
        !second.active_changed,
        "later import must not steal active subscription"
    );
    assert_eq!(
        store.index().expect("index").active_id.as_deref(),
        Some(first.meta.id.as_str())
    );
    assert_eq!(store.index().expect("index").subscriptions.len(), 2);

    fs::remove_dir_all(root).ok();
}

#[test]
fn subscription_can_switch_active_explicitly() {
    let root = unique_store_dir("explicit-switch");
    let store = SubscriptionStore::new(&root);

    let first = store
        .import_text(Some("First".to_string()), None, FIRST_SUB, false)
        .expect("first import");
    let second = store
        .import_text(Some("Second".to_string()), None, SECOND_SUB, false)
        .expect("second import");
    let active = store.set_active(&second.meta.id).expect("set active");

    assert_eq!(active.id, second.meta.id);
    assert_ne!(active.id, first.meta.id);
    assert_eq!(
        store.index().expect("index").active_id.as_deref(),
        Some(second.meta.id.as_str())
    );

    fs::remove_dir_all(root).ok();
}

#[tokio::test]
async fn subscription_update_all_updates_every_saved_url() {
    let root = unique_store_dir("update-all");
    let server = SubscriptionTestServer::start(vec![FIRST_SUB, SECOND_SUB]);
    let store = SubscriptionStore::new(&root);

    let first = store
        .import_text(
            Some("First".to_string()),
            Some(server.url("/first")),
            FIRST_SUB,
            false,
        )
        .expect("first import");
    let second = store
        .import_text(
            Some("Second".to_string()),
            Some(server.url("/second")),
            SECOND_SUB,
            false,
        )
        .expect("second import");

    let results = store
        .update_all_from_urls_with(SubscriptionUpdateOptions {
            timeout_secs: 2,
            retries: 0,
            concurrency: 2,
        })
        .await
        .expect("update all");

    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|item| item.updated));
    assert_eq!(
        store.document(&first.meta.id).expect("first doc").nodes[0].name,
        "HK-01"
    );
    assert_eq!(
        store.document(&second.meta.id).expect("second doc").nodes[0].name,
        "SG-01"
    );

    fs::remove_dir_all(root).ok();
}

#[test]
fn subscription_runtime_config_preserves_groups_rules_and_default() {
    let root = unique_store_dir("runtime-config");
    let store = SubscriptionStore::new(&root);
    store
        .import_text(Some("First".to_string()), None, FIRST_SUB, false)
        .expect("import");

    let config = store
        .active_runtime_config(SuperConfig::default(), true)
        .expect("runtime config");

    assert_eq!(config.core.default_outbound, "HK-01");
    assert!(config
        .outbounds
        .iter()
        .any(|item| matches!(item, OutboundConfig::Shadowsocks { name, .. } if name == "HK-01")));
    assert!(config.outbounds.iter().any(|item| {
        matches!(
            item,
            OutboundConfig::Group { name, kind, members }
                if name == "First Group" && kind == "select" && members == &vec!["HK-01".to_string()]
        )
    }));
    assert!(config.rules.iter().any(|rule| {
        rule.target == RuleTarget::DomainSuffix
            && rule.value == "first.example"
            && rule.outbound == "First Group"
    }));
    assert!(config
        .rules
        .iter()
        .any(|rule| rule.target == RuleTarget::Match && rule.outbound == "HK-01"));

    fs::remove_dir_all(root).ok();
}

struct SubscriptionTestServer {
    addr: std::net::SocketAddr,
    handle: Option<thread::JoinHandle<()>>,
}

impl SubscriptionTestServer {
    fn start(responses: Vec<&'static str>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        let handle = thread::spawn(move || {
            for response in responses {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let mut buffer = [0u8; 1024];
                let _ = stream.read(&mut buffer);
                let body = response.as_bytes();
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(body);
            }
        });
        Self {
            addr,
            handle: Some(handle),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}

impl Drop for SubscriptionTestServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn unique_store_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("skyhook-subscription-tests-{name}-{nanos}"))
}
