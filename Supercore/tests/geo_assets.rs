use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

use supercore::{
    config::{GeoConfig, SuperConfig},
    geo::{prepare_geo_assets, update_geo_assets, update_geo_assets_with_progress},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn geo_assets_download_to_cache_and_prepare_geoip_database() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let len = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..len]);
            let body: &[u8] = if request.contains("GET /geoip.mmdb") {
                b"fake-mmdb"
            } else if request.contains("GET /geosite.dat") {
                b"fake-geosite"
            } else {
                b"not-found"
            };
            let status = if body == b"not-found" {
                "404 Not Found"
            } else {
                "200 OK"
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
        }
    });

    let cache_dir = unique_test_dir("geo-assets");
    let config = GeoConfig {
        auto_update: true,
        update_on_start: true,
        cache_dir: cache_dir.clone(),
        geoip_url: Some(format!("http://{addr}/geoip.mmdb")),
        geosite_url: Some(format!("http://{addr}/geosite.dat")),
        update_timeout_secs: 2,
    };

    let summaries = update_geo_assets(&config).await.unwrap();

    assert_eq!(summaries.len(), 2);
    assert!(summaries.iter().all(|summary| summary.updated));
    assert!(summaries
        .iter()
        .all(|summary| summary.source == format!("http://{addr}")));
    assert!(summaries
        .iter()
        .all(|summary| !summary.source.contains("geoip.mmdb")));
    assert_eq!(
        fs::read(cache_dir.join("geoip.mmdb")).unwrap(),
        b"fake-mmdb"
    );
    assert_eq!(
        fs::read(cache_dir.join("geosite.dat")).unwrap(),
        b"fake-geosite"
    );

    server.await.unwrap();
}

#[tokio::test]
#[allow(clippy::field_reassign_with_default)]
async fn prepare_geo_assets_uses_cached_geoip_when_no_url_is_configured() {
    let cache_dir = unique_test_dir("geo-cached");
    fs::create_dir_all(&cache_dir).unwrap();
    fs::write(cache_dir.join("geoip.mmdb"), b"cached-mmdb").unwrap();

    let mut config = SuperConfig::default();
    config.geo = GeoConfig {
        auto_update: true,
        update_on_start: true,
        cache_dir: cache_dir.clone(),
        geoip_url: None,
        geosite_url: None,
        update_timeout_secs: 2,
    };

    let config = prepare_geo_assets(config).await;

    assert_eq!(config.geoip_database, Some(cache_dir.join("geoip.mmdb")));
}

#[tokio::test]
async fn manual_geo_update_can_force_refresh_when_auto_update_is_disabled() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 1024];
        let _ = stream.read(&mut request).await.unwrap();
        let body = b"forced-mmdb";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
    });
    let cache_dir = unique_test_dir("geo-force");
    let config = GeoConfig {
        auto_update: false,
        update_on_start: false,
        cache_dir: cache_dir.clone(),
        geoip_url: Some(format!("http://{addr}/private-token/geoip.mmdb")),
        geosite_url: None,
        update_timeout_secs: 2,
    };

    let summaries = update_geo_assets_with_progress(&config, true, CancellationToken::new(), None)
        .await
        .unwrap();

    assert_eq!(summaries.len(), 1);
    assert!(summaries[0].updated);
    assert_eq!(summaries[0].source, format!("http://{addr}"));
    assert!(!summaries[0].source.contains("private-token"));
    assert_eq!(
        fs::read(cache_dir.join("geoip.mmdb")).unwrap(),
        b"forced-mmdb"
    );
    server.await.unwrap();
}

fn unique_test_dir(name: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("supercore-{name}-{nanos}"))
}
