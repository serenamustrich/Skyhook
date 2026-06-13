use tempfile::NamedTempFile;

use skyhook::traffic_store::TrafficStore;

#[test]
fn traffic_store_persist_and_reload() {
    let file = NamedTempFile::new().unwrap();
    let path = file.path();

    let store = TrafficStore::new(path);
    store.add_global_traffic(1000, 2000);
    store.add_outbound_traffic("proxy-a", 500, 1000);
    store.add_subscription_traffic("sub-1", 300, 600);
    store.persist().unwrap();

    let reloaded = TrafficStore::new(path);
    let snapshot = reloaded.get();
    assert_eq!(snapshot.global_upload, 1000);
    assert_eq!(snapshot.global_download, 2000);
    assert_eq!(snapshot.per_outbound["proxy-a"].upload, 500);
    assert_eq!(snapshot.per_outbound["proxy-a"].download, 1000);
    assert_eq!(snapshot.per_subscription["sub-1"].upload, 300);
    assert_eq!(snapshot.per_subscription["sub-1"].download, 600);
    assert!(snapshot.saved_at.is_some());
}

#[test]
fn traffic_store_accumulate() {
    let file = NamedTempFile::new().unwrap();
    let store = TrafficStore::new(file.path());

    store.add_global_traffic(100, 200);
    store.add_global_traffic(50, 100);

    let snapshot = store.get();
    assert_eq!(snapshot.global_upload, 150);
    assert_eq!(snapshot.global_download, 300);
}

#[test]
fn traffic_store_outbound_accumulate() {
    let file = NamedTempFile::new().unwrap();
    let store = TrafficStore::new(file.path());

    store.add_outbound_traffic("proxy-a", 100, 200);
    store.add_outbound_traffic("proxy-a", 50, 100);
    store.add_outbound_traffic("proxy-b", 300, 400);

    let snapshot = store.get();
    assert_eq!(snapshot.per_outbound["proxy-a"].upload, 150);
    assert_eq!(snapshot.per_outbound["proxy-a"].download, 300);
    assert_eq!(snapshot.per_outbound["proxy-b"].upload, 300);
    assert_eq!(snapshot.per_outbound["proxy-b"].download, 400);
}

#[test]
fn traffic_store_subscription_accumulate() {
    let file = NamedTempFile::new().unwrap();
    let store = TrafficStore::new(file.path());

    store.add_subscription_traffic("sub-1", 100, 200);
    store.add_subscription_traffic("sub-1", 50, 100);
    store.add_subscription_traffic("sub-2", 300, 400);

    let snapshot = store.get();
    assert_eq!(snapshot.per_subscription["sub-1"].upload, 150);
    assert_eq!(snapshot.per_subscription["sub-1"].download, 300);
    assert_eq!(snapshot.per_subscription["sub-2"].upload, 300);
    assert_eq!(snapshot.per_subscription["sub-2"].download, 400);
}

#[test]
fn traffic_store_survives_reload() {
    let file = NamedTempFile::new().unwrap();
    let path = file.path();

    // First session
    {
        let store = TrafficStore::new(path);
        store.add_global_traffic(100, 200);
        store.persist().unwrap();
    }

    // Second session - simulates restart
    {
        let store = TrafficStore::new(path);
        let snapshot = store.get();
        assert_eq!(snapshot.global_upload, 100);
        assert_eq!(snapshot.global_download, 200);

        // Add more traffic
        store.add_global_traffic(50, 100);
        store.persist().unwrap();
    }

    // Third session
    {
        let store = TrafficStore::new(path);
        let snapshot = store.get();
        assert_eq!(snapshot.global_upload, 150);
        assert_eq!(snapshot.global_download, 300);
    }
}
