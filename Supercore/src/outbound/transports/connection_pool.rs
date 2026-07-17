use std::{future::Future, sync::Arc};

use tokio::sync::Mutex;

pub(crate) struct SharedConnectionPool<T> {
    connection: Mutex<Option<Arc<T>>>,
}

impl<T> Default for SharedConnectionPool<T> {
    fn default() -> Self {
        Self {
            connection: Mutex::new(None),
        }
    }
}

impl<T> SharedConnectionPool<T> {
    pub(crate) async fn get_or_connect<E, H, C, F>(
        &self,
        healthy: H,
        connect: C,
    ) -> Result<Arc<T>, E>
    where
        H: Fn(&T) -> bool,
        C: FnOnce() -> F,
        F: Future<Output = Result<T, E>>,
    {
        let mut pooled = self.connection.lock().await;
        if let Some(connection) = pooled.as_ref().filter(|connection| healthy(connection)) {
            return Ok(Arc::clone(connection));
        }

        // Drop a failed transport before opening its replacement. The mutex is
        // intentionally held across connect so concurrent callers share one
        // authenticated QUIC handshake instead of creating a connection burst.
        pooled.take();
        let connection = Arc::new(connect().await?);
        *pooled = Some(Arc::clone(&connection));
        Ok(connection)
    }

    #[cfg(test)]
    async fn clear(&self) {
        self.connection.lock().await.take();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    use quinn::crypto::rustls::QuicServerConfig;
    use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer};

    use crate::outbound::transports::{
        connect_quic_endpoint, create_quic_endpoint, quic_client_config,
    };

    use super::SharedConnectionPool;

    const TEST_ALPN: &str = "supercore-pool-test";

    #[derive(Debug)]
    struct TestConnection {
        healthy: AtomicBool,
        dropped: Arc<AtomicUsize>,
    }

    impl TestConnection {
        fn new(dropped: Arc<AtomicUsize>) -> Self {
            Self {
                healthy: AtomicBool::new(true),
                dropped,
            }
        }
    }

    impl Drop for TestConnection {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn concurrent_callers_share_one_connection_attempt() {
        let pool = Arc::new(SharedConnectionPool::default());
        let connects = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut callers = Vec::new();

        for _ in 0..24 {
            let pool = Arc::clone(&pool);
            let connects = Arc::clone(&connects);
            let dropped = Arc::clone(&dropped);
            callers.push(tokio::spawn(async move {
                pool.get_or_connect(
                    |connection: &TestConnection| connection.healthy.load(Ordering::SeqCst),
                    || async move {
                        connects.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        Ok::<_, ()>(TestConnection::new(dropped))
                    },
                )
                .await
                .expect("pooled connection")
            }));
        }

        let first = callers.remove(0).await.expect("first caller join failed");
        for caller in callers {
            let connection = caller.await.expect("caller join failed");
            assert!(Arc::ptr_eq(&first, &connection));
        }
        assert_eq!(connects.load(Ordering::SeqCst), 1);
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn unhealthy_connection_is_closed_and_rebuilt_once() {
        let pool = SharedConnectionPool::default();
        let connects = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));

        let first = pool
            .get_or_connect(
                |connection: &TestConnection| connection.healthy.load(Ordering::SeqCst),
                {
                    let connects = Arc::clone(&connects);
                    let dropped = Arc::clone(&dropped);
                    move || async move {
                        connects.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, ()>(TestConnection::new(dropped))
                    }
                },
            )
            .await
            .expect("first connection");
        first.healthy.store(false, Ordering::SeqCst);
        drop(first);

        let replacement = pool
            .get_or_connect(
                |connection: &TestConnection| connection.healthy.load(Ordering::SeqCst),
                {
                    let connects = Arc::clone(&connects);
                    let dropped = Arc::clone(&dropped);
                    move || async move {
                        connects.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, ()>(TestConnection::new(dropped))
                    }
                },
            )
            .await
            .expect("replacement connection");

        assert!(replacement.healthy.load(Ordering::SeqCst));
        assert_eq!(connects.load(Ordering::SeqCst), 2);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);

        drop(replacement);
        pool.clear().await;
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn failed_rebuild_leaves_pool_empty_for_retry() {
        let pool = SharedConnectionPool::<TestConnection>::default();
        let attempts = AtomicUsize::new(0);
        let dropped = Arc::new(AtomicUsize::new(0));

        let error = pool
            .get_or_connect(
                |_| true,
                || async {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    Err::<TestConnection, _>("connect failed")
                },
            )
            .await
            .expect_err("first attempt must fail");
        assert_eq!(error, "connect failed");

        let connection = pool
            .get_or_connect(
                |_| true,
                || async {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, &str>(TestConnection::new(Arc::clone(&dropped)))
                },
            )
            .await
            .expect("retry connection");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        drop(connection);
        pool.clear().await;
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    struct QuicTestConnection {
        _endpoint: quinn::Endpoint,
        connection: quinn::Connection,
        dropped: Arc<AtomicUsize>,
    }

    impl Drop for QuicTestConnection {
        fn drop(&mut self) {
            self.connection
                .close(quinn::VarInt::from_u32(0), b"pool test close");
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn real_quic_server_observes_single_flight_rebuild_and_close() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let certificate =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("certificate");
        let certificate_der = CertificateDer::from(certificate.cert);
        let private_key = PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der());
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der], private_key.into())
            .expect("server crypto");
        server_crypto.alpn_protocols = vec![TEST_ALPN.as_bytes().to_vec()];
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_crypto).expect("QUIC server config"),
        ));
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .expect("QUIC server endpoint");
        let server_address = server_endpoint.local_addr().expect("server address");
        let accepted = Arc::new(AtomicUsize::new(0));
        let (connection_tx, mut connection_rx) = tokio::sync::mpsc::unbounded_channel();
        let accept_endpoint = server_endpoint.clone();
        let accepted_counter = Arc::clone(&accepted);
        let server_task = tokio::spawn(async move {
            while let Some(incoming) = accept_endpoint.accept().await {
                let connection = incoming.await.expect("incoming QUIC connection");
                accepted_counter.fetch_add(1, Ordering::SeqCst);
                if connection_tx.send(connection).is_err() {
                    break;
                }
            }
        });

        let pool = Arc::new(SharedConnectionPool::default());
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut callers = Vec::new();
        for _ in 0..16 {
            let pool = Arc::clone(&pool);
            let dropped = Arc::clone(&dropped);
            callers.push(tokio::spawn(async move {
                pool.get_or_connect(
                    |connection: &QuicTestConnection| {
                        connection.connection.close_reason().is_none()
                    },
                    || open_test_quic_connection(server_address, dropped),
                )
                .await
                .expect("shared real QUIC connection")
            }));
        }
        let mut client_connections = Vec::new();
        for caller in callers {
            client_connections.push(caller.await.expect("QUIC caller join"));
        }
        let first_client = Arc::clone(&client_connections[0]);
        assert!(client_connections
            .iter()
            .all(|connection| Arc::ptr_eq(&first_client, connection)));
        let first_server = tokio::time::timeout(Duration::from_secs(1), connection_rx.recv())
            .await
            .expect("first server accept timeout")
            .expect("first server connection");
        assert_eq!(accepted.load(Ordering::SeqCst), 1);

        first_server.close(quinn::VarInt::from_u32(7), b"invalidate pooled connection");
        tokio::time::timeout(Duration::from_secs(1), first_client.connection.closed())
            .await
            .expect("client must observe server close");
        drop(first_server);
        drop(first_client);
        drop(client_connections);

        let replacement = pool
            .get_or_connect(
                |connection: &QuicTestConnection| connection.connection.close_reason().is_none(),
                {
                    let dropped = Arc::clone(&dropped);
                    move || open_test_quic_connection(server_address, dropped)
                },
            )
            .await
            .expect("replacement real QUIC connection");
        let second_server = tokio::time::timeout(Duration::from_secs(1), connection_rx.recv())
            .await
            .expect("second server accept timeout")
            .expect("second server connection");
        assert_eq!(accepted.load(Ordering::SeqCst), 2);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);

        drop(replacement);
        pool.clear().await;
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
        drop(second_server);
        server_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
        tokio::time::timeout(Duration::from_secs(1), server_task)
            .await
            .expect("server task timeout")
            .expect("server task join");
    }

    async fn open_test_quic_connection(
        remote: SocketAddr,
        dropped: Arc<AtomicUsize>,
    ) -> anyhow::Result<QuicTestConnection> {
        let endpoint = create_quic_endpoint(remote)?;
        let (endpoint, connection) = connect_quic_endpoint(
            endpoint,
            remote,
            "localhost",
            quic_client_config(true, Some(TEST_ALPN), None)?,
            1_000,
            "pool-test",
        )
        .await?;
        Ok(QuicTestConnection {
            _endpoint: endpoint,
            connection,
            dropped,
        })
    }
}
