use std::time::Duration;

use supercore::{config::OutboundConfig, outbound::build_outbounds, routing::Destination};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinSet,
    time::timeout,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_outbound_handles_one_thousand_concurrent_streams() {
    const CONNECTIONS: usize = 1_000;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("listener address");
    let server = tokio::spawn(async move {
        let mut handlers = JoinSet::new();
        for _ in 0..CONNECTIONS {
            let (mut stream, _) = listener.accept().await.expect("accept");
            handlers.spawn(async move {
                let mut request = [0_u8; 4];
                stream.read_exact(&mut request).await.expect("server read");
                assert_eq!(&request, b"ping");
                stream.write_all(b"pong").await.expect("server write");
            });
        }
        while handlers.join_next().await.is_some() {}
    });

    let configs = [OutboundConfig::Direct {
        name: "direct".to_string(),
    }];
    let outbounds = build_outbounds(&configs, None).expect("outbounds");
    let direct = outbounds.get("direct").expect("direct outbound").clone();
    let mut clients = JoinSet::new();
    for _ in 0..CONNECTIONS {
        let direct = direct.clone();
        clients.spawn(async move {
            let mut stream = direct
                .connect(
                    &Destination::new(address.ip().to_string(), address.port()),
                    5_000,
                )
                .await
                .expect("connect");
            stream.write_all(b"ping").await.expect("client write");
            let mut response = [0_u8; 4];
            stream.read_exact(&mut response).await.expect("client read");
            assert_eq!(&response, b"pong");
        });
    }

    timeout(Duration::from_secs(15), async {
        while let Some(result) = clients.join_next().await {
            result.expect("client task");
        }
        server.await.expect("server task");
    })
    .await
    .expect("one thousand concurrent streams exceeded the stability deadline");
}
