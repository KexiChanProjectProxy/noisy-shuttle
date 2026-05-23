mod helpers;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[tokio::test]
async fn echo_target_one_shot() {
    let (target, addr) = helpers::EchoTarget::new().await.unwrap();
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(b"hello-echo").await.unwrap();
    let mut buf = [0u8; 10];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf[..10], b"hello-echo");
    drop(target);
}

#[tokio::test]
async fn shuttle_server_client_require_library_access() {
    let result = helpers::TestShuttleServer::new().await;
    assert!(
        result.is_err(),
        "TestShuttleServer requires library access - shuttle is binary crate"
    );

    let dummy_addr = "127.0.0.1:12345".parse().unwrap();
    let result = helpers::TestShuttleClient::new(dummy_addr).await;
    assert!(
        result.is_err(),
        "TestShuttleClient requires library access - shuttle is binary crate"
    );
}
