use super::*;
use sloggers::terminal::{Destination, TerminalLoggerBuilder};
use sloggers::types::Severity;
use sloggers::Build;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[tokio::test]
async fn expired_token() {
    let mut mock = MockServerHandlerIOTrait::new();

    // No command should run
    mock.expect_run().never();

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

    let mut builder = TerminalLoggerBuilder::new();
    builder.level(Severity::Critical);
    builder.destination(Destination::Stderr);
    let logger = builder.build().unwrap();

    let config = ServerConfig {
        bind: String::from(""),
        hmac_secret: String::from("test_secret_test_test"),
        command_open: String::from(""),
        command_close: String::from(""),
        open_timeout: 0,
        max_time_skew: 2.0, // max allowed, client will send 5 behind
    };

    // Time 5 seconds in the past - server only allows 2 seconds
    let now_bytes: [u8; 8] = (time() - 5.0).to_le_bytes();
    let mut message = [0; 40];

    // Sign message correctly
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(&config.hmac_secret.as_bytes()).unwrap();
    mac.update(&now_bytes);
    let hmac_bytes: [u8; 32] = mac.finalize().into_bytes().into();

    now_bytes.iter().enumerate().for_each(|(i, b)| {
        message[i] = *b;
    });
    hmac_bytes.iter().enumerate().for_each(|(i, b)| {
        message[i + 8] = *b;
    });

    match handler_inner(&mock, message, addr, &logger, config).await {
        Err(HandlerError::TokenExpired(_)) => (),
        Err(e) => panic!("Unexpected Err returned {:?}", e),
        Ok(()) => panic!("Unexpected Ok returned"),
    }
}

#[tokio::test]
async fn invalid_mac() {
    let mut mock = MockServerHandlerIOTrait::new();

    // No command should run
    mock.expect_run().never();

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

    let mut builder = TerminalLoggerBuilder::new();
    builder.level(Severity::Critical);
    builder.destination(Destination::Stderr);
    let logger = builder.build().unwrap();

    let config = ServerConfig {
        bind: String::from(""),
        hmac_secret: String::from("test_secret_test_test"),
        command_open: String::from(""),
        command_close: String::from(""),
        open_timeout: 0,
        max_time_skew: 2.0,
    };

    // Send correct time
    let now_bytes: [u8; 8] = time().to_le_bytes();
    let mut message = [0; 40];

    // Sign message with a different secret
    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        HmacSha256::new_from_slice(String::from("a different secret").as_bytes()).unwrap();
    mac.update(&now_bytes);
    let hmac_bytes: [u8; 32] = mac.finalize().into_bytes().into();

    now_bytes.iter().enumerate().for_each(|(i, b)| {
        message[i] = *b;
    });
    hmac_bytes.iter().enumerate().for_each(|(i, b)| {
        message[i + 8] = *b;
    });

    match handler_inner(&mock, message, addr, &logger, config).await {
        Err(HandlerError::InvalidMac(_)) => (),
        Err(e) => panic!("Unexpected Err returned {:?}", e),
        Ok(()) => panic!("Unexpected Ok returned"),
    }
}

#[tokio::test]
async fn valid_run() {
    let mut mock = MockServerHandlerIOTrait::new();

    // run() should be called twice
    mock.expect_run().times(2).return_const(Ok(()));

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

    let mut builder = TerminalLoggerBuilder::new();
    builder.level(Severity::Critical);
    builder.destination(Destination::Stderr);
    let logger = builder.build().unwrap();

    let config = ServerConfig {
        bind: String::from(""),
        hmac_secret: String::from("test_secret_test_test"),
        command_open: String::from(""),
        command_close: String::from(""),
        open_timeout: 0,
        max_time_skew: 2.0,
    };

    // Send correct time, but do not sign anything
    let now_bytes: [u8; 8] = time().to_le_bytes();
    let mut message = [0; 40];

    // Sign message correctly
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(&config.hmac_secret.as_bytes()).unwrap();
    mac.update(&now_bytes);
    let hmac_bytes: [u8; 32] = mac.finalize().into_bytes().into();

    now_bytes.iter().enumerate().for_each(|(i, b)| {
        message[i] = *b;
    });
    hmac_bytes.iter().enumerate().for_each(|(i, b)| {
        message[i + 8] = *b;
    });

    assert!(handler_inner(&mock, message, addr, &logger, config)
        .await
        .is_ok());
}

#[tokio::test]
async fn command_error() {
    let mut mock = MockServerHandlerIOTrait::new();

    // run() should be called once and return an error
    mock.expect_run().once().return_const(Err(()));

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

    let mut builder = TerminalLoggerBuilder::new();
    builder.level(Severity::Critical);
    builder.destination(Destination::Stderr);
    let logger = builder.build().unwrap();

    let config = ServerConfig {
        bind: String::from(""),
        hmac_secret: String::from("test_secret_test_test"),
        command_open: String::from(""),
        command_close: String::from(""),
        open_timeout: 0,
        max_time_skew: 2.0,
    };

    // Send correct time, but do not sign anything
    let now_bytes: [u8; 8] = time().to_le_bytes();
    let mut message = [0; 40];

    // Sign message correctly
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(&config.hmac_secret.as_bytes()).unwrap();
    mac.update(&now_bytes);
    let hmac_bytes: [u8; 32] = mac.finalize().into_bytes().into();

    now_bytes.iter().enumerate().for_each(|(i, b)| {
        message[i] = *b;
    });
    hmac_bytes.iter().enumerate().for_each(|(i, b)| {
        message[i + 8] = *b;
    });

    match handler_inner(&mock, message, addr, &logger, config).await {
        Err(HandlerError::CommandOpenFailed) => (),
        Err(e) => panic!("Unexpected Err returned {:?}", e),
        Ok(()) => panic!("Unexpected Ok returned"),
    }
}
