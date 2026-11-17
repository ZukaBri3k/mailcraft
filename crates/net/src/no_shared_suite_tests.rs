// SPDX-FileCopyrightText: MailCraft contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! A handshake that fails for want of a cipher suite in common is known as such all the way to
//! the host, which may then offer the older encryption; any other failure is not. The servers
//! here answer the ClientHello with an alert and nothing else, as an old server that offers only
//! CBC suites does: no TLS library is needed to be one.
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::fake::{Fake, ImapWorld, MailIo};
use crate::{NetError, test_account};
use mailcraft_model::{Account, Security, Server};

const PASSWORD: &str = "invented-horse";
const HANDSHAKE_FAILURE: u8 = 40;
const INSUFFICIENT_SECURITY: u8 = 71;
const UNKNOWN_CA: u8 = 48;

/// Read the client's first record (its ClientHello), then answer with `alert`, or with nothing.
fn answer(stream: &mut dyn MailIo, alert: Option<u8>) {
    let mut header = [0u8; 5];
    if stream.read_exact(&mut header).is_err() {
        return;
    }
    let mut hello = vec![0u8; usize::from(u16::from_be_bytes([header[3], header[4]]))];
    let _ = stream.read_exact(&mut hello);
    if let Some(alert) = alert {
        // A fatal alert record, TLS 1.2.
        let _ = stream.write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, alert]);
        let _ = stream.flush();
    }
}

/// A server on this machine that answers every handshake as [`answer`] does.
fn refusing(alert: Option<u8>) -> u16 {
    counting(alert).0
}

/// [`refusing`], with how many connections it took (counted before it answers).
fn counting(alert: Option<u8>) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let taken = Arc::new(AtomicUsize::new(0));
    let count = taken.clone();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().take(4).flatten() {
            count.fetch_add(1, Ordering::SeqCst);
            answer(&mut stream, alert);
        }
    });
    (port, taken)
}

fn server(port: u16, security: Security) -> Server {
    Server { host: "127.0.0.1".into(), port, security }
}

fn account(incoming: Option<Server>, outgoing: Option<Server>) -> Account {
    Account { email: "ada@example.org".into(), username: "ada".into(), incoming, outgoing, ..Default::default() }
}

#[test]
fn an_imap_server_with_no_suite_in_common_is_known_as_such() {
    for alert in [HANDSHAKE_FAILURE, INSUFFICIENT_SECURITY] {
        let port = refusing(Some(alert));
        let error = test_account(&account(Some(server(port, Security::Tls)), None), PASSWORD).unwrap_err();
        assert!(error.legacy_tls_would_help(), "{error:?}");
        assert_eq!(
            error.to_string(),
            "couldn't make a secure connection to 127.0.0.1: the server and MailCraft found no encryption in common; often the server offers only older encryption (CBC suites) that MailCraft doesn't use, and its administrator can turn on the AES-GCM suites"
        );
    }
}

#[test]
fn an_smtp_server_with_no_suite_in_common_is_known_as_such() {
    let port = refusing(Some(HANDSHAKE_FAILURE));
    let error = test_account(&account(None, Some(server(port, Security::Tls))), PASSWORD).unwrap_err();
    assert!(error.legacy_tls_would_help(), "{error:?}");
}

#[test]
fn starttls_with_no_suite_in_common_is_known_as_such() {
    let peer = Fake::imap(ImapWorld {
        user: "ada".into(),
        password: PASSWORD.into(),
        offer_starttls: true,
        starttls_upgrade: Some(Arc::new(|mut stream: Box<dyn MailIo>| -> Box<dyn MailIo> {
            answer(&mut *stream, Some(HANDSHAKE_FAILURE));
            stream
        })),
        ..Default::default()
    });
    let error = test_account(&account(Some(server(peer.port, Security::StartTls)), None), PASSWORD).unwrap_err();
    assert!(error.legacy_tls_would_help(), "{error:?}");
}

#[test]
fn other_failures_are_not_taken_for_missing_suites() {
    // The server refuses the client's certificate authorities, or hangs up.
    for alert in [Some(UNKNOWN_CA), None] {
        let port = refusing(alert);
        let error = test_account(&account(Some(server(port, Security::Tls)), None), PASSWORD).unwrap_err();
        assert!(matches!(error, NetError::Tls { .. }), "{error:?}");
        assert!(!error.legacy_tls_would_help(), "{error:?}");
    }
    // A server that doesn't offer STARTTLS.
    let peer = Fake::imap(ImapWorld { user: "ada".into(), password: PASSWORD.into(), ..Default::default() });
    let error = test_account(&account(Some(server(peer.port, Security::StartTls)), None), PASSWORD).unwrap_err();
    assert!(matches!(error, NetError::Tls { .. }), "{error:?}");
    assert!(!error.legacy_tls_would_help(), "{error:?}");
    // Nobody there at all.
    let closed = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let error = test_account(&account(Some(server(closed, Security::Tls)), None), PASSWORD).unwrap_err();
    assert!(!error.legacy_tls_would_help(), "{error:?}");
}

#[test]
fn the_password_is_blanked_without_losing_the_kind_of_failure() {
    let error = NetError::Tls { host: "127.0.0.1".into(), reason: format!("said {PASSWORD}").into(), no_shared_suite: true };
    let clean = error.without(PASSWORD);
    assert!(clean.legacy_tls_would_help());
    assert!(!clean.to_string().contains(PASSWORD));
}

#[test]
fn the_older_encryption_is_tried_only_where_the_owner_allows_it() {
    // A second handshake, with the system's TLS, in a build that has it; the server refuses that
    // one too, and the error is the system's, not one that asks for the older encryption again.
    for (incoming, service) in [(true, "imap"), (false, "smtp")] {
        let (port, taken) = counting(Some(HANDSHAKE_FAILURE));
        let tls = Some(server(port, Security::Tls));
        let allowed = Account { legacy_tls: true, ..if incoming { account(tls, None) } else { account(None, tls) } };
        let error = test_account(&allowed, PASSWORD).unwrap_err();
        assert!(matches!(error, NetError::Tls { .. }), "{service}: {error:?}");
        if crate::transport::SYSTEM_TLS {
            assert_eq!(taken.load(Ordering::SeqCst), 2, "{service}");
            assert!(!error.legacy_tls_would_help(), "{service}: {error:?}");
        } else {
            assert_eq!(taken.load(Ordering::SeqCst), 1, "{service}");
        }
    }
    // Not allowed: one handshake.
    let (port, taken) = counting(Some(HANDSHAKE_FAILURE));
    let error = test_account(&account(Some(server(port, Security::Tls)), None), PASSWORD).unwrap_err();
    assert!(error.legacy_tls_would_help(), "{error:?}");
    assert_eq!(taken.load(Ordering::SeqCst), 1);
}

#[test]
fn any_other_failure_is_never_tried_again_with_the_older_encryption() {
    for alert in [Some(UNKNOWN_CA), None] {
        let (port, taken) = counting(alert);
        let allowed = Account { legacy_tls: true, ..account(Some(server(port, Security::Tls)), None) };
        assert!(test_account(&allowed, PASSWORD).is_err());
        assert_eq!(taken.load(Ordering::SeqCst), 1, "{alert:?}");
    }
}

#[test]
fn starttls_is_asked_again_before_the_older_encryption() {
    let peer = Fake::imap(ImapWorld {
        user: "ada".into(),
        password: PASSWORD.into(),
        offer_starttls: true,
        starttls_upgrade: Some(Arc::new(|mut stream: Box<dyn MailIo>| -> Box<dyn MailIo> {
            answer(&mut *stream, Some(HANDSHAKE_FAILURE));
            stream
        })),
        ..Default::default()
    });
    let allowed = Account { legacy_tls: true, ..account(Some(server(peer.port, Security::StartTls)), None) };
    assert!(test_account(&allowed, PASSWORD).is_err());
    let asked = peer.world().log.iter().filter(|line| line.contains(" STARTTLS")).count();
    assert_eq!(asked, if crate::transport::SYSTEM_TLS { 2 } else { 1 });
}
