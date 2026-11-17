// SPDX-FileCopyrightText: MailCraft contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The older encryption against a server that offers only a CBC suite, TLS 1.2, as old servers do
//! (#1504). The server is OpenSSL, which is what the system's TLS is on Linux: rustls finds no
//! suite in common with it, and the system's TLS does, for an account whose owner allows it.
use std::sync::Arc;

use openssl::pkey::PKey;
use openssl::ssl::{SslAcceptor, SslMethod, SslVersion};
use openssl::x509::X509;

use crate::fake::{Fake, ImapWorld, MailIo};
use crate::test_account;
use crate::tls_test_support::{Authority, trusting};
use mailcraft_model::{Account, Security, Server};

const PASSWORD: &str = "invented-horse";

/// An IMAP server whose STARTTLS offers TLS 1.2 with `ECDHE-ECDSA-AES128-SHA` and nothing else,
/// with a certificate `authority` issued.
fn cbc_only(authority: &Authority) -> Fake<ImapWorld> {
    let (cert, key) = authority.identity(&["localhost", "127.0.0.1"]);
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    builder.set_min_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    builder.set_max_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    builder.set_cipher_list("ECDHE-ECDSA-AES128-SHA").unwrap();
    builder.set_certificate(&X509::from_der(&cert).unwrap()).unwrap();
    builder.add_extra_chain_cert(X509::from_der(authority.root().as_ref()).unwrap()).unwrap();
    builder.set_private_key(&PKey::private_key_from_der(&key).unwrap()).unwrap();
    let acceptor = Arc::new(builder.build());
    Fake::imap(ImapWorld {
        user: "ada".into(),
        password: PASSWORD.into(),
        plain: true,
        offer_starttls: true,
        starttls_upgrade: Some(Arc::new(move |stream: Box<dyn MailIo>| -> Box<dyn MailIo> {
            match acceptor.accept(stream) {
                Ok(tls) => Box::new(tls),
                // The client hung up: nothing more is said on this connection.
                Err(_) => Box::new(std::io::Cursor::new(Vec::new())),
            }
        })),
        ..Default::default()
    })
}

fn account(port: u16, legacy_tls: bool) -> Account {
    let incoming = Server { host: "127.0.0.1".into(), port, security: Security::StartTls };
    Account { email: "ada@example.org".into(), username: "ada".into(), incoming: Some(incoming), legacy_tls, ..Default::default() }
}

#[test]
fn an_account_that_allows_the_older_encryption_signs_in_to_a_cbc_only_server() {
    let authority = Authority::new("MailCraft Test Authority");
    let peer = cbc_only(&authority);
    trusting(vec![authority.root()], || {
        assert_eq!(test_account(&account(peer.port, true), PASSWORD), Ok(()));
    });
    let log = &peer.world().log;
    let second = log.iter().rposition(|s| s.contains(" STARTTLS")).unwrap();
    assert!(log.iter().skip(second).any(|s| s.contains(" AUTHENTICATE PLAIN")), "{log:?}");
}

#[test]
fn an_account_that_doesn_t_is_told_why_and_never_signs_in() {
    let authority = Authority::new("MailCraft Test Authority");
    let peer = cbc_only(&authority);
    let error = trusting(vec![authority.root()], || test_account(&account(peer.port, false), PASSWORD).unwrap_err());
    assert!(error.legacy_tls_would_help(), "{error:?}");
    assert!(!peer.world().log.iter().any(|s| s.contains(" AUTHENTICATE") || s.contains(" LOGIN ")));
}

#[test]
fn the_older_encryption_takes_only_a_certificate_the_system_trusts() {
    let authority = Authority::new("MailCraft Test Authority");
    let peer = cbc_only(&authority);
    let error = test_account(&account(peer.port, true), PASSWORD).unwrap_err();
    assert!(!error.legacy_tls_would_help(), "{error:?}");
    assert!(!peer.world().log.iter().any(|s| s.contains(" AUTHENTICATE") || s.contains(" LOGIN ")));
}
