// SPDX-FileCopyrightText: MailCraft contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The older encryption (#1504): the system's own TLS (Security.framework on macOS and iOS,
//! SChannel on Windows, OpenSSL on Linux and FreeBSD), for a mail server that shares no cipher
//! suite with rustls, which has only the AEAD ones; most often an old server that offers only CBC
//! suites.
//!
//! It is used only for an account whose owner allows it, and only after rustls found no suite in
//! common with that server (`transport::older`). TLS 1.2 at least; the suites are the system's;
//! the certificate must be one the system trusts and be for the server's name, with no
//! fingerprint trusted besides. The handshake has the same time limit as rustls's.

use std::net::TcpStream;
use std::time::{Duration, Instant};

use native_tls::{HandshakeError, Protocol, TlsConnector, TlsStream};

use crate::NetError;
use mailcraft_i18n::{Text, said};

/// Shake hands over `tcp` with the system's TLS, and check the server's certificate against
/// `host`: within `handshake`, each wait no longer than `io`, which every read and write waits
/// afterwards.
pub(crate) fn secure(tcp: TcpStream, host: &str, io: Duration, handshake: Duration) -> Result<TlsStream<TcpStream>, NetError> {
    let failed = |reason: Text| NetError::tls(host, reason);
    let waits = |tcp: &TcpStream, wait: Duration| {
        let wait = Some(wait.max(Duration::from_millis(1)));
        tcp.set_read_timeout(wait).and_then(|()| tcp.set_write_timeout(wait)).map_err(|_| failed(said!("the connection couldn't be set up")))
    };
    let connector = connector().map_err(|e| failed(system_words(&e)))?;
    let deadline = Instant::now() + handshake;
    waits(&tcp, io.min(handshake))?;
    let mut attempt = connector.connect(host, tcp);
    loop {
        match attempt {
            Ok(stream) => {
                waits(stream.get_ref(), io)?;
                return Ok(stream);
            }
            Err(HandshakeError::Failure(e)) => return Err(failed(system_words(&e))),
            // A wait ran out with the handshake under way: on with it while there is time left.
            Err(HandshakeError::WouldBlock(midway)) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(failed(said!("the server took too long")));
                }
                waits(midway.get_ref(), io.min(left))?;
                attempt = midway.handshake();
            }
        }
    }
}

/// The system's TLS, TLS 1.2 at least (and a test's own certificate authority besides the
/// system's, in a test).
fn connector() -> Result<TlsConnector, native_tls::Error> {
    let mut builder = TlsConnector::builder();
    builder.min_protocol_version(Some(Protocol::Tlsv12));
    #[cfg(test)]
    for root in crate::tls_test_support::trusted_roots().unwrap_or_default() {
        builder.add_root_certificate(native_tls::Certificate::from_der(root.as_ref())?);
    }
    builder.build()
}

/// What the system said, as it said it, without control characters and not too long.
fn system_words(e: &native_tls::Error) -> Text {
    Text::verbatim(e.to_string().chars().filter(|c| !c.is_control()).take(200).collect::<String>())
}
