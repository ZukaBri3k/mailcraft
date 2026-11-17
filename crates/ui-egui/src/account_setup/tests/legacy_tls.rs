// SPDX-FileCopyrightText: MailCraft contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! #1504: servers that offer only older encryption (CBC suites). Add Account offers to connect
//! with it when the check says so, in a build that has it; Account Settings shows it and takes it
//! back.

use super::*;

/// A mail exchanger that is nobody's this program knows.
const HOSTED_MX: &str = "mx.hosted.example";

/// A host whose servers share no cipher suite with MailCraft's own encryption (or fail as
/// `no_shared_suite` says), and take the older encryption. The log is each account it was handed.
fn old_servers(app: &mut MailApp, no_shared_suite: bool) -> Log<Account> {
    let asked: Log<Account> = Default::default();
    let log = asked.clone();
    app.services.test_account = Some(Box::new(move |account: Account, _secret| {
        let (tx, rx) = mpsc::channel();
        let answer = if account.legacy_tls {
            Ok(())
        } else {
            Err(AccountCheckFailure { said: mailcraft_i18n::Text::verbatim("no encryption in common"), no_shared_suite })
        };
        log.lock().unwrap().push(account);
        tx.send(answer).unwrap();
        rx
    }));
    asked
}

/// Add Account for an address at a hosted domain, its password typed and Connect pressed.
fn refused(older: bool, no_shared_suite: bool) -> (Harness<'static, MailApp>, Log<Account>) {
    let mut a = app(false);
    a.services.legacy_tls = older;
    lookups(&mut a, Some(Ok(vec![HOSTED_MX])));
    let asked = old_servers(&mut a, no_shared_suite);
    let mut h = open(a, json!({}));
    connect(&mut h, "noor@lumen.example");
    assert_eq!(page(&h), Some(Page::Password));
    type_password(&mut h);
    press(&mut h, Key::Enter);
    h.run_steps(5);
    assert_eq!(page(&h), Some(Page::Password));
    (h, asked)
}

const OFFER: &str = "Connect with older encryption";

#[test]
fn a_server_with_only_older_encryption_can_be_connected_to_with_it() {
    let (mut h, asked) = refused(true, true);
    assert!(says(&h, "offers only older encryption"));
    assert!(!wizard(&h).unwrap().legacy_tls);
    click(&mut h, OFFER);
    h.run_steps(5);
    let asked = asked.lock().unwrap();
    assert_eq!(asked.iter().map(|a| a.legacy_tls).collect::<Vec<_>>(), [false, true]);
    let added = h.state().session.mailbox.accounts.iter().find(|a| a.email == "noor@lumen.example").unwrap();
    assert!(added.legacy_tls);
}

#[test]
fn nothing_is_offered_for_another_failure_or_in_a_build_without_it() {
    for (older, no_shared_suite) in [(true, false), (false, true)] {
        let (h, asked) = refused(older, no_shared_suite);
        assert!(h.query_by_label(OFFER).is_none(), "{older} {no_shared_suite}");
        assert!(says(&h, "no encryption in common"));
        assert_eq!(asked.lock().unwrap().len(), 1);
        assert!(!h.state().session.mailbox.accounts.iter().any(|a| a.email == "noor@lumen.example"));
    }
}

/// Account Settings for an IMAP account, in a build that has the older encryption or not.
fn settings(older: bool, legacy: bool) -> (Harness<'static, MailApp>, Id) {
    let mut a = app(true);
    a.services.legacy_tls = older;
    let params = json!({"email": "noor@lumen.example", "incoming": {"host": "imap.lumen.example"}, "outgoing": {"host": "smtp.lumen.example"}, "legacyTls": legacy});
    let id = a.execute("account.add", params).unwrap()["id"].as_u64().unwrap();
    (open(a, json!({"id": id})), id)
}

const TICK: &str = "Allow older encryption if the servers need it";

#[test]
fn account_settings_show_the_older_encryption_and_take_it_back() {
    let (mut h, id) = settings(true, false);
    h.get_by_label(TICK).click();
    h.run();
    assert_eq!(wizard(&h).unwrap().edit_command(), Some(("account.edit", json!({"id": id, "legacyTls": true}))));
    assert!(says(&h, "Less safe"));

    let (mut h, id) = settings(true, true);
    assert!(wizard(&h).unwrap().legacy_tls);
    h.get_by_label(TICK).click();
    h.run();
    assert_eq!(wizard(&h).unwrap().edit_command(), Some(("account.edit", json!({"id": id, "legacyTls": false}))));
    click(&mut h, "Save");
    assert!(!h.state().session.mailbox.account(id).unwrap().legacy_tls);
}

#[test]
fn a_build_without_it_never_turns_it_on_but_still_takes_it_back() {
    let (mut h, _) = settings(false, false);
    h.get_by_label(TICK).click();
    h.run();
    assert!(!wizard(&h).unwrap().legacy_tls);
    assert!(wizard(&h).unwrap().edit_command().is_none());

    let (mut h, id) = settings(false, true);
    h.get_by_label(TICK).click();
    h.run();
    assert_eq!(wizard(&h).unwrap().edit_command(), Some(("account.edit", json!({"id": id, "legacyTls": false}))));
}
