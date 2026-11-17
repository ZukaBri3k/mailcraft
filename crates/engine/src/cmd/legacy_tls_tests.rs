// SPDX-FileCopyrightText: MailCraft contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! #1504: an account whose mail servers offer only older encryption (CBC suites) may be allowed
//! it, from the CLI and the window. Kept through a save and a load; off where there are no mail
//! servers.

use mailcraft_model::{Account, Mailbox};
use serde_json::{Value, json};

use crate::Session;

fn session() -> Session {
    Session::new(Mailbox::with_local_account("Ada Lovelace", "ada@example.org"))
}

fn refusal(s: &mut Session, id: &str, params: Value) -> String {
    match s.run(id, &params) {
        Err(e) => e.to_string(),
        Ok(answer) => panic!("{id} {params} wasn't refused: {answer}"),
    }
}

/// The account `id` as the mailbox file has it after a save and a load.
fn reloaded(s: &Session, id: u64) -> Account {
    let file = crate::io::write_mailbox(&s.mailbox).unwrap();
    crate::io::read_mailbox(&file).unwrap().accounts.into_iter().find(|a| a.id == id).unwrap()
}

fn listed(s: &mut Session, id: u64) -> Value {
    let listed = s.run("account.list", &json!({})).unwrap();
    listed.as_array().or_else(|| listed["accounts"].as_array()).unwrap().iter().find(|a| a["id"] == id).unwrap().clone()
}

#[test]
fn the_older_encryption_is_a_choice_kept_with_the_account() {
    let mut s = session();
    let old =
        json!({"email": "ada@old.example", "incoming": {"host": "imap.old.example"}, "outgoing": {"host": "smtp.old.example"}, "legacyTls": true});
    let id = s.run("account.add", &old).unwrap()["id"].as_u64().unwrap();
    assert!(reloaded(&s, id).legacy_tls);
    assert_eq!(listed(&mut s, id)["legacyTls"], true);

    s.run("account.edit", &json!({"id": id, "legacyTls": false})).unwrap();
    assert!(!reloaded(&s, id).legacy_tls);
    assert_eq!(listed(&mut s, id)["legacyTls"], false);
    assert!(refusal(&mut s, "account.edit", json!({"id": id, "legacyTls": "yes"})).contains("true or false"));
    assert!(!s.mailbox.account(id).unwrap().legacy_tls);

    // An edit that doesn't name it leaves it as it was.
    s.run("account.edit", &json!({"id": id, "legacyTls": true})).unwrap();
    s.run("account.edit", &json!({"id": id, "displayName": "Ada"})).unwrap();
    assert!(s.mailbox.account(id).unwrap().legacy_tls);
}

#[test]
fn an_account_without_mail_servers_has_no_older_encryption() {
    let mut s = session();
    let id = s.run("account.add", &json!({"email": "ada@here.example", "legacyTls": true})).unwrap()["id"].as_u64().unwrap();
    assert!(!s.mailbox.account(id).unwrap().legacy_tls);
    let old = json!({"email": "ada@old.example", "incoming": {"host": "imap.old.example"}, "legacyTls": true});
    let id = s.run("account.add", &old).unwrap()["id"].as_u64().unwrap();
    s.run("account.edit", &json!({"id": id, "incoming": null})).unwrap();
    assert!(!s.mailbox.account(id).unwrap().legacy_tls);
}

#[test]
fn a_mailbox_from_before_has_it_off_and_a_file_that_is_off_says_nothing() {
    let account: Account = serde_json::from_value(json!({"email": "ada@example.org"})).unwrap();
    assert!(!account.legacy_tls);
    let account: Account = serde_json::from_value(json!({"email": "ada@example.org", "legacyTls": "garbage"})).unwrap();
    assert!(!account.legacy_tls);
    assert!(serde_json::to_value(&account).unwrap().get("legacyTls").is_none());
}

/// The account `account.add` makes from `params`, as the owner.
fn added(s: &mut Session, params: Value) -> u64 {
    s.run("account.add", &params).unwrap()["id"].as_u64().unwrap()
}

fn old_servers(legacy: bool) -> Value {
    json!({"email": "ada@old.example", "incoming": {"host": "imap.old.example"}, "outgoing": {"host": "smtp.old.example"}, "legacyTls": legacy})
}

#[test]
fn an_agent_is_refused_turning_on_the_older_encryption_even_when_allowed_everything() {
    use crate::agent::{Access, Class, Verdict, check};
    let mut s = session();
    let id = added(&mut s, old_servers(false));
    for (command, params) in [("account.edit", json!({"id": id, "legacyTls": true})), ("account.add", old_servers(true))] {
        let Verdict::Refuse(why) = check(&s, command, &params, &Class::ALL) else { panic!("{command} {params} wasn't refused") };
        assert!(why.contains("only the owner"), "{why}");
    }
    assert!(matches!(check(&s, "account.edit", &json!({"id": id, "legacyTls": false}), &Class::ALL), Verdict::Run));
    assert_eq!(crate::agent::access("ui.allowLegacyTls"), Some(Access::Never));
}

#[test]
fn whatever_path_an_agent_takes_the_older_encryption_stays_off() {
    let mut s = session();
    let id = added(&mut s, old_servers(false));
    // Past the gate, by the command itself.
    s.agent = Some(crate::agent::Class::ALL.to_vec());
    assert!(refusal(&mut s, "account.edit", json!({"id": id, "legacyTls": true})).contains("only the owner"));
    assert!(!s.mailbox.account(id).unwrap().legacy_tls);
    s.agent = None;
    // The owner turns it on, then off; an agent's undo would turn it on again.
    s.run("account.edit", &json!({"id": id, "legacyTls": true})).unwrap();
    s.run("account.edit", &json!({"id": id, "legacyTls": false})).unwrap();
    s.agent = Some(crate::agent::Class::ALL.to_vec());
    assert!(refusal(&mut s, "edit.undo", json!({})).contains("only the owner"));
    assert!(!s.mailbox.account(id).unwrap().legacy_tls);
    // Turning it off is an agent's to do.
    s.agent = None;
    s.run("account.edit", &json!({"id": id, "legacyTls": true})).unwrap();
    s.agent = Some(vec![crate::agent::Class::Accounts]);
    s.run("account.edit", &json!({"id": id, "legacyTls": false})).unwrap();
    assert!(!s.mailbox.account(id).unwrap().legacy_tls);
}
