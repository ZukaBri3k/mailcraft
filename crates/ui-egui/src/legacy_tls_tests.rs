// SPDX-FileCopyrightText: MailCraft contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The older encryption for an account's mail servers (#1504) is the owner's to allow, from the
//! window: an agent's call is refused, however much it was allowed.

use std::sync::mpsc::Receiver;

use mailcraft_engine::Session;
use mailcraft_engine::agent::Class;
use mailcraft_model::Mailbox;
use serde_json::{Value, json};

use crate::control::{ControlRequest, Outcome};
use crate::{MailApp, Services};

fn app() -> MailApp {
    let mut a = MailApp::new(Session::new(Mailbox::with_local_account("Ada Lovelace", "ada@example.org")), Services::default());
    a.autosave = false;
    a
}

/// `command` sent by an agent that was allowed everything: its answer, when it has one.
fn agent(a: &mut MailApp, command: &str, params: Value) -> (Outcome, Receiver<Value>) {
    let (req, rx) = ControlRequest::new("engine.execute", json!({"command": command, "params": params}));
    (crate::control::handle(a, &egui::Context::default(), &req.from_agent(Class::ALL.to_vec())), rx)
}

fn with_servers(a: &mut MailApp) -> u64 {
    let params = json!({"email": "ada@old.example", "incoming": {"host": "imap.old.example"}, "outgoing": {"host": "smtp.old.example"}});
    a.run("account.add", params).unwrap()["id"].as_u64().unwrap()
}

#[test]
fn the_owner_allows_the_older_encryption_for_an_account_with_mail_servers() {
    let mut a = app();
    let id = with_servers(&mut a);
    assert!(a.run("ui.allowLegacyTls", json!({"account": id})).is_err());
    assert!(!a.session.mailbox.account(id).unwrap().legacy_tls);
    a.run("ui.allowLegacyTls", json!({"account": id, "confirmed": true})).unwrap();
    assert!(a.session.mailbox.account(id).unwrap().legacy_tls);
    let local = a.session.mailbox.accounts.iter().find(|x| x.incoming.is_none()).unwrap().id;
    assert!(a.run("ui.allowLegacyTls", json!({"account": local, "confirmed": true})).is_err());
    assert!(a.run("ui.allowLegacyTls", json!({"account": 9_999, "confirmed": true})).is_err());
}

#[test]
fn an_agent_never_allows_it_and_may_take_it_back() {
    let mut a = app();
    let id = with_servers(&mut a);
    for (command, params) in
        [("ui.allowLegacyTls", json!({"account": id, "confirmed": true})), ("account.edit", json!({"id": id, "legacyTls": true}))]
    {
        let (Outcome::Done(answer), _rx) = agent(&mut a, command, params) else { panic!("the owner was asked about {command}") };
        assert_eq!(answer["ok"], false, "{command}: {answer}");
        assert!(!a.session.mailbox.account(id).unwrap().legacy_tls, "{command}");
    }
    a.run("ui.allowLegacyTls", json!({"account": id, "confirmed": true})).unwrap();
    let (Outcome::Done(answer), _rx) = agent(&mut a, "account.edit", json!({"id": id, "legacyTls": false})) else { panic!("asked") };
    assert_ne!(answer["ok"], false, "{answer}");
    assert!(!a.session.mailbox.account(id).unwrap().legacy_tls);
}
