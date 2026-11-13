//! Zabbix-style fleet mode: agents on monitored servers push to a central server;
//! a console UI reads the server's database.

pub mod agent;
pub mod auth;
pub mod db;
pub mod pki;
pub mod proto;
pub mod server;
pub mod tui;
pub mod up;
pub mod users;
pub mod util;
pub mod web;
pub mod webhook;
