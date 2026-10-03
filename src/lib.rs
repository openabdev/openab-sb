//! OpenAB Switchboard: relays MCP tool calls from OpenAB Connect and openab-pty
//! sessions to a machine that can only dial out. See `README.md` for the shape
//! and `docs/SOUTHBOUND-CONTRACT.md` for the dialling side.

pub mod audit;
pub mod auth;
pub mod config;
pub mod hub;
pub mod mcp;
pub mod pty;
pub mod server;

pub use server::App;
