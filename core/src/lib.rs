//! VibeFTP's engine: protocols, connection pools, transfers, edit copies, sites and pins.
//! It knows nothing about the UI; the program around it implements `Host`.

pub mod error;
pub mod host;
pub mod identity;
pub mod logger;
pub mod ops;
pub mod protocol;
pub mod session;
pub mod store;
pub mod types;

pub use host::{Event, Host, Paths};
pub use ops::Core;
