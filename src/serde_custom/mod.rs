//! Custom serialization and deserialization modules
//!
//! In general, users should not need to invoke these manually. These are exposed for potential use
//! in your applications, should you wish to make extensions to the implementations provided.
pub mod byte_sequence;
pub mod option_byte_sequence;
pub mod base64_url_uint;
pub mod option_base64_url_uint;
#[macro_use]
pub mod flatten;
