//! JSON Web Signatures, including JWT signing and headers
//!
//! Defined in [RFC 7515](https://tools.ietf.org/html/rfc7515). For most common use,
//! you will want to look at the  [`Compact`](enum.Compact.html) enum.
mod compact;
mod flattened;

pub use compact::{Compact, Header, RegisteredHeader, Secret};
pub use flattened::{Signable, SignedData};
