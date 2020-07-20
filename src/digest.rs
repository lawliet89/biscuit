//! Secure cryptographic digests
//!
//! Currently used by JWK thumbprints.
//! This simply wraps the ring::digest module, while providing forward compatibility
//! should the implementation change.

/// A digest algorithm
pub struct Algorithm(pub(crate) &'static ring::digest::Algorithm);

// SHA-1 as specified in FIPS 180-4. Deprecated.
// SHA-1 is not exposed at the moment, as the only user is JWK thumbprints,
// which postdate SHA-1 deprecation and don't have a backwards-compatibility reason to use it.
//pub static SHA1_FOR_LEGACY_USE_ONLY: Algorithm = Algorithm(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);

/// SHA-256 as specified in FIPS 180-4.
pub static SHA256: Algorithm = Algorithm(&ring::digest::SHA256);

/// SHA-384 as specified in FIPS 180-4.
pub static SHA384: Algorithm = Algorithm(&ring::digest::SHA384);

/// SHA-512 as specified in FIPS 180-4.
pub static SHA512: Algorithm = Algorithm(&ring::digest::SHA512);

/// SHA-512/256 as specified in FIPS 180-4.
pub static SHA512_256: Algorithm = Algorithm(&ring::digest::SHA512_256);
