//! Encryption and key derivation, built on `age` with a scrypt passphrase
//! recipient. Implemented in Phase 1 — this module intentionally contains no
//! hand-rolled cryptography, only calls into the audited `age` crate.
