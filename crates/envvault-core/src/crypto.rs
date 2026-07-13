//! Encryption and key derivation, built entirely on the audited `age` crate.
//! Nothing in this module invents cryptography: no raw AES, no manual nonces,
//! no hand-rolled KDF parameters.
//!
//! ## Design
//!
//! The age format forbids combining a passphrase (scrypt) recipient with any
//! other recipient in one file (`EncryptError::MixedRecipientAndPassphrase`),
//! so "master password + recovery key" cannot be two recipients of the same
//! blob. Instead we use the standard envelope construction:
//!
//! 1. At vault creation, generate a random X25519 **vault identity**.
//! 2. The vault payload is age-encrypted to the vault identity's public key
//!    (and, if enabled, to the recovery key's public key).
//! 3. The vault identity itself is age-encrypted with an **scrypt passphrase
//!    recipient** derived from the master password, and stored beside the
//!    payload.
//!
//! Unlock = scrypt-unwrap the identity (this is the deliberate ~500ms–1s
//! cost), then decrypt the payload. The recovery key is a standard
//! `AGE-SECRET-KEY-1…` string, so the payload can also be decrypted with the
//! stock `age` CLI — the anti-lock-in property, proven by a test.

use std::io::{Read, Write};
use std::iter;

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::secrecy::{ExposeSecret, SecretString};
use age::x25519;
use age::{DecryptError, Decryptor, Encryptor};
use zeroize::Zeroizing;

/// log2(N) for the scrypt KDF wrapping the vault identity. 2^18 is the spec
/// minimum and lands in the required 500ms–1s unlock window on a modern
/// laptop (measured by `measure_unlock_time` in the crypto tests).
pub const SCRYPT_WORK_FACTOR_LOG_N: u8 = 18;

/// Cap accepted work factors when unwrapping, so a malicious vault file
/// cannot DoS the app with an absurd KDF cost.
const MAX_ACCEPTED_WORK_FACTOR_LOG_N: u8 = 22;

/// Errors internal to the crypto layer. `vault.rs` maps these onto
/// [`crate::CoreError`] with file-path context attached.
#[derive(Debug)]
pub enum CryptoError {
    /// The passphrase failed to unwrap the vault identity. With an AEAD this
    /// is cryptographically indistinguishable from a tampered wrapped-key
    /// blob; we fail closed and report it as a wrong password.
    WrongPassphrase,
    /// The ciphertext is not valid age data or failed authentication.
    Corrupted(String),
    Io(std::io::Error),
}

impl From<std::io::Error> for CryptoError {
    fn from(e: std::io::Error) -> Self {
        CryptoError::Io(e)
    }
}

/// Generate a fresh X25519 identity (vault identity or recovery key).
pub fn generate_identity() -> x25519::Identity {
    x25519::Identity::generate()
}

/// Encrypt the vault identity under the master password (age + scrypt).
/// Returns an ASCII-armored age file as a string.
pub fn wrap_identity(
    identity: &x25519::Identity,
    passphrase: &SecretString,
    work_factor_log_n: u8,
) -> Result<String, CryptoError> {
    let mut recipient = age::scrypt::Recipient::new(passphrase.clone());
    recipient.set_work_factor(work_factor_log_n);

    let plaintext = Zeroizing::new(identity.to_string().expose_secret().as_bytes().to_vec());
    encrypt_armored(&plaintext, iter::once(&recipient as &dyn age::Recipient))
}

/// Decrypt the wrapped vault identity with the master password.
pub fn unwrap_identity(
    armored: &str,
    passphrase: &SecretString,
) -> Result<x25519::Identity, CryptoError> {
    let mut scrypt_id = age::scrypt::Identity::new(passphrase.clone());
    scrypt_id.set_max_work_factor(MAX_ACCEPTED_WORK_FACTOR_LOG_N);

    let bytes = decrypt_armored(armored, &scrypt_id).map_err(|e| match e {
        // Wrong passphrase and tampered-ciphertext are indistinguishable by
        // design; fail closed as WrongPassphrase (never partial plaintext).
        CryptoError::Corrupted(reason)
            if reason.contains("decryption failed") || reason.contains("no matching keys") =>
        {
            CryptoError::WrongPassphrase
        }
        other => other,
    })?;

    let text = Zeroizing::new(
        String::from_utf8(bytes.to_vec())
            .map_err(|_| CryptoError::Corrupted("wrapped identity is not UTF-8".into()))?,
    );
    text.trim()
        .parse::<x25519::Identity>()
        .map_err(|e| CryptoError::Corrupted(format!("wrapped identity invalid: {e}")))
}

/// Encrypt the serialized vault payload to one or more X25519 recipients.
pub fn encrypt_payload(
    plaintext: &[u8],
    recipients: &[&x25519::Recipient],
) -> Result<String, CryptoError> {
    encrypt_armored(
        plaintext,
        recipients.iter().map(|r| *r as &dyn age::Recipient),
    )
}

/// Decrypt the vault payload with the unwrapped vault identity (or the
/// recovery key). The returned buffer is zeroized on drop.
pub fn decrypt_payload(
    armored: &str,
    identity: &x25519::Identity,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    decrypt_armored(armored, identity)
}

fn encrypt_armored<'a>(
    plaintext: &[u8],
    recipients: impl Iterator<Item = &'a dyn age::Recipient>,
) -> Result<String, CryptoError> {
    let encryptor = Encryptor::with_recipients(recipients)
        .map_err(|e| CryptoError::Corrupted(format!("encryption setup failed: {e}")))?;

    let armor = ArmoredWriter::wrap_output(Vec::new(), Format::AsciiArmor)?;
    let mut writer = encryptor
        .wrap_output(armor)
        .map_err(|e| CryptoError::Corrupted(format!("encryption failed: {e}")))?;
    writer.write_all(plaintext)?;
    let armor = writer.finish()?;
    let bytes = armor.finish()?;

    String::from_utf8(bytes).map_err(|_| CryptoError::Corrupted("armor is not UTF-8".into()))
}

fn decrypt_armored(
    armored: &str,
    identity: &dyn age::Identity,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let decryptor =
        Decryptor::new_buffered(ArmoredReader::new(armored.as_bytes())).map_err(map_decrypt)?;
    let mut reader = decryptor
        .decrypt(iter::once(identity))
        .map_err(map_decrypt)?;

    let mut plaintext = Zeroizing::new(Vec::new());
    reader.read_to_end(&mut plaintext).map_err(|e| {
        // A bad auth tag surfaces as an io error during streaming; treat any
        // read failure as corruption, never as success.
        CryptoError::Corrupted(format!("payload authentication failed: {e}"))
    })?;
    Ok(plaintext)
}

fn map_decrypt(e: DecryptError) -> CryptoError {
    match e {
        DecryptError::DecryptionFailed => CryptoError::Corrupted("decryption failed".into()),
        DecryptError::NoMatchingKeys => CryptoError::Corrupted("no matching keys".into()),
        DecryptError::Io(io) => CryptoError::Io(io),
        other => CryptoError::Corrupted(other.to_string()),
    }
}
