//! Fimbl error type

use std::io;

use thiserror::Error;

/// Errors in the operation of fimbl rather than problems or
/// unexpected conditions discovered during file verification or
/// database checking.
#[derive(Error, Debug)]
pub enum FimblError {
    #[error("database access error")]
    DatabaseError(#[from] sled::Error),
    #[error("bad fingerprint in database")]
    FingerprintDeserializationError(#[from] rmp_serde::decode::Error),
    #[error("error while accessing file for fingerprinting")]
    FileAccessError(#[from] io::Error),
}
