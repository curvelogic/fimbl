//! Hashing file content and attributes

use crate::error::FimblError;

use sha3::{Digest, Sha3_256};
use std::os::unix::fs::PermissionsExt;
use std::{
    fs::{symlink_metadata, File, Metadata},
    io::{self, Read},
    path::Path,
    time::SystemTime,
};

type Hash = Sha3_256;
const HASH_SIZE: usize = 32;
pub type HashValue = [u8; HASH_SIZE];

/// Fingerprint of file data and attributes at a point in time
///
/// Tracked attributes include file type (file or symlink), creation
/// and modification times and unix permissions. Access time is ignored.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Fingerprint {
    /// Hash of file contents
    pub content_hash: HashValue,

    /// True if file is a symlink to elsewhere
    pub symlink: bool,

    /// File creation time
    pub created: Option<SystemTime>,

    /// File modification time
    pub modified: Option<SystemTime>,

    /// Unix file mode
    pub unix_mode: Option<u32>,

    /// Readonly (unix or windows)
    pub read_only: bool,
}

/// Read the entire file and calculate a hash of its contents
fn hash_contents(path: &Path) -> io::Result<HashValue> {
    let mut file = File::open(path)?;

    let mut hasher = Hash::new();

    let mut buffer = vec![0; 4096];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hasher.finalize().as_slice().try_into().unwrap())
}

#[cfg(windows)]
fn unix_mode(metadata: &Metadata) -> Option<u32> {
    None
}

#[cfg(not(windows))]
fn unix_mode(metadata: &Metadata) -> Option<u32> {
    Some(metadata.permissions().mode())
}

/// Generate file fingerprint for comparison or storage
pub fn fingerprint_file(path: &Path) -> io::Result<Fingerprint> {
    let metadata = symlink_metadata(path)?;
    let content_hash = hash_contents(path)?;

    Ok(Fingerprint {
        content_hash,
        symlink: metadata.is_symlink(),
        created: metadata.created().ok(),
        modified: metadata.modified().ok(),
        unix_mode: unix_mode(&metadata),
        read_only: metadata.permissions().readonly(),
    })
}

impl Fingerprint {
    /// Fingerprint a file on disk
    pub fn from_file(path: &Path) -> Result<Self, FimblError> {
        Ok(fingerprint_file(path)?)
    }
}

#[cfg(test)]
pub mod tests {

    use std::path::PathBuf;

    use super::*;

    #[test]
    fn test_fingerprint_lorem_ipsum_content() {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("resources/test/loremipsum.txt");

        let expected = [
            180, 140, 108, 172, 36, 194, 255, 235, 235, 56, 177, 126, 45, 82, 184, 188, 208, 200,
            0, 45, 188, 213, 174, 119, 118, 223, 231, 174, 161, 208, 249, 145,
        ];
        assert_eq!(hash_contents(&d).unwrap(), expected);
    }

    #[test]
    fn test_fingerprint_file_metadata() {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("resources/test/loremipsum.txt");

        let fingerprint = fingerprint_file(&d).unwrap();
        assert!(fingerprint.created.is_some());
        assert!(fingerprint.modified.is_some());
        if cfg!(target_os = "windows") {
            assert!(fingerprint.unix_mode.is_none())
        } else {
            assert!(fingerprint.unix_mode.is_some())
        }
        assert!(!fingerprint.symlink);
        assert!(!fingerprint.read_only);
    }
}
