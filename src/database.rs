//! Managing the state database

use crate::{error::FimblError, fingerprint::Fingerprint, report::ReportItem};
use sled::{self, Db, IVec};
use std::{
    path::{Path, PathBuf},
    time::SystemTime,
};

/// The SystemDatabase stores file fingerprint and logs
///
/// Two sled trees `fingerprints` and `logs`.
pub struct SystemDatabase {
    /// Location of the data directory
    path: PathBuf,

    /// The (open) sled database
    db: Db,
}

/// Convert path to key buffer
///
/// For now, may fail with windows unicode paths
fn path_as_key(path: &Path) -> Option<IVec> {
    path.to_str().map(|s| IVec::from(s.as_bytes()))
}

/// Convert key bytes to a PathBuf
fn path_from_key<K: AsRef<[u8]>>(key_bytes: K) -> Option<PathBuf> {
    std::str::from_utf8(key_bytes.as_ref())
        .ok()
        .and_then(|s| PathBuf::try_from(s).ok())
}

/// DB contains facts about fingerprints, either that they are valid
/// from a given time or that they are no longer verified from a given
/// time (i.e. removed from the database).
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
enum FingerprintRecord {
    /// Fingerprint was valid at specified time
    Assert(SystemTime, Fingerprint),
    /// No fingerprint was valid (or tracked) from specified time
    Retract(SystemTime),
}

impl FingerprintRecord {
    fn assert(fingerprint: Fingerprint) -> Self {
        FingerprintRecord::Assert(SystemTime::now(), fingerprint)
    }

    fn retract() -> Self {
        FingerprintRecord::Retract(SystemTime::now())
    }

    fn fingerprint(&self) -> Option<&Fingerprint> {
        match self {
            FingerprintRecord::Assert(_, fp) => Some(fp),
            FingerprintRecord::Retract(_) => None,
        }
    }

    /// Serialize to bytes
    pub fn to_vec(&self) -> Vec<u8> {
        rmp_serde::to_vec(self).unwrap()
    }

    /// Deserialize from bytes
    pub fn from_slice(input: &[u8]) -> Result<Self, FimblError> {
        Ok(rmp_serde::from_slice(input)?)
    }
}

impl SystemDatabase {
    /// Path of database directory
    pub fn path(&self) -> &Path {
        self.path.as_ref()
    }

    /// Open the database at the specified path, creating if required
    pub fn open(db_dir: &Path) -> Result<Self, FimblError> {
        let path = db_dir.to_owned();
        let db = sled::open(db_dir)?;

        Ok(SystemDatabase { path, db })
    }

    /// Store fingerprint for new file in the database
    ///
    /// Pre-existing files are a report, unless tolerant flag is set
    /// in which case the file is verified. This will not update an
    /// existing incorrect fingerprint. For that, use accept.
    pub fn store_new_file(
        &mut self,
        path: &Path,
        fingerprint: &Fingerprint,
        tolerate_existing: bool,
    ) -> Result<Vec<ReportItem>, FimblError> {
        let tree = self.db.open_tree("fingerprints")?;
        let mut reports = vec![];

        match path_as_key(path) {
            Some(path_key) => match tree.get(&path_key)? {
                Some(record_bytes) => {
                    let record = FingerprintRecord::from_slice(record_bytes.as_ref())?;

                    match record.fingerprint() {
                        Some(stored_fingerprint) if tolerate_existing => {
                            if *stored_fingerprint != *fingerprint {
                                reports.push(ReportItem::FileContentChanged {
                                    path: path.to_path_buf(),
                                })
                            }
                        }
                        Some(_) => {
                            reports.push(ReportItem::FileAlreadyTracked {
                                path: path.to_path_buf(),
                            });
                        }
                        None => {
                            tree.insert(
                                &path_key,
                                FingerprintRecord::assert(fingerprint.clone()).to_vec(),
                            )?;
                        }
                    }
                }
                None => {
                    tree.insert(
                        &path_key,
                        FingerprintRecord::assert(fingerprint.clone()).to_vec(),
                    )?;
                }
            },
            None => {
                reports.push(ReportItem::FileNameNotSupported {
                    path: path.to_path_buf(),
                });
            }
        }

        Ok(reports)
    }

    /// Store updated fingerprint for existing file in the database
    ///
    /// Missing files are a report, unless tolerant flag is set
    /// in which case the file is added.
    pub fn update_existing_file(
        &mut self,
        path: &Path,
        fingerprint: &Fingerprint,
        tolerate_untracked: bool,
    ) -> Result<Vec<ReportItem>, FimblError> {
        let tree = self.db.open_tree("fingerprints")?;
        let mut reports = vec![];

        if let Some(path_key) = path_as_key(path) {
            let exists = tree.contains_key(&path_key)?;

            if exists || tolerate_untracked {
                tree.insert(
                    &path_key,
                    FingerprintRecord::assert(fingerprint.clone()).to_vec(),
                )?;
            } else {
                reports.push(ReportItem::FileNotTracked {
                    path: path.to_path_buf(),
                })
            }
        } else {
            reports.push(ReportItem::FileNameNotSupported {
                path: path.to_path_buf(),
            });
        }

        Ok(reports)
    }

    /// Remove fingerprint for specified file
    pub fn remove_existing_file(
        &mut self,
        path: &Path,
        tolerate_untracked: bool,
    ) -> Result<Vec<ReportItem>, FimblError> {
        let tree = self.db.open_tree("fingerprints")?;
        let mut reports = vec![];

        if let Some(path_key) = path_as_key(path) {
            let exists = tree.contains_key(&path_key)?;

            if exists || tolerate_untracked {
                tree.insert(&path_key, FingerprintRecord::retract().to_vec())?;
            } else {
                reports.push(ReportItem::FileNotTracked {
                    path: path.to_path_buf(),
                })
            }
        } else {
            reports.push(ReportItem::FileNameNotSupported {
                path: path.to_path_buf(),
            });
        }

        Ok(reports)
    }

    /// List the currently tracked files and their fingerprints
    pub fn list_fingerprint_assertions(&self) -> Result<Vec<(PathBuf, Fingerprint)>, FimblError> {
        let tree = self.db.open_tree("fingerprints")?;
        let mut fingerprints = vec![];

        for item in tree.into_iter().flatten() {
            let (k, v) = item;
            let path = path_from_key(k).unwrap();
            let record = FingerprintRecord::from_slice(&v)?;
            if let FingerprintRecord::Assert(_t, fingerprint) = record {
                fingerprints.push((path, fingerprint));
            }
        }

        Ok(fingerprints)
    }

    /// Validate that the supplied fingerprint matches the one
    /// recorded for the path
    pub fn verify(
        &mut self,
        path: &Path,
        fingerprint: &Fingerprint,
    ) -> Result<Vec<ReportItem>, FimblError> {
        let tree = self.db.open_tree("fingerprints")?;
        let mut reports = vec![];

        match path_as_key(path) {
            Some(path_key) => match tree.get(&path_key)? {
                Some(record_bytes) => {
                    let record = FingerprintRecord::from_slice(record_bytes.as_ref())?;

                    match record.fingerprint() {
                        Some(stored_fingerprint) => {
                            if *stored_fingerprint != *fingerprint {
                                reports.push(ReportItem::FileContentChanged {
                                    path: path.to_path_buf(),
                                })
                            }
                        }
                        None => {
                            // fingerprint retracted
                            reports.push(ReportItem::FileNotTracked {
                                path: path.to_path_buf(),
                            })
                        }
                    }
                }
                None => {
                    // fingerprint never tracked
                    reports.push(ReportItem::FileNotTracked {
                        path: path.to_path_buf(),
                    })
                }
            },
            None => {
                reports.push(ReportItem::FileNameNotSupported {
                    path: path.to_path_buf(),
                });
            }
        }

        Ok(reports)
    }
}
