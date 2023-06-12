//! Report items (info and warn) for unexpected modifications and
//! other conditions.

use std::path::PathBuf;

/// A report item that may represent unexpected file system
/// modification or other concerning situation.
#[allow(clippy::enum_variant_names)]
pub enum ReportItem {
    /// The file exists (unexpectedly) and is not tolerated
    FileAlreadyTracked { path: PathBuf },
    /// The file is missing (unexpectedly) from the database
    FileNotTracked { path: PathBuf },
    /// The file contents have changed
    FileContentChanged { path: PathBuf },
    /// The filename is not supported
    FileNameNotSupported { path: PathBuf },
    /// File is (now) a directory
    FileIsDirectory { path: PathBuf },
}

impl std::fmt::Display for ReportItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportItem::FileAlreadyTracked { path } => {
                write!(f, "file already exists: {}", path.display())
            }
            ReportItem::FileContentChanged { path } => {
                write!(f, "file content changed: {}", path.display())
            }
            ReportItem::FileNameNotSupported { path } => {
                write!(
                    f,
                    "file ignored - unsupported file name: {}",
                    path.display()
                )
            }
            ReportItem::FileNotTracked { path } => {
                write!(f, "file is untracked: {}", path.display())
            }
            ReportItem::FileIsDirectory { path } => {
                write!(f, "file is (now) a directory: {}", path.display())
            }
        }
    }
}
