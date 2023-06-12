//! Simple command line file integrity management tool

mod database;
mod error;
mod fingerprint;
mod report;

#[macro_use]
extern crate serde_derive;

use clap::{Parser, Subcommand};
use database::SystemDatabase;
use error::FimblError;
use fingerprint::Fingerprint;
use report::ReportItem;
use std::{
    fs::{canonicalize, read_link},
    path::{Path, PathBuf},
};

/// fimbl - command line file integrity checker
///
/// All commands use a database at "~/.config/fimbl/db" by default
#[derive(Parser)]
#[command(version)]
struct CliArgs {
    /// Consider symlink targets (in addition to the links)
    #[arg(short, long)]
    verbose: bool,

    /// Consider symlink targets (in addition to the links)
    #[arg(short = 's', long)]
    follow_symlinks: bool,

    /// Tolerate unexpected pre-existing or absent files
    #[arg(short, long)]
    tolerant: bool,

    /// Specify alternative database
    #[arg(short, long, value_name = "FILE")]
    database: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

impl CliArgs {
    fn database(&self) -> Option<&Path> {
        self.database.as_deref()
    }
}

#[derive(Subcommand)]
enum Command {
    /// Add new files to the database (and fingerprint)
    Add { files: Vec<PathBuf> },
    /// Remove files from the database (keeping historic fingerprints)
    Remove { files: Vec<PathBuf> },
    /// List all files current in the database
    List {},
    /// Verify the files specified against the database
    Verify { files: Vec<PathBuf> },
    /// Verify all files current in the database
    VerifyAll {},
    /// Accept modifications to the specified files
    Accept { files: Vec<PathBuf> },
}

/// Expand a symlink into chain of links and ultimate target
fn symlink_reference_chain(path: &Path) -> Result<Vec<PathBuf>, FimblError> {
    let mut chain = vec![];
    let mut target: PathBuf = path.to_owned();
    loop {
        chain.push(target.clone());
        let symlink = target.is_symlink();

        if symlink {
            target = read_link(target)?;
        } else {
            break;
        }
    }

    Ok(chain)
}

/// Expand symlinks to include targets as well and filter out directories...
fn preprocess_file_list(files: &Vec<PathBuf>) -> Result<(Vec<PathBuf>, Vec<PathBuf>), FimblError> {
    let mut files_and_symlinks = vec![];
    let mut directories = vec![];

    for file in files {
        let mut chain = symlink_reference_chain(file)?;
        let target = chain.last().unwrap();
        if Path::is_dir(target) {
            directories.append(&mut chain);
        } else {
            files_and_symlinks.append(&mut chain);
        }
    }
    Ok((files_and_symlinks, directories))
}

/// If dirs is non-empty, return an error
fn reject_directories(dirs: &[PathBuf]) -> Vec<ReportItem> {
    dirs.iter()
        .map(|d| ReportItem::FileIsDirectory { path: d.clone() })
        .collect()
}

/// Fingerprint files and add to database
fn add(
    files: &Vec<PathBuf>,
    database: &mut SystemDatabase,
    tolerate_existing: bool,
) -> Result<Vec<ReportItem>, FimblError> {
    let (files, dirs) = preprocess_file_list(files)?;
    let mut reports = reject_directories(&dirs);

    for file in files {
        let file = canonicalize(&file)?;

        match Fingerprint::from_file(&file) {
            Ok(fingerprint) => {
                let mut file_reports =
                    database.store_new_file(&file, &fingerprint, tolerate_existing)?;
                reports.append(&mut file_reports);
            }
            Err(e) => {
                panic!("Cannot add {}: {}", file.to_string_lossy(), e);
            }
        }
    }

    Ok(reports)
}

/// List all the files currently in the database to stdout
fn list(database: &SystemDatabase, verbose: bool) -> Result<Vec<ReportItem>, FimblError> {
    if verbose {
        println!("Fimbl DB is at {}", database.path().display());
        println!("Files tracked:\n");
    }

    for (path, _fingerprint) in database.list_fingerprint_assertions()? {
        println!("{}", path.display());
    }

    Ok(vec![])
}

/// Remove files from database (by marking as gone)
fn remove(
    files: &Vec<PathBuf>,
    database: &mut SystemDatabase,
    tolerate_untracked: bool,
) -> Result<Vec<ReportItem>, FimblError> {
    let (files, dirs) = preprocess_file_list(files)?;
    let mut reports = reject_directories(&dirs);

    for file in files {
        let file = canonicalize(&file)?;

        let mut file_reports = database.remove_existing_file(&file, tolerate_untracked)?;
        reports.append(&mut file_reports);
    }

    Ok(reports)
}

/// Verify the specified files match fingerprints in the database
fn verify(
    files: &Vec<PathBuf>,
    database: &mut SystemDatabase,
) -> Result<Vec<ReportItem>, FimblError> {
    let (files, dirs) = preprocess_file_list(files)?;
    let mut reports = reject_directories(&dirs);

    for file in files {
        let file = canonicalize(&file)?;

        match Fingerprint::from_file(&file) {
            Ok(fingerprint) => {
                let mut file_reports = database.verify(&file, &fingerprint)?;
                reports.append(&mut file_reports);
            }
            Err(e) => {
                panic!("Cannot verify {}: {}", file.to_string_lossy(), e);
            }
        }
    }

    Ok(reports)
}

/// Verify all files that are current in the database
fn verify_all(database: &mut SystemDatabase) -> Result<Vec<ReportItem>, FimblError> {
    let mut reports = vec![];

    for (file, _) in database.list_fingerprint_assertions()? {
        match Fingerprint::from_file(&file) {
            Ok(fingerprint) => {
                let mut file_reports = database.verify(&file, &fingerprint)?;
                reports.append(&mut file_reports);
            }
            Err(e) => {
                panic!("Cannot verify {}: {}", file.to_string_lossy(), e);
            }
        }
    }

    Ok(reports)
}

/// Accept modifications to the specified files
fn accept(
    files: &Vec<PathBuf>,
    database: &mut SystemDatabase,
    tolerate_untracked: bool,
) -> Result<Vec<ReportItem>, FimblError> {
    let (files, dirs) = preprocess_file_list(files)?;
    let mut reports = reject_directories(&dirs);

    for file in files {
        let file = canonicalize(&file)?;
        match Fingerprint::from_file(&file) {
            Ok(fingerprint) => {
                let mut file_reports =
                    database.update_existing_file(&file, &fingerprint, tolerate_untracked)?;
                reports.append(&mut file_reports);
            }
            Err(e) => {
                panic!("Cannot add {}: {}", file.to_string_lossy(), e);
            }
        }
    }

    Ok(reports)
}

fn report(report_items: Vec<ReportItem>) {
    for item in report_items {
        println!("- {item}")
    }
}

fn main() {
    let cli = CliArgs::parse();

    let default_db = if let Some(path) = dirs::home_dir() {
        path.join(".config/fimbl/db")
    } else {
        panic!("No HOME directory")
    };

    let db_path = cli.database().unwrap_or(&*default_db);

    let mut database = SystemDatabase::open(db_path).unwrap();

    let reports = match &cli.command {
        Command::Add { files } => add(files, &mut database, cli.tolerant),
        Command::Remove { files } => remove(files, &mut database, cli.tolerant),
        Command::List {} => list(&database, cli.verbose),
        Command::Verify { files } => verify(files, &mut database),
        Command::VerifyAll {} => verify_all(&mut database),
        Command::Accept { files } => accept(files, &mut database, cli.tolerant),
    };

    report(reports.unwrap());
}
