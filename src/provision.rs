//! Self-provisioning: copying the stopit binary and its runtime closure into
//! the session directory (DESIGN.md §2.1, §6.2).
//!
//! bwrap runs `stopit __init` inside the sandbox, which sees neither
//! `/nix/store` nor `/usr` unless a profile grants them, and must not depend
//! on host paths it cannot see or that may change mid-session. So
//! [`provision`] copies the binary to `<dir>/stopit`, and its program
//! interpreter (`PT_INTERP`) and every shared library that interpreter
//! resolves for it to `<dir>/lib/`. The directory is mounted read-only at
//! [`SANDBOX_RUNTIME_DIR`](crate::spec::SANDBOX_RUNTIME_DIR), and the copy is
//! run through the copied interpreter with the copied libraries as its
//! library path ([`Provisioned::command_prefix`]): neither the binary's own
//! `PT_INTERP` nor its run path need to exist in the sandbox, and no ELF
//! patching or environment variable is involved.
//!
//! The closure is what the binary's own interpreter lists in its list mode
//! (`<interp> --list <exe>`, which is what `ldd` runs), so the loader that
//! will load the copy decides what is copied. A static binary has no
//! interpreter and is copied alone.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, Write as _};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use thiserror::Error;

use crate::session::{SessionDir, create_private_dir};

/// File name of the copied binary in the provisioned directory.
const EXE_NAME: &str = "stopit";

/// Name of the directory of the copied interpreter and libraries.
const LIB_DIR: &str = "lib";

/// Mode of the copied binary and interpreter: the owner may read and run
/// them, no one may write them.
const EXEC_MODE: u32 = 0o500;

/// Mode of the copied libraries: they are mapped, never executed directly.
const LIB_MODE: u32 = 0o400;

/// Error reading the program interpreter from an ELF file.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ElfError {
    /// The file does not start with the ELF magic number.
    #[error("not an ELF file")]
    NotElf,

    /// The file is ELF, but of a kind stopit does not read.
    #[error("unsupported ELF file: {0}")]
    Unsupported(&'static str),

    /// A header or segment the file refers to lies past its end.
    #[error("truncated ELF file")]
    Truncated,

    /// A header is inconsistent.
    #[error("malformed ELF file: {0}")]
    Malformed(&'static str),

    /// The interpreter path is not absolute.
    #[error("the program interpreter {0:?} is not an absolute path")]
    RelativeInterpreter(PathBuf),
}

/// Error in the interpreter's list output.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ListError {
    /// The loader found no file for a needed library.
    #[error("library {0:?} not found")]
    NotFound(OsString),

    /// The loader resolved a library to a path that is not absolute.
    #[error("library {name:?} resolved to {path:?}, which is not an absolute path")]
    NotAbsolute {
        /// The library name the loader looked for.
        name: OsString,
        /// The path it printed.
        path: PathBuf,
    },

    /// A library name the copy cannot be stored under: it contains a `/`
    /// but is not absolute, or is `.` or `..`.
    #[error("library name {0:?} is not a plain file name")]
    BadName(OsString),
}

/// Error provisioning a binary.
#[derive(Debug, Error)]
pub enum ProvisionError {
    /// A file could not be read or inspected.
    #[error("cannot read {path:?}: {source}")]
    Read {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// The binary's program interpreter could not be read.
    #[error("cannot read the program interpreter of {path:?}: {source}")]
    Elf {
        /// The binary.
        path: PathBuf,
        /// What is wrong with it.
        source: ElfError,
    },

    /// The interpreter could not be started in list mode.
    #[error("cannot run {interp:?} to list the libraries of {exe:?}: {source}")]
    ListSpawn {
        /// The interpreter.
        interp: PathBuf,
        /// The binary.
        exe: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// The interpreter's list mode failed, and its output names no missing
    /// library (that is reported as [`ProvisionError::List`]).
    #[error("{interp:?} --list {exe:?} failed ({status}); stdout: {stdout:?}; stderr: {stderr:?}")]
    ListFailed {
        /// The interpreter.
        interp: PathBuf,
        /// The binary.
        exe: PathBuf,
        /// Its exit status.
        status: ExitStatus,
        /// What it wrote to stdout, trimmed.
        stdout: String,
        /// What it wrote to stderr, trimmed.
        stderr: String,
    },

    /// The running binary's file was deleted or replaced since it started,
    /// so there is nothing to copy.
    #[error("the stopit binary {path:?} was replaced or removed since it started; restart stopit")]
    SelfReplaced {
        /// The path the binary was started from.
        path: PathBuf,
    },

    /// The interpreter's list output names a library that cannot be copied.
    #[error("cannot resolve the libraries of {exe:?} with {interp:?}: {source}")]
    List {
        /// The interpreter.
        interp: PathBuf,
        /// The binary.
        exe: PathBuf,
        /// What is wrong with the output.
        source: ListError,
    },

    /// A library is loaded by absolute path. The copy could not be found
    /// there in the sandbox.
    #[error("{exe:?} loads {path:?} by absolute path, which is not supported")]
    AbsoluteDependency {
        /// The binary.
        exe: PathBuf,
        /// The library.
        path: PathBuf,
    },

    /// Two different files would be copied under the same name in `lib/`.
    #[error("both {first:?} and {second:?} would be copied as lib/{name:?}")]
    DuplicateName {
        /// The shared file name.
        name: OsString,
        /// The first file.
        first: PathBuf,
        /// The second file.
        second: PathBuf,
    },

    /// Something to copy is not a regular file.
    #[error("{path:?} is not a regular file")]
    NotRegularFile {
        /// The file.
        path: PathBuf,
    },

    /// A directory could not be created.
    #[error("cannot create {path:?}: {source}")]
    CreateDir {
        /// The directory.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// A copy could not be written. An existing file is an error too: copies
    /// are only ever written to new files.
    #[error("cannot write {path:?}: {source}")]
    Write {
        /// The copy.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
}

/// A binary provisioned into a directory by [`provision`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provisioned {
    exe: PathBuf,
    loader: Option<PathBuf>,
    lib_dir: PathBuf,
}

impl Provisioned {
    /// A `Provisioned` for unit tests elsewhere in the crate, with arbitrary
    /// paths and nothing copied.
    #[cfg(test)]
    pub(crate) fn for_tests(exe: PathBuf, loader: Option<PathBuf>, lib_dir: PathBuf) -> Self {
        Provisioned {
            exe,
            loader,
            lib_dir,
        }
    }

    /// The copied binary on the host, `<dir>/stopit`.
    pub fn exe(&self) -> &Path {
        &self.exe
    }

    /// The copied program interpreter on the host, `<dir>/lib/<name>`, or
    /// `None` for a static binary.
    pub fn loader(&self) -> Option<&Path> {
        self.loader.as_deref()
    }

    /// The directory of the copied interpreter and libraries on the host,
    /// `<dir>/lib` (empty for a static binary).
    pub fn lib_dir(&self) -> &Path {
        &self.lib_dir
    }

    /// The leading arguments that run the copy when the provisioned directory
    /// is mounted at `base` (normally
    /// [`SANDBOX_RUNTIME_DIR`](crate::spec::SANDBOX_RUNTIME_DIR)); the
    /// binary's own arguments follow. For a dynamic binary that is the copied
    /// interpreter with the copied libraries as its only library path,
    /// `<base>/lib/<interp> --library-path <base>/lib <base>/stopit`; for a
    /// static one just `<base>/stopit`.
    ///
    /// The program then sees `<base>/stopit` as `argv[0]`, but
    /// `/proc/self/exe` names the interpreter. `base` must not contain `:`,
    /// which separates entries of a library path.
    pub fn command_prefix(&self, base: &Path) -> Vec<OsString> {
        let exe = base.join(EXE_NAME).into_os_string();
        let Some(loader) = &self.loader else {
            return vec![exe];
        };
        let lib_dir = base.join(LIB_DIR);
        let name = loader.file_name().expect("the loader copy has a file name");
        vec![
            lib_dir.join(name).into_os_string(),
            "--library-path".into(),
            lib_dir.into_os_string(),
            exe,
        ]
    }
}

/// Provisions the running binary (the canonical path of `/proc/self/exe`)
/// into the session directory. Only meaningful on the host: inside a sandbox,
/// `/proc/self/exe` is the interpreter the copy runs through.
pub fn provision_self(session: &SessionDir) -> Result<Provisioned, ProvisionError> {
    let exe = running_exe(Path::new("/proc/self/exe"))?;
    provision(&exe, session.root())
}

/// The canonical path of the binary the magic link `self_exe` (normally
/// `/proc/self/exe`) refers to. The kernel appends ` (deleted)` to the
/// link's text once that file is gone (removed, or replaced by an upgrade);
/// that is a [`ProvisionError::SelfReplaced`], not a confusing missing file.
fn running_exe(self_exe: &Path) -> Result<PathBuf, ProvisionError> {
    let read_error = |source| ProvisionError::Read {
        path: self_exe.to_path_buf(),
        source,
    };
    let target = fs::read_link(self_exe).map_err(read_error)?;
    if let Some(path) = target.as_os_str().as_bytes().strip_suffix(b" (deleted)") {
        // A file really named `… (deleted)` still exists.
        if !target.exists() {
            return Err(ProvisionError::SelfReplaced {
                path: PathBuf::from(OsStr::from_bytes(path)),
            });
        }
    }
    fs::canonicalize(self_exe).map_err(read_error)
}

/// Copies the binary `exe`, its program interpreter and the libraries the
/// interpreter resolves for it into the existing directory `dir`: the binary
/// to `<dir>/stopit`, the rest to `<dir>/lib/` under the names the loader
/// looks for. `<dir>/stopit` and `<dir>/lib` must not exist yet; nothing
/// existing is followed or overwritten.
///
/// A failure part way through leaves what was already written in `dir`. That
/// is fine for the session directory, which [`SessionDir`] removes with
/// everything in it when dropped; the session does not start anyway.
pub fn provision(exe: &Path, dir: &Path) -> Result<Provisioned, ProvisionError> {
    // The bytes read here are both parsed and copied, so the copy is the
    // binary that was inspected.
    let bytes = fs::read(exe).map_err(|source| ProvisionError::Read {
        path: exe.to_path_buf(),
        source,
    })?;
    let interp = read_interpreter(&bytes).map_err(|source| ProvisionError::Elf {
        path: exe.to_path_buf(),
        source,
    })?;
    let libraries = match &interp {
        Some(interp) => resolve_libraries(exe, interp)?,
        None => Vec::new(),
    };
    install(&bytes, interp.as_deref(), &libraries, dir)
}

// --- ELF -------------------------------------------------------------------

/// The ELF magic number, `e_ident[0..4]`.
const ELF_MAGIC: &[u8] = b"\x7fELF";
/// Length of `e_ident`.
const EI_NIDENT: usize = 16;
/// Index of the class (32 or 64 bit) in `e_ident`.
const EI_CLASS: usize = 4;
/// Index of the data encoding (endianness) in `e_ident`.
const EI_DATA: usize = 5;
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ELFDATA2MSB: u8 = 2;
/// Size of the ELF64 file header.
const EHDR64_SIZE: usize = 64;
/// Size of an ELF64 program header.
const PHDR64_SIZE: usize = 56;
/// `e_phnum` value saying the real count is stored elsewhere.
const PN_XNUM: u16 = 0xffff;
/// Program header type of the interpreter path.
const PT_INTERP: u32 = 3;

/// Reads the program interpreter (`PT_INTERP`) of an ELF64 little-endian
/// file: `Some` absolute path for a dynamically linked binary, `None` for a
/// static one.
pub fn read_interpreter(elf: &[u8]) -> Result<Option<PathBuf>, ElfError> {
    if !elf.starts_with(ELF_MAGIC) {
        return Err(ElfError::NotElf);
    }
    let ident = elf.get(..EI_NIDENT).ok_or(ElfError::Truncated)?;
    match ident[EI_CLASS] {
        ELFCLASS64 => {}
        ELFCLASS32 => return Err(ElfError::Unsupported("32-bit ELF; only ELF64 is supported")),
        _ => return Err(ElfError::Malformed("invalid ELF class")),
    }
    match ident[EI_DATA] {
        ELFDATA2LSB => {}
        ELFDATA2MSB => return Err(ElfError::Unsupported("big-endian ELF")),
        _ => return Err(ElfError::Malformed("invalid data encoding")),
    }
    let header = elf.get(..EHDR64_SIZE).ok_or(ElfError::Truncated)?;
    let phoff = le_u64(header, 32);
    let phentsize = le_u16(header, 54);
    let phnum = le_u16(header, 56);
    if phnum == PN_XNUM {
        return Err(ElfError::Unsupported("more than 65534 program headers"));
    }
    if phnum > 0 && usize::from(phentsize) < PHDR64_SIZE {
        return Err(ElfError::Malformed("program header entries are too small"));
    }
    for index in 0..u64::from(phnum) {
        let offset = index
            .checked_mul(u64::from(phentsize))
            .and_then(|o| o.checked_add(phoff))
            .ok_or(ElfError::Truncated)?;
        let phdr = slice(elf, offset, PHDR64_SIZE as u64)?;
        if le_u32(phdr, 0) != PT_INTERP {
            continue;
        }
        // Like the kernel, the first PT_INTERP counts.
        let segment = slice(elf, le_u64(phdr, 8), le_u64(phdr, 32))?;
        let end = segment
            .iter()
            .position(|&b| b == 0)
            .ok_or(ElfError::Malformed(
                "interpreter path is not NUL-terminated",
            ))?;
        let path = PathBuf::from(OsStr::from_bytes(&segment[..end]));
        if !path.is_absolute() {
            return Err(ElfError::RelativeInterpreter(path));
        }
        return Ok(Some(path));
    }
    Ok(None)
}

/// The `len` bytes of `elf` at `offset`, or [`ElfError::Truncated`] if they
/// are not all in it.
fn slice(elf: &[u8], offset: u64, len: u64) -> Result<&[u8], ElfError> {
    let start = usize::try_from(offset).map_err(|_| ElfError::Truncated)?;
    let len = usize::try_from(len).map_err(|_| ElfError::Truncated)?;
    let end = start.checked_add(len).ok_or(ElfError::Truncated)?;
    elf.get(start..end).ok_or(ElfError::Truncated)
}

fn le_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().expect("2 bytes"))
}

fn le_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"))
}

fn le_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8 bytes"))
}

// --- Library resolution ----------------------------------------------------

/// A library to copy: the name the loader looks for, and the file it found.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Library {
    name: OsString,
    path: PathBuf,
}

/// One object in the interpreter's list output.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ListEntry {
    /// `name => /abs/path (0x…)`: a library found by name.
    Library(Library),
    /// `/abs/path (0x…)` or `/abs/name => /abs/path (0x…)`: an object loaded
    /// by absolute path, normally the interpreter itself.
    Absolute {
        /// The path as asked for.
        name: PathBuf,
        /// The path the loader found it at.
        path: PathBuf,
    },
}

/// Runs `interp --list exe` and returns the libraries it resolves, without
/// the interpreter itself.
///
/// The environment is cleared, so `LD_LIBRARY_PATH` and `LD_PRELOAD` do not
/// change what is copied: the libraries are found as the binary's own run
/// path and the system's search path find them.
fn resolve_libraries(exe: &Path, interp: &Path) -> Result<Vec<Library>, ProvisionError> {
    let output = Command::new(interp)
        .arg("--list")
        .arg(exe)
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .map_err(|source| ProvisionError::ListSpawn {
            interp: interp.to_path_buf(),
            exe: exe.to_path_buf(),
            source,
        })?;
    // Parsed before the exit status is checked, so a missing library is
    // reported by name whether or not the loader fails because of it.
    let entries = parse_list(&output.stdout).map_err(|source| ProvisionError::List {
        interp: interp.to_path_buf(),
        exe: exe.to_path_buf(),
        source,
    })?;
    if !output.status.success() {
        let trimmed = |bytes: &[u8]| String::from_utf8_lossy(bytes).trim().to_string();
        return Err(ProvisionError::ListFailed {
            interp: interp.to_path_buf(),
            exe: exe.to_path_buf(),
            status: output.status,
            stdout: trimmed(&output.stdout),
            stderr: trimmed(&output.stderr),
        });
    }
    let mut libraries = Vec::new();
    for entry in entries {
        match entry {
            ListEntry::Library(library) => libraries.push(library),
            // The interpreter is copied separately.
            ListEntry::Absolute { name, path } if name == interp || same_file(&path, interp) => {}
            ListEntry::Absolute { path, .. } => {
                return Err(ProvisionError::AbsoluteDependency {
                    exe: exe.to_path_buf(),
                    path,
                });
            }
        }
    }
    Ok(libraries)
}

/// Parses the list output of the glibc loader (`ld.so --list`, as `ldd`
/// prints it). One object per line:
///
/// * `name => /abs/path (0x…)`: a library found by name;
/// * `/abs/path (0x…)`: an object loaded by absolute path (the interpreter);
/// * `name => not found`: an error;
/// * `linux-vdso.so.1 (0x…)` or `linux-vdso.so.1 =>  (0x…)`: the vDSO, which
///   has no file, like any other line without a path, is skipped.
///
/// musl's loader prints the same format.
fn parse_list(output: &[u8]) -> Result<Vec<ListEntry>, ListError> {
    let mut entries = Vec::new();
    for line in output.split(|&b| b == b'\n') {
        let line = strip_address(line.trim_ascii());
        if line.is_empty() {
            continue;
        }
        let (name, path) = match line.windows(2).position(|w| w == b"=>") {
            Some(arrow) => (
                line[..arrow].trim_ascii(),
                Some(line[arrow + 2..].trim_ascii()),
            ),
            None => (line, None),
        };
        let os = |bytes: &[u8]| OsStr::from_bytes(bytes).to_os_string();
        let path = match path {
            None if name.starts_with(b"/") => name,
            // The vDSO, or a line that is not an object.
            None => continue,
            Some(b"not found") => return Err(ListError::NotFound(os(name))),
            // The vDSO in older glibc versions.
            Some([]) => continue,
            Some(path) => path,
        };
        if !path.starts_with(b"/") {
            return Err(ListError::NotAbsolute {
                name: os(name),
                path: PathBuf::from(os(path)),
            });
        }
        if name.starts_with(b"/") {
            entries.push(ListEntry::Absolute {
                name: PathBuf::from(os(name)),
                path: PathBuf::from(os(path)),
            });
            continue;
        }
        if name.contains(&b'/') || name == b"." || name == b".." {
            return Err(ListError::BadName(os(name)));
        }
        entries.push(ListEntry::Library(Library {
            name: os(name),
            path: PathBuf::from(os(path)),
        }));
    }
    Ok(entries)
}

/// `line` without a trailing load address `(0x…)` and the space before it.
fn strip_address(line: &[u8]) -> &[u8] {
    let Some(inner) = line.strip_suffix(b")") else {
        return line;
    };
    let Some(open) = inner.windows(3).rposition(|w| w == b"(0x") else {
        return line;
    };
    if inner[open + 3..].iter().all(u8::is_ascii_hexdigit) {
        line[..open].trim_ascii_end()
    } else {
        line
    }
}

/// Whether `a` and `b` are the same file, following symlinks. `false` if
/// either cannot be inspected.
fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::metadata(a), fs::metadata(b)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

// --- Copying ---------------------------------------------------------------

/// Writes the binary `exe` (its bytes) to `<dir>/stopit`, and copies
/// `interp` and `libraries` into `<dir>/lib/`.
fn install(
    exe: &[u8],
    interp: Option<&Path>,
    libraries: &[Library],
    dir: &Path,
) -> Result<Provisioned, ProvisionError> {
    // Every copy in `lib/` and its source, the interpreter first. Checked
    // before anything is written.
    let mut copies: Vec<(OsString, &Path, u32)> = Vec::new();
    let mut by_name: HashMap<OsString, &Path> = HashMap::new();
    let interp_entry = interp.map(|path| {
        let name = path
            .file_name()
            .expect("an absolute ELF interpreter path has a file name");
        (name.to_os_string(), path, EXEC_MODE)
    });
    let library_entries = libraries
        .iter()
        .map(|lib| (lib.name.clone(), lib.path.as_path(), LIB_MODE));
    for (name, path, mode) in interp_entry.into_iter().chain(library_entries) {
        if let Some(&first) = by_name.get(&name) {
            // The same file reached twice (a library the loader also lists
            // under the interpreter's name) is copied once.
            if same_file(first, path) {
                continue;
            }
            return Err(ProvisionError::DuplicateName {
                name,
                first: first.to_path_buf(),
                second: path.to_path_buf(),
            });
        }
        by_name.insert(name.clone(), path);
        copies.push((name, path, mode));
    }

    let exe_path = dir.join(EXE_NAME);
    let lib_dir = dir.join(LIB_DIR);
    // Not `create_dir_all`: an existing `lib` (or link) is an error.
    create_private_dir(&lib_dir).map_err(|source| ProvisionError::CreateDir {
        path: lib_dir.clone(),
        source,
    })?;
    write_new(&exe_path, EXEC_MODE, |file| file.write_all(exe))?;
    for (name, source, mode) in &copies {
        let mut from = File::open(source).map_err(|e| read_error(source, e))?;
        let meta = from.metadata().map_err(|e| read_error(source, e))?;
        if !meta.is_file() {
            return Err(ProvisionError::NotRegularFile {
                path: source.to_path_buf(),
            });
        }
        let to = lib_dir.join(name);
        write_new(&to, *mode, |file| io::copy(&mut from, file).map(drop))?;
    }

    let loader = interp.map(|path| lib_dir.join(path.file_name().expect("checked above")));
    Ok(Provisioned {
        exe: exe_path,
        loader,
        lib_dir,
    })
}

fn read_error(path: &Path, source: io::Error) -> ProvisionError {
    ProvisionError::Read {
        path: path.to_path_buf(),
        source,
    }
}

/// Creates the new file `path` (failing if anything, a link included, is
/// there), fills it with `fill`, and sets its mode to exactly `mode`.
///
/// The file is closed on return. A process forked meanwhile by another thread
/// holds the write descriptor until it calls `exec`, and running the copy
/// fails with `ETXTBSY` while it does; provisioning happens at session start,
/// before any sandbox is spawned.
fn write_new(
    path: &Path,
    mode: u32,
    fill: impl FnOnce(&mut File) -> io::Result<()>,
) -> Result<(), ProvisionError> {
    let write_error = |source| ProvisionError::Write {
        path: path.to_path_buf(),
        source,
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(write_error)?;
    fill(&mut file).map_err(write_error)?;
    // On the open descriptor, so independent of the umask and of the path.
    file.set_permissions(Permissions::from_mode(mode))
        .map_err(write_error)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use tempfile::TempDir;

    use super::*;
    use crate::spec::SANDBOX_RUNTIME_DIR;

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().mode() & 0o7777
    }

    fn names(dir: &Path) -> Vec<OsString> {
        let mut names: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        names.sort();
        names
    }

    // --- ELF ---

    /// A minimal ELF file: the 64-byte header, the program headers right
    /// after it, then each header's segment data in order.
    fn elf(class: u8, data: u8, phdrs: &[(u32, &[u8])]) -> Vec<u8> {
        let mut out = vec![0u8; EHDR64_SIZE];
        out[..4].copy_from_slice(ELF_MAGIC);
        out[EI_CLASS] = class;
        out[EI_DATA] = data;
        out[6] = 1; // EI_VERSION
        out[32..40].copy_from_slice(&(EHDR64_SIZE as u64).to_le_bytes());
        out[54..56].copy_from_slice(&(PHDR64_SIZE as u16).to_le_bytes());
        out[56..58].copy_from_slice(&(phdrs.len() as u16).to_le_bytes());
        let mut offset = (EHDR64_SIZE + PHDR64_SIZE * phdrs.len()) as u64;
        for (p_type, segment) in phdrs {
            let mut phdr = vec![0u8; PHDR64_SIZE];
            phdr[..4].copy_from_slice(&p_type.to_le_bytes());
            phdr[8..16].copy_from_slice(&offset.to_le_bytes());
            phdr[32..40].copy_from_slice(&(segment.len() as u64).to_le_bytes());
            out.extend(phdr);
            offset += segment.len() as u64;
        }
        for (_, segment) in phdrs {
            out.extend_from_slice(segment);
        }
        out
    }

    const PT_LOAD: u32 = 1;

    #[test]
    fn finds_the_interpreter_of_the_running_binary() {
        let bytes = fs::read("/proc/self/exe").unwrap();
        let interp = read_interpreter(&bytes)
            .unwrap()
            .expect("the test binary is dynamically linked");
        assert!(interp.is_absolute(), "{interp:?}");
        assert!(interp.is_file(), "{interp:?} exists");
    }

    #[test]
    fn finds_the_interpreter_among_other_headers() {
        let bytes = elf(
            ELFCLASS64,
            ELFDATA2LSB,
            &[
                (PT_LOAD, b"code"),
                (PT_INTERP, b"/lib/ld.so\0"),
                (PT_LOAD, b""),
            ],
        );
        assert_eq!(
            read_interpreter(&bytes),
            Ok(Some(PathBuf::from("/lib/ld.so")))
        );
    }

    #[test]
    fn interpreter_path_ends_at_the_first_nul() {
        let bytes = elf(ELFCLASS64, ELFDATA2LSB, &[(PT_INTERP, b"/ld.so\0junk\0")]);
        assert_eq!(read_interpreter(&bytes), Ok(Some(PathBuf::from("/ld.so"))));
    }

    #[test]
    fn static_binary_has_no_interpreter() {
        let bytes = elf(ELFCLASS64, ELFDATA2LSB, &[(PT_LOAD, b"code")]);
        assert_eq!(read_interpreter(&bytes), Ok(None));
        let bytes = elf(ELFCLASS64, ELFDATA2LSB, &[]);
        assert_eq!(read_interpreter(&bytes), Ok(None));
    }

    #[test]
    fn non_elf_is_an_error() {
        for bytes in [
            &b""[..],
            b"\x7fEL",
            b"#!/bin/sh\necho hi\n",
            b"\0ELF\x02\x01",
        ] {
            assert_eq!(read_interpreter(bytes), Err(ElfError::NotElf), "{bytes:?}");
        }
    }

    #[test]
    fn thirty_two_bit_elf_is_unsupported() {
        let mut bytes = elf(ELFCLASS64, ELFDATA2LSB, &[(PT_INTERP, b"/ld.so\0")]);
        bytes[EI_CLASS] = ELFCLASS32;
        let err = read_interpreter(&bytes).unwrap_err();
        assert!(matches!(err, ElfError::Unsupported(_)), "{err}");
        assert!(err.to_string().contains("32-bit"), "{err}");
        // Even when shorter than an ELF64 header.
        assert_eq!(read_interpreter(&bytes[..52]), Err(err));
    }

    #[test]
    fn big_endian_elf_is_unsupported() {
        let bytes = elf(ELFCLASS64, ELFDATA2MSB, &[]);
        let err = read_interpreter(&bytes).unwrap_err();
        assert!(err.to_string().contains("big-endian"), "{err}");
    }

    #[test]
    fn invalid_class_or_encoding_is_malformed() {
        for (class, data) in [(0, ELFDATA2LSB), (3, ELFDATA2LSB), (ELFCLASS64, 0)] {
            let bytes = elf(class, data, &[]);
            assert!(
                matches!(read_interpreter(&bytes), Err(ElfError::Malformed(_))),
                "{class} {data}"
            );
        }
    }

    #[test]
    fn every_truncation_is_an_error() {
        let bytes = elf(
            ELFCLASS64,
            ELFDATA2LSB,
            &[(PT_LOAD, b""), (PT_INTERP, b"/lib/ld.so\0")],
        );
        // The interpreter path is the last thing in the file, so every
        // shorter prefix lacks some of it.
        for len in ELF_MAGIC.len()..bytes.len() {
            assert_eq!(
                read_interpreter(&bytes[..len]),
                Err(ElfError::Truncated),
                "length {len}"
            );
        }
    }

    #[test]
    fn offsets_past_the_end_are_truncation_not_panics() {
        let mut bytes = elf(ELFCLASS64, ELFDATA2LSB, &[(PT_INTERP, b"/ld.so\0")]);
        let phdr = EHDR64_SIZE;
        // Segment offset near u64::MAX: offset + size overflows.
        bytes[phdr + 8..phdr + 16].copy_from_slice(&(u64::MAX - 2).to_le_bytes());
        assert_eq!(read_interpreter(&bytes), Err(ElfError::Truncated));

        let mut bytes = elf(ELFCLASS64, ELFDATA2LSB, &[(PT_INTERP, b"/ld.so\0")]);
        // Program header table offset near u64::MAX.
        bytes[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(read_interpreter(&bytes), Err(ElfError::Truncated));
    }

    #[test]
    fn interpreter_without_nul_is_malformed() {
        let bytes = elf(ELFCLASS64, ELFDATA2LSB, &[(PT_INTERP, b"/lib/ld.so")]);
        assert!(matches!(
            read_interpreter(&bytes),
            Err(ElfError::Malformed(_))
        ));
    }

    #[test]
    fn relative_interpreter_is_an_error() {
        for path in [&b"ld.so\0"[..], b"\0"] {
            let bytes = elf(ELFCLASS64, ELFDATA2LSB, &[(PT_INTERP, path)]);
            assert!(
                matches!(
                    read_interpreter(&bytes),
                    Err(ElfError::RelativeInterpreter(_))
                ),
                "{path:?}"
            );
        }
    }

    #[test]
    fn small_program_header_entries_are_malformed() {
        let mut bytes = elf(ELFCLASS64, ELFDATA2LSB, &[(PT_INTERP, b"/ld.so\0")]);
        bytes[54..56].copy_from_slice(&32u16.to_le_bytes());
        assert!(matches!(
            read_interpreter(&bytes),
            Err(ElfError::Malformed(_))
        ));
    }

    #[test]
    fn extended_program_header_count_is_unsupported() {
        let mut bytes = elf(ELFCLASS64, ELFDATA2LSB, &[]);
        bytes[56..58].copy_from_slice(&PN_XNUM.to_le_bytes());
        assert!(matches!(
            read_interpreter(&bytes),
            Err(ElfError::Unsupported(_))
        ));
    }

    // --- List output ---

    fn lib(name: &str, path: &str) -> ListEntry {
        ListEntry::Library(Library {
            name: name.into(),
            path: path.into(),
        })
    }

    fn absolute(name: &str, path: &str) -> ListEntry {
        ListEntry::Absolute {
            name: name.into(),
            path: path.into(),
        }
    }

    #[test]
    fn parses_glibc_list_output() {
        let output = b"\tlinux-vdso.so.1 (0x00007ffd6c3e5000)\n\
            \tlibgcc_s.so.1 => /nix/store/abc-gcc-lib/lib/libgcc_s.so.1 (0x00007f1c2a8a0000)\n\
            \tlibc.so.6 => /nix/store/def-glibc/lib/libc.so.6 (0x00007f1c2a600000)\n\
            \t/nix/store/def-glibc/lib/ld-linux-x86-64.so.2 (0x00007f1c2a8d0000)\n";
        assert_eq!(
            parse_list(output),
            Ok(vec![
                lib("libgcc_s.so.1", "/nix/store/abc-gcc-lib/lib/libgcc_s.so.1"),
                lib("libc.so.6", "/nix/store/def-glibc/lib/libc.so.6"),
                absolute(
                    "/nix/store/def-glibc/lib/ld-linux-x86-64.so.2",
                    "/nix/store/def-glibc/lib/ld-linux-x86-64.so.2"
                ),
            ])
        );
    }

    #[test]
    fn parses_an_absolute_name_resolved_elsewhere() {
        let output = b"\t/lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x7f00)\n";
        assert_eq!(
            parse_list(output),
            Ok(vec![absolute(
                "/lib64/ld-linux-x86-64.so.2",
                "/usr/lib64/ld-linux-x86-64.so.2"
            )])
        );
    }

    #[test]
    fn skips_the_vdso_in_both_formats_and_lines_without_a_path() {
        let output = b"\tlinux-vdso.so.1 (0x00007ffd6c3e5000)\n\
            \tlinux-vdso.so.1 =>  (0x00007ffd6c3e5000)\n\
            \tlinux-gate.so.1 (0xf7f00000)\n\
            \n\
            \tstatically linked\n";
        assert_eq!(parse_list(output), Ok(vec![]));
    }

    #[test]
    fn tolerates_odd_whitespace() {
        let output =
            b"   libc.so.6   =>\t/lib/libc.so.6\t(0x1f)  \r\n\n\n  /lib/ld.so  (0xABCdef)\r\n";
        assert_eq!(
            parse_list(output),
            Ok(vec![
                lib("libc.so.6", "/lib/libc.so.6"),
                absolute("/lib/ld.so", "/lib/ld.so"),
            ])
        );
    }

    #[test]
    fn keeps_spaces_and_parentheses_inside_paths() {
        let output = b"\tlibx.so => /opt/my lib (v2)/libx.so (0x1000)\n";
        assert_eq!(
            parse_list(output),
            Ok(vec![lib("libx.so", "/opt/my lib (v2)/libx.so")])
        );
        // No address: nothing is stripped.
        assert_eq!(
            parse_list(b"libx.so => /opt/libx.so (0xzz)"),
            Ok(vec![lib("libx.so", "/opt/libx.so (0xzz)")])
        );
    }

    #[test]
    fn not_found_is_an_error() {
        let output = b"\tlibc.so.6 => /lib/libc.so.6 (0x1)\n\tlibmissing.so.3 => not found\n";
        assert_eq!(
            parse_list(output),
            Err(ListError::NotFound("libmissing.so.3".into()))
        );
    }

    #[test]
    fn relative_resolved_path_is_an_error() {
        let err = parse_list(b"\tlibx.so => lib/libx.so (0x1)\n").unwrap_err();
        assert_eq!(
            err,
            ListError::NotAbsolute {
                name: "libx.so".into(),
                path: "lib/libx.so".into(),
            }
        );
    }

    #[test]
    fn names_that_are_not_file_names_are_errors() {
        for name in ["sub/libx.so", ".", ".."] {
            let line = format!("\t{name} => /lib/libx.so (0x1)\n");
            assert_eq!(
                parse_list(line.as_bytes()),
                Err(ListError::BadName(name.into())),
                "{name}"
            );
        }
    }

    #[test]
    fn non_utf8_paths_are_kept() {
        let output = b"\tlib\xff.so => /lib/\xfe/lib\xff.so (0x1)\n";
        assert_eq!(
            parse_list(output),
            Ok(vec![ListEntry::Library(Library {
                name: OsStr::from_bytes(b"lib\xff.so").into(),
                path: PathBuf::from(OsStr::from_bytes(b"/lib/\xfe/lib\xff.so")),
            })])
        );
    }

    #[test]
    fn resolves_the_libraries_of_the_running_binary() {
        let exe = fs::canonicalize("/proc/self/exe").unwrap();
        let interp = read_interpreter(&fs::read(&exe).unwrap()).unwrap().unwrap();
        let libraries = resolve_libraries(&exe, &interp).unwrap();
        assert!(!libraries.is_empty());
        for library in &libraries {
            assert!(library.path.is_absolute(), "{library:?}");
            assert!(library.path.is_file(), "{library:?}");
            assert!(!same_file(&library.path, &interp), "{library:?}");
        }
        // A glibc binary needs libc. Its name is glibc-specific; the rest of
        // the test is not.
        assert!(
            libraries
                .iter()
                .any(|l| l.name.as_bytes().starts_with(b"libc.so")),
            "{libraries:?}"
        );
    }

    #[test]
    fn listing_a_non_elf_file_fails() {
        let exe = fs::canonicalize("/proc/self/exe").unwrap();
        let interp = read_interpreter(&fs::read(&exe).unwrap()).unwrap().unwrap();
        let tmp = TempDir::new().unwrap();
        let text = tmp.path().join("text");
        fs::write(&text, b"not a program\n").unwrap();
        let err = resolve_libraries(&text, &interp).unwrap_err();
        assert!(matches!(err, ProvisionError::ListFailed { .. }), "{err}");
        let msg = err.to_string();
        assert!(msg.contains("text"), "{msg}");
        assert!(
            msg.contains("stdout: ") && msg.contains("stderr: "),
            "{msg}"
        );
    }

    #[test]
    fn running_exe_is_the_canonical_binary() {
        assert_eq!(
            running_exe(Path::new("/proc/self/exe")).unwrap(),
            fs::canonicalize("/proc/self/exe").unwrap()
        );
    }

    #[test]
    fn deleted_running_exe_says_to_restart() {
        // The kernel's link text for a deleted binary, mimicked by a
        // dangling symlink.
        let tmp = TempDir::new().unwrap();
        let link = tmp.path().join("exe");
        symlink(tmp.path().join("stopit (deleted)"), &link).unwrap();
        let err = running_exe(&link).unwrap_err();
        match &err {
            ProvisionError::SelfReplaced { path } => {
                assert_eq!(path, &tmp.path().join("stopit"));
            }
            other => panic!("unexpected error: {other}"),
        }
        assert!(err.to_string().contains("restart stopit"), "{err}");
    }

    #[test]
    fn existing_file_named_deleted_is_not_mistaken_for_a_deleted_binary() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("stopit (deleted)");
        fs::write(&file, b"").unwrap();
        let link = tmp.path().join("exe");
        symlink(&file, &link).unwrap();
        assert_eq!(
            running_exe(&link).unwrap(),
            fs::canonicalize(&file).unwrap()
        );
    }

    #[test]
    fn missing_interpreter_is_a_spawn_error() {
        let tmp = TempDir::new().unwrap();
        let err =
            resolve_libraries(Path::new("/proc/self/exe"), &tmp.path().join("ld.so")).unwrap_err();
        assert!(matches!(err, ProvisionError::ListSpawn { .. }), "{err}");
        assert!(err.to_string().contains("ld.so"), "{err}");
    }

    // --- Copying ---

    /// Source files for `install`: an interpreter and two libraries.
    struct Sources {
        dir: TempDir,
    }

    impl Sources {
        fn new() -> Self {
            let dir = TempDir::new().unwrap();
            fs::write(dir.path().join("ld.so"), b"interpreter").unwrap();
            fs::write(dir.path().join("liba.so.1"), b"library a").unwrap();
            fs::write(dir.path().join("libb.so.2"), b"library b").unwrap();
            Sources { dir }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.dir.path().join(name)
        }

        fn lib(&self, name: &str, file: &str) -> Library {
            Library {
                name: name.into(),
                path: self.path(file),
            }
        }
    }

    #[test]
    fn installs_with_explicit_modes_and_names() {
        let src = Sources::new();
        let dest = TempDir::new().unwrap();
        let provisioned = install(
            b"the binary",
            Some(&src.path("ld.so")),
            &[
                src.lib("liba.so.1", "liba.so.1"),
                src.lib("libb.so.2", "libb.so.2"),
            ],
            dest.path(),
        )
        .unwrap();

        let lib_dir = dest.path().join("lib");
        assert_eq!(provisioned.exe(), dest.path().join("stopit"));
        assert_eq!(provisioned.lib_dir(), lib_dir);
        assert_eq!(provisioned.loader(), Some(lib_dir.join("ld.so").as_path()));

        assert_eq!(names(dest.path()), ["lib", "stopit"]);
        assert_eq!(names(&lib_dir), ["ld.so", "liba.so.1", "libb.so.2"]);
        assert_eq!(mode(&lib_dir), 0o700);
        assert_eq!(mode(provisioned.exe()), 0o500);
        assert_eq!(mode(&lib_dir.join("ld.so")), 0o500);
        assert_eq!(mode(&lib_dir.join("liba.so.1")), 0o400);
        assert_eq!(mode(&lib_dir.join("libb.so.2")), 0o400);
        assert_eq!(fs::read(provisioned.exe()).unwrap(), b"the binary");
        assert_eq!(fs::read(lib_dir.join("ld.so")).unwrap(), b"interpreter");
        assert_eq!(fs::read(lib_dir.join("liba.so.1")).unwrap(), b"library a");
    }

    #[test]
    fn copies_under_the_name_the_loader_asked_for() {
        let src = Sources::new();
        let dest = TempDir::new().unwrap();
        install(b"", None, &[src.lib("liba.so", "liba.so.1")], dest.path()).unwrap();
        assert_eq!(names(&dest.path().join("lib")), ["liba.so"]);
    }

    #[test]
    fn symlink_sources_are_copied_as_content() {
        let src = Sources::new();
        symlink(src.path("liba.so.1"), src.path("liba.so")).unwrap();
        symlink("ld.so", src.path("ld-link.so")).unwrap();
        let dest = TempDir::new().unwrap();
        let provisioned = install(
            b"",
            Some(&src.path("ld-link.so")),
            &[src.lib("liba.so", "liba.so")],
            dest.path(),
        )
        .unwrap();
        let lib_dir = provisioned.lib_dir();
        // The interpreter keeps the name it was asked for, too.
        assert_eq!(names(lib_dir), ["ld-link.so", "liba.so"]);
        for (name, content) in [
            ("ld-link.so", &b"interpreter"[..]),
            ("liba.so", b"library a"),
        ] {
            let path = lib_dir.join(name);
            assert!(fs::symlink_metadata(&path).unwrap().is_file(), "{name}");
            assert_eq!(fs::read(&path).unwrap(), content, "{name}");
        }
    }

    #[test]
    fn static_binary_gets_an_empty_lib_dir() {
        let dest = TempDir::new().unwrap();
        let provisioned = install(b"static", None, &[], dest.path()).unwrap();
        assert_eq!(provisioned.loader(), None);
        assert_eq!(names(provisioned.lib_dir()), Vec::<OsString>::new());
        assert_eq!(mode(provisioned.exe()), 0o500);
    }

    #[test]
    fn existing_binary_is_not_overwritten() {
        let dest = TempDir::new().unwrap();
        fs::write(dest.path().join("stopit"), b"old").unwrap();
        let err = install(b"new", None, &[], dest.path()).unwrap_err();
        match &err {
            ProvisionError::Write { path, source } => {
                assert_eq!(path, &dest.path().join("stopit"));
                assert_eq!(source.kind(), io::ErrorKind::AlreadyExists);
            }
            other => panic!("unexpected error: {other}"),
        }
        assert_eq!(fs::read(dest.path().join("stopit")).unwrap(), b"old");
    }

    #[test]
    fn existing_symlink_is_not_followed() {
        let outside = TempDir::new().unwrap();
        let target = outside.path().join("precious");
        fs::write(&target, b"keep me").unwrap();
        let dest = TempDir::new().unwrap();
        symlink(&target, dest.path().join("stopit")).unwrap();
        let err = install(b"new", None, &[], dest.path()).unwrap_err();
        assert!(matches!(err, ProvisionError::Write { .. }), "{err}");
        assert_eq!(fs::read(&target).unwrap(), b"keep me");
        // A dangling link is not followed to create its target either.
        let dest = TempDir::new().unwrap();
        let missing = outside.path().join("missing");
        symlink(&missing, dest.path().join("stopit")).unwrap();
        assert!(install(b"new", None, &[], dest.path()).is_err());
        assert!(!missing.exists());
    }

    #[test]
    fn existing_lib_dir_or_link_is_an_error() {
        let dest = TempDir::new().unwrap();
        fs::create_dir(dest.path().join("lib")).unwrap();
        let err = install(b"", None, &[], dest.path()).unwrap_err();
        assert!(matches!(err, ProvisionError::CreateDir { .. }), "{err}");

        let outside = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();
        symlink(outside.path(), dest.path().join("lib")).unwrap();
        let src = Sources::new();
        let err =
            install(b"", None, &[src.lib("liba.so.1", "liba.so.1")], dest.path()).unwrap_err();
        assert!(matches!(err, ProvisionError::CreateDir { .. }), "{err}");
        assert_eq!(names(outside.path()), Vec::<OsString>::new());
    }

    #[test]
    fn duplicate_names_are_an_error_before_anything_is_written() {
        let src = Sources::new();
        let dest = TempDir::new().unwrap();
        let err = install(
            b"",
            Some(&src.path("ld.so")),
            &[
                src.lib("liba.so.1", "liba.so.1"),
                src.lib("liba.so.1", "libb.so.2"),
            ],
            dest.path(),
        )
        .unwrap_err();
        match &err {
            ProvisionError::DuplicateName {
                name,
                first,
                second,
            } => {
                assert_eq!(name, "liba.so.1");
                assert_eq!(first, &src.path("liba.so.1"));
                assert_eq!(second, &src.path("libb.so.2"));
            }
            other => panic!("unexpected error: {other}"),
        }
        assert!(err.to_string().contains("libb.so.2"), "{err}");
        assert_eq!(names(dest.path()), Vec::<OsString>::new());
    }

    #[test]
    fn library_named_like_the_interpreter_is_a_duplicate() {
        let src = Sources::new();
        let dest = TempDir::new().unwrap();
        let err = install(
            b"",
            Some(&src.path("ld.so")),
            &[src.lib("ld.so", "liba.so.1")],
            dest.path(),
        )
        .unwrap_err();
        assert!(matches!(err, ProvisionError::DuplicateName { .. }), "{err}");
    }

    #[test]
    fn the_same_file_under_one_name_twice_is_copied_once() {
        let src = Sources::new();
        symlink("liba.so.1", src.path("liba-link")).unwrap();
        let dest = TempDir::new().unwrap();
        let provisioned = install(
            b"",
            Some(&src.path("ld.so")),
            &[
                src.lib("liba.so.1", "liba.so.1"),
                src.lib("liba.so.1", "liba-link"),
                src.lib("ld.so", "ld.so"),
            ],
            dest.path(),
        )
        .unwrap();
        assert_eq!(names(provisioned.lib_dir()), ["ld.so", "liba.so.1"]);
        // The interpreter keeps its executable mode.
        assert_eq!(mode(&provisioned.lib_dir().join("ld.so")), 0o500);
    }

    #[test]
    fn non_regular_source_is_an_error() {
        let src = Sources::new();
        fs::create_dir(src.path("libdir.so")).unwrap();
        let dest = TempDir::new().unwrap();
        let err =
            install(b"", None, &[src.lib("libdir.so", "libdir.so")], dest.path()).unwrap_err();
        assert!(
            matches!(err, ProvisionError::NotRegularFile { .. }),
            "{err}"
        );
    }

    #[test]
    fn missing_source_is_an_error_naming_it() {
        let src = Sources::new();
        let dest = TempDir::new().unwrap();
        let err = install(b"", None, &[src.lib("libz.so", "libz.so")], dest.path()).unwrap_err();
        assert!(matches!(err, ProvisionError::Read { .. }), "{err}");
        assert!(err.to_string().contains("libz.so"), "{err}");
    }

    // --- Command prefix ---

    #[test]
    fn command_prefix_runs_a_dynamic_binary_through_its_loader() {
        let provisioned = Provisioned {
            exe: "/host/session/stopit".into(),
            loader: Some("/host/session/lib/ld-linux-x86-64.so.2".into()),
            lib_dir: "/host/session/lib".into(),
        };
        assert_eq!(
            provisioned.command_prefix(Path::new(SANDBOX_RUNTIME_DIR)),
            [
                "/run/stopit/lib/ld-linux-x86-64.so.2",
                "--library-path",
                "/run/stopit/lib",
                "/run/stopit/stopit",
            ]
        );
    }

    #[test]
    fn command_prefix_runs_a_static_binary_directly() {
        let provisioned = Provisioned {
            exe: "/host/session/stopit".into(),
            loader: None,
            lib_dir: "/host/session/lib".into(),
        };
        assert_eq!(
            provisioned.command_prefix(Path::new("/run/stopit")),
            ["/run/stopit/stopit"]
        );
    }

    // --- End to end ---

    #[test]
    fn provisions_the_running_binary_into_a_session() {
        let tmp = fs::canonicalize(std::env::temp_dir()).unwrap();
        let runtime = TempDir::new_in(tmp).unwrap();
        fs::set_permissions(runtime.path(), Permissions::from_mode(0o700)).unwrap();
        let session = SessionDir::create(Some(runtime.path().as_os_str())).unwrap();

        let provisioned = provision_self(&session).unwrap();
        assert_eq!(provisioned.exe(), session.root().join("stopit"));
        assert_eq!(provisioned.lib_dir(), session.root().join("lib"));
        assert_eq!(
            fs::read(provisioned.exe()).unwrap(),
            fs::read("/proc/self/exe").unwrap()
        );
        let loader = provisioned.loader().expect("the test binary is dynamic");
        assert_eq!(loader.parent(), Some(provisioned.lib_dir()));
        assert!(names(provisioned.lib_dir()).len() > 1);

        // The copied test harness runs through the copied loader.
        let prefix = provisioned.command_prefix(session.root());
        let out = Command::new(&prefix[0])
            .args(&prefix[1..])
            .args(["--list", "provisions_the_running_binary_into_a_session"])
            .env_clear()
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        assert!(
            String::from_utf8_lossy(&out.stdout)
                .contains("provisions_the_running_binary_into_a_session"),
            "{out:?}"
        );

        // A second provisioning into the same session fails.
        assert!(provision_self(&session).is_err());
    }

    /// Panics and catches the panic. Trivial on the host; run by
    /// [`unwinding_works_with_only_the_copied_libraries`] inside a sandbox,
    /// where unwinding needs the copied `libgcc_s`.
    #[test]
    fn panic_is_caught() {
        let result = std::panic::catch_unwind(|| panic!("unwind me"));
        let payload = result.expect_err("the closure panics");
        assert_eq!(payload.downcast_ref::<&str>(), Some(&"unwind me"));
    }

    #[test]
    fn unwinding_works_with_only_the_copied_libraries() {
        let dir = TempDir::new().unwrap();
        let exe = fs::canonicalize("/proc/self/exe").unwrap();
        let provisioned = provision(&exe, dir.path()).unwrap();

        // libtest names tests without the crate name.
        let module = module_path!().split_once("::").unwrap().1;
        let test = format!("{module}::panic_is_caught");
        let result = Command::new("bwrap")
            .args(["--unshare-all", "--die-with-parent", "--clearenv"])
            .arg("--ro-bind")
            .arg(dir.path())
            .arg(SANDBOX_RUNTIME_DIR)
            .args(["--proc", "/proc", "--dev", "/dev", "--"])
            .args(provisioned.command_prefix(Path::new(SANDBOX_RUNTIME_DIR)))
            .args(["--exact", &test, "--test-threads=1"])
            .output();
        let out = match result {
            Ok(out) => out,
            Err(e) if e.kind() == io::ErrorKind::NotFound => panic!(
                "bwrap (bubblewrap) is not on PATH; this test needs it. \
                 Run the tests inside `nix develop`, which provides it."
            ),
            Err(e) => panic!("cannot run bwrap: {e}"),
        };
        assert!(out.status.success(), "{out:?}");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains(&format!("test {test} ... ok")), "{out:?}");
        assert!(stdout.contains("1 passed"), "{out:?}");
    }
}
