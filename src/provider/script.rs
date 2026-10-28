//! The `script` provider: a host executable that prints a manifest
//! (DESIGN.md §3.6).
//!
//! Protocol: the script is executed directly (no shell, no arguments) with
//! the directory of the declaring `.stopit.toml` as its current directory
//! and the supervisor's environment. It receives one JSON object on stdin:
//!
//! ```json
//! {
//!   "config": { "...": "the [provider.config] table" },
//!   "context": {
//!     "workspace": "/host/path", "workspace_mount": "/workspace",
//!     "home": "/home/user", "session_dir": "/run/...",
//!     "profile": "main", "name": "<provider name>"
//!   }
//! }
//! ```
//!
//! and prints a JSON manifest, which must declare `version`, on stdout. A
//! non-zero exit or an invalid manifest is an error, which aborts startup.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::OnceLock;
use std::thread;

use rustix::process::{Pid, Signal, kill_process_group};
use serde_json::{Map, Number, Value};

use super::{Provider, ProviderContext, ProviderError, ProviderOutput};
use crate::config::{ProfileRef, ProviderName, ScriptSource};
use crate::escape::escape_message;
use crate::manifest::Manifest;

/// Maximum size of a script's stdout; more is an error.
pub const STDOUT_LIMIT: usize = 16 * 1024 * 1024;

/// Maximum amount of a script's stderr kept for error messages; the rest is
/// read and discarded.
pub const STDERR_LIMIT: usize = 64 * 1024;

/// Runs a host executable and parses the manifest it prints.
///
/// **The script runs on the host with the user's privileges**, on purpose
/// (e.g. to call `nix`). It inherits the supervisor's environment.
///
/// The script runs in its own session (`setsid`), which also makes it the
/// leader of a new process group, and has **no controlling terminal**: it
/// cannot prompt interactively. Anything that opens `/dev/tty` (an ssh
/// passphrase, a git credential prompt) fails immediately (ENXIO) with a
/// readable error on stderr, instead of being stopped by SIGTTIN in a
/// background process group and hanging startup silently. When its output
/// exceeds the limit (or cannot be read), the script's whole process group
/// is killed.
///
/// Because the script is not in the terminal's foreground process group,
/// Ctrl-C (SIGINT) reaches only the supervisor. Once the supervisor handles
/// SIGINT/SIGTERM, it must kill the script's process group itself (tracked
/// follow-up); until then an interrupted supervisor leaves a running script
/// behind.
///
/// There is deliberately no timeout: a first `nix` evaluation can
/// legitimately take minutes. A script that never exits blocks startup, and
/// so does a background process it leaves behind that holds its stdout or
/// stderr open, or holds its stdin open without reading it.
#[derive(Debug, Clone)]
pub struct ScriptProvider {
    name: ProviderName,
    /// `source` joined to `base_dir`, as declared; used in error messages.
    source: PathBuf,
    /// The canonical form of `source`: both the executed and the protected
    /// file. Resolved on first use.
    canonical: OnceLock<PathBuf>,
    base_dir: PathBuf,
    protect: bool,
    config: toml::Table,
}

impl ScriptProvider {
    /// Creates a provider for `source`, declared in a configuration file in
    /// `base_dir`.
    ///
    /// A relative `source` is resolved against `base_dir`; an absolute one is
    /// used as is. `base_dir` is also the script's current directory; it
    /// should be absolute (a relative one is made absolute against the
    /// supervisor's current directory). The filesystem is not consulted
    /// here: the path is canonicalized on first use.
    pub fn new(
        name: ProviderName,
        source: &ScriptSource,
        base_dir: &Path,
        protect: bool,
        config: toml::Table,
    ) -> Self {
        ScriptProvider {
            name,
            source: base_dir.join(source.as_path()),
            canonical: OnceLock::new(),
            base_dir: base_dir.to_owned(),
            protect,
            config,
        }
    }

    /// The canonical script path (no `.`, `..` or symlinks), resolved once
    /// and cached, so the file that is protected is exactly the file that
    /// is executed. Protecting a symlink would leave its target writable.
    fn canonical_source(&self) -> Result<&Path, ProviderError> {
        if let Some(p) = self.canonical.get() {
            return Ok(p);
        }
        let resolved = fs::canonicalize(&self.source).map_err(|error| {
            self.base_dir_error()
                .unwrap_or_else(|| ProviderError::Resolve {
                    name: self.name.clone(),
                    script: self.source.clone(),
                    error,
                })
        })?;
        // A concurrent caller may have won the race; both resolved the same
        // path modulo filesystem changes, and the first one is kept.
        let _ = self.canonical.set(resolved);
        Ok(self.canonical.get().expect("just set"))
    }

    /// An error blaming `base_dir` if it is not an accessible directory.
    fn base_dir_error(&self) -> Option<ProviderError> {
        let error = match fs::metadata(&self.base_dir) {
            Ok(m) if m.is_dir() => return None,
            Ok(_) => io::Error::from(io::ErrorKind::NotADirectory),
            Err(e) => e,
        };
        Some(ProviderError::BaseDir {
            name: self.name.clone(),
            script: self.source.clone(),
            dir: self.base_dir.clone(),
            error,
        })
    }

    /// Builds the JSON document written to the script's stdin.
    fn stdin_json(&self, ctx: &ProviderContext) -> Result<Value, ProviderError> {
        let path = |field: &'static str, p: &Path| -> Result<Value, ProviderError> {
            match p.to_str() {
                Some(s) => Ok(Value::String(s.to_owned())),
                None => Err(ProviderError::NonUtf8Path {
                    name: self.name.clone(),
                    script: self.source.clone(),
                    field,
                    path: p.to_owned(),
                }),
            }
        };
        let mut context = Map::new();
        context.insert("workspace".into(), path("workspace", &ctx.workspace)?);
        context.insert(
            "workspace_mount".into(),
            path("workspace_mount", ctx.workspace_mount.as_path())?,
        );
        context.insert("home".into(), path("home", &ctx.home)?);
        context.insert("session_dir".into(), path("session_dir", &ctx.session_dir)?);
        context.insert(
            "profile".into(),
            Value::String(ProfileRef::main().as_str().to_owned()),
        );
        context.insert("name".into(), Value::String(self.name.as_str().to_owned()));

        let config = table_to_json(&self.config, "").map_err(|(key, reason)| {
            ProviderError::ConfigNotJson {
                name: self.name.clone(),
                script: self.source.clone(),
                key,
                reason,
            }
        })?;

        let mut doc = Map::new();
        doc.insert("config".into(), config);
        doc.insert("context".into(), Value::Object(context));
        Ok(Value::Object(doc))
    }

    /// Runs the script with `input` on stdin and returns its stdout.
    ///
    /// When several things go wrong, the error reported is the first of:
    /// stdout too large or unreadable; waiting for the script failed; the
    /// script exited unsuccessfully (with whatever stderr was captured);
    /// reading stderr failed; writing stdin failed (other than the script
    /// not reading it, which is fine).
    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>, ProviderError> {
        let spawn_err = |error| {
            self.base_dir_error()
                .unwrap_or_else(|| ProviderError::Spawn {
                    name: self.name.clone(),
                    script: self.source.clone(),
                    error,
                })
        };
        let io_err = |error| ProviderError::Io {
            name: self.name.clone(),
            script: self.source.clone(),
            error,
        };
        // The canonical path is absolute. A relative `current_dir` would make
        // a relative program path ambiguous; it is made absolute anyway.
        let program = self.canonical_source()?;
        let cwd = std::path::absolute(&self.base_dir).map_err(spawn_err)?;
        let mut cmd = Command::new(program);
        cmd.current_dir(&cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: the closure runs in the forked child before `exec`, where
        // only async-signal-safe operations are allowed. It only calls
        // `setsid(2)`, which is async-signal-safe (POSIX), through rustix's
        // raw syscall wrapper: no allocation, no locks. Converting the
        // `Errno` into `io::Error` is a plain integer wrap (the `Os`
        // representation), which does not allocate either.
        unsafe {
            cmd.pre_exec(|| rustix::process::setsid().map(drop).map_err(io::Error::from));
        }
        let mut child = cmd.spawn().map_err(spawn_err)?;
        let mut stdin = child.stdin.take().expect("stdin is piped");
        let mut stdout = child.stdout.take().expect("stdout is piped");
        let mut stderr = child.stderr.take().expect("stderr is piped");

        // stdin is written and stderr drained on their own threads, so a
        // script that ignores stdin, or fills one pipe while we wait on
        // another, cannot deadlock the supervisor.
        thread::scope(|s| {
            let writer = s.spawn(move || {
                // `stdin` is dropped (closed) when this closure returns. A
                // script may exit without reading its input: not an error.
                // (std ignores SIGPIPE in Rust binaries, so this surfaces as
                // `BrokenPipe` rather than killing the supervisor.)
                match stdin.write_all(&input) {
                    Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
                    r => r,
                }
            });
            let err_reader = s.spawn(move || read_stderr(&mut stderr));

            let out = read_capped(&mut stdout, STDOUT_LIMIT);
            drop(stdout);
            if !matches!(out, Ok(Some(_))) {
                // Too much output or a read error: stop the script and
                // anything it started.
                kill_group(&child);
            }
            let status = child.wait();
            let written = writer.join().expect("stdin writer panicked");
            let stderr = err_reader.join().expect("stderr reader panicked");

            let out = match out.map_err(io_err)? {
                Some(out) => out,
                None => {
                    return Err(ProviderError::StdoutTooLarge {
                        name: self.name.clone(),
                        script: self.source.clone(),
                        limit: STDOUT_LIMIT,
                    });
                }
            };
            let status = status.map_err(io_err)?;
            if !status.success() {
                let stderr = stderr.unwrap_or_else(|e| format!("[could not read stderr: {e}]"));
                return Err(ProviderError::Failed {
                    name: self.name.clone(),
                    script: self.source.clone(),
                    status,
                    stderr,
                });
            }
            stderr.map_err(io_err)?;
            written.map_err(io_err)?;
            Ok(out)
        })
    }
}

impl Provider for ScriptProvider {
    fn name(&self) -> &ProviderName {
        &self.name
    }

    /// The canonical script path when `protect` is true, otherwise nothing.
    ///
    /// Protecting the script's directory (for scripts that source other
    /// files, DESIGN.md §3.6) is not implemented yet.
    fn protected_paths(&self) -> Result<Vec<PathBuf>, ProviderError> {
        if self.protect {
            Ok(vec![self.canonical_source()?.to_owned()])
        } else {
            Ok(Vec::new())
        }
    }

    /// Runs the script and parses its manifest. The grants apply to `main`.
    fn manifest(&self, ctx: &ProviderContext) -> Result<ProviderOutput, ProviderError> {
        let input = serde_json::to_vec(&self.stdin_json(ctx)?)
            .expect("serializing a serde_json::Value cannot fail");
        let out = self.run(input)?;
        let text = String::from_utf8(out).map_err(|error| ProviderError::StdoutNotUtf8 {
            name: self.name.clone(),
            script: self.source.clone(),
            error,
        })?;
        let manifest =
            Manifest::from_json_str(&text).map_err(|error| ProviderError::InvalidManifest {
                name: self.name.clone(),
                script: self.source.clone(),
                error,
            })?;
        Ok(ProviderOutput {
            profile: ProfileRef::main(),
            manifest,
        })
    }
}

/// Reads `r` to the end, or returns `None` as soon as more than `limit`
/// bytes have been read.
fn read_capped(r: &mut impl Read, limit: usize) -> io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();
    r.take(limit as u64 + 1).read_to_end(&mut buf)?;
    Ok((buf.len() <= limit).then_some(buf))
}

/// Sends SIGKILL to the child's process group (the child leads it: `setsid`
/// creates a new session and process group). The child is not reaped yet, so its pid, which is
/// the group id, cannot have been reused. Errors are ignored: the group may
/// already be gone.
fn kill_group(child: &Child) {
    let _ = kill_process_group(Pid::from_child(child), Signal::KILL);
}

/// Reads stderr to the end, keeping the first [`STDERR_LIMIT`] bytes, as
/// trimmed (lossy) text with a marker when the rest was discarded.
///
/// Control and format characters other than `\n` and `\t` are escaped
/// ([`escape_message`], `\u{1b}`): the text ends up on the host terminal,
/// and stderr may echo content the sandbox can write, so it must not carry
/// terminal escape sequences (DESIGN.md §5.3). The supervisor escapes every
/// message it prints again; escaping here keeps the error's own text safe
/// for any other caller.
fn read_stderr(r: &mut impl Read) -> io::Result<String> {
    let mut buf = Vec::new();
    r.take(STDERR_LIMIT as u64).read_to_end(&mut buf)?;
    let discarded = io::copy(r, &mut io::sink())?;
    let mut text = escape_message(String::from_utf8_lossy(&buf).trim());
    if discarded > 0 {
        text.push_str(&format!(" [... {discarded} more bytes discarded]"));
    }
    Ok(text)
}

/// Converts a TOML table to JSON. `path` is the dotted key path of the table
/// (empty at the top level), used to name an unrepresentable value.
///
/// Every TOML value maps to its natural JSON counterpart, except datetimes,
/// which become strings in their TOML form: RFC 3339 for offset date-times
/// (`1979-05-27T07:32:00Z`), and the RFC 3339 partial forms for local
/// date-times, dates and times. Floats that JSON cannot represent (`nan`,
/// `inf`) are an error.
fn table_to_json(table: &toml::Table, path: &str) -> Result<Value, (String, &'static str)> {
    let mut map = Map::new();
    for (k, v) in table {
        let key = if path.is_empty() {
            k.clone()
        } else {
            format!("{path}.{k}")
        };
        map.insert(k.clone(), value_to_json(v, &key)?);
    }
    Ok(Value::Object(map))
}

fn value_to_json(v: &toml::Value, path: &str) -> Result<Value, (String, &'static str)> {
    Ok(match v {
        toml::Value::String(s) => Value::String(s.clone()),
        toml::Value::Integer(i) => Value::Number((*i).into()),
        toml::Value::Float(f) => match Number::from_f64(*f) {
            Some(n) => Value::Number(n),
            None => {
                return Err((
                    path.to_owned(),
                    "JSON cannot represent NaN or infinite floats",
                ));
            }
        },
        toml::Value::Boolean(b) => Value::Bool(*b),
        toml::Value::Datetime(d) => Value::String(d.to_string()),
        toml::Value::Array(items) => Value::Array(
            items
                .iter()
                .enumerate()
                .map(|(i, item)| value_to_json(item, &format!("{path}[{i}]")))
                .collect::<Result<_, _>>()?,
        ),
        toml::Value::Table(t) => table_to_json(t, path)?,
    })
}

/// Describes how a script exited unsuccessfully.
pub(super) fn describe_status(status: &ExitStatus) -> String {
    if let Some(code) = status.code() {
        return format!("exited with code {code}");
    }
    if let Some(sig) = status.signal() {
        let name = match sig {
            1 => " (SIGHUP)",
            2 => " (SIGINT)",
            3 => " (SIGQUIT)",
            4 => " (SIGILL)",
            6 => " (SIGABRT)",
            7 => " (SIGBUS)",
            8 => " (SIGFPE)",
            9 => " (SIGKILL)",
            11 => " (SIGSEGV)",
            13 => " (SIGPIPE)",
            14 => " (SIGALRM)",
            15 => " (SIGTERM)",
            _ => "",
        };
        return format!("was killed by signal {sig}{name}");
    }
    format!("exited unsuccessfully ({status})")
}

/// Formats captured stderr for an error message.
pub(super) fn describe_stderr(stderr: &str) -> String {
    if stderr.is_empty() {
        "; stderr was empty".to_owned()
    } else {
        format!("; stderr:\n{stderr}")
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::RwLock;

    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::config::{Config, ProviderKind};

    /// Writing an executable while another test thread forks can leave a
    /// write descriptor open in the child for a moment, making `exec` of the
    /// new file fail with ETXTBSY. Scripts are written under the write lock
    /// and run under the read lock, so no fork overlaps a write.
    static EXEC_LOCK: RwLock<()> = RwLock::new(());

    fn write_script(dir: &Path, file: &str, body: &str) -> PathBuf {
        let _guard = EXEC_LOCK.write().unwrap_or_else(|e| e.into_inner());
        let path = dir.join(file);
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn ctx() -> ProviderContext {
        ProviderContext {
            workspace: PathBuf::from("/w/proj"),
            workspace_mount: "/workspace".parse().unwrap(),
            home: PathBuf::from("/home/u"),
            session_dir: PathBuf::from("/run/s"),
        }
    }

    fn provider(name: &str, source: &str, base_dir: &Path) -> ScriptProvider {
        ScriptProvider::new(
            name.parse().unwrap(),
            &source.parse().unwrap(),
            base_dir,
            true,
            toml::Table::new(),
        )
    }

    fn run(p: &ScriptProvider) -> Result<ProviderOutput, ProviderError> {
        let _guard = EXEC_LOCK.read().unwrap_or_else(|e| e.into_inner());
        p.manifest(&ctx())
    }

    /// A temp dir with `run.sh` containing `body`, and a provider for it.
    fn setup(body: &str) -> (TempDir, ScriptProvider) {
        let dir = TempDir::new().unwrap();
        write_script(dir.path(), "run.sh", &format!("#!/bin/sh\n{body}"));
        let p = provider("env", "run.sh", dir.path());
        (dir, p)
    }

    fn err(body: &str) -> (TempDir, ProviderError) {
        let (dir, p) = setup(body);
        let e = run(&p).expect_err("the script should fail");
        (dir, e)
    }

    #[test]
    fn prints_a_manifest() {
        let (_dir, p) = setup(
            "printf '%s' '{\"version\": 1, \"fs\": {\"ro\": [\"/etc/ssl/certs\"]}, \
             \"env\": {\"set\": {\"LANG\": \"C.UTF-8\"}}, \"profiles\": {\"local\": {}}}'\n",
        );
        let out = run(&p).unwrap();
        assert_eq!(out.profile, ProfileRef::main());
        let expected = Manifest::from_json_str(
            r#"{"version": 1, "fs": {"ro": ["/etc/ssl/certs"]},
                "env": {"set": {"LANG": "C.UTF-8"}}, "profiles": {"local": {}}}"#,
        )
        .unwrap();
        assert_eq!(out.manifest, expected);
        assert_eq!(out.manifest.grants.fs.ro.len(), 1);
        assert_eq!(p.name().as_str(), "env");
    }

    #[test]
    fn stdin_json_and_cwd() {
        let dir = TempDir::new().unwrap();
        write_script(
            dir.path(),
            "run.sh",
            "#!/bin/sh\ncat > ./stdin.json\nprintf '{\"version\":1}'\n",
        );
        let cfg = Config::from_toml_str(
            r#"
            [[provider]]
            type = "script"
            name = "agent-env"
            source = "run.sh"
            [provider.config]
            s = "str \"quoted\" ünï"
            i = -42
            big = 9223372036854775807
            f = 2.5
            t = true
            no = false
            arr = [1, "two", [3.5], { k = "v" }]
            empty = []
            odt = 1979-05-27T07:32:00Z
            odt_off = 1979-05-27T00:32:00.5-07:00
            ldt = 1979-05-27T07:32:00
            ld = 1979-05-27
            lt = 07:32:00
            [provider.config.nested]
            deep = { x = 1 }
            "#,
        )
        .unwrap();
        let e = &cfg.providers[0];
        let ProviderKind::Script {
            source,
            protect,
            config,
        } = &e.kind
        else {
            panic!("{:?}", e.kind);
        };
        let p = ScriptProvider::new(e.name.clone(), source, dir.path(), *protect, config.clone());
        run(&p).unwrap();
        let got: Value =
            serde_json::from_slice(&fs::read(dir.path().join("stdin.json")).unwrap()).unwrap();
        assert_eq!(
            got,
            json!({
                "config": {
                    "s": "str \"quoted\" ünï",
                    "i": -42,
                    "big": 9223372036854775807_i64,
                    "f": 2.5,
                    "t": true,
                    "no": false,
                    "arr": [1, "two", [3.5], {"k": "v"}],
                    "empty": [],
                    "odt": "1979-05-27T07:32:00Z",
                    "odt_off": "1979-05-27T00:32:00.5-07:00",
                    "ldt": "1979-05-27T07:32:00",
                    "ld": "1979-05-27",
                    "lt": "07:32:00",
                    "nested": {"deep": {"x": 1}},
                },
                "context": {
                    "workspace": "/w/proj",
                    "workspace_mount": "/workspace",
                    "home": "/home/u",
                    "session_dir": "/run/s",
                    "profile": "main",
                    "name": "agent-env",
                },
            })
        );
    }

    #[test]
    fn empty_config_is_an_empty_object() {
        let (dir, p) = setup("cat > ./stdin.json\nprintf '{\"version\":1}'\n");
        run(&p).unwrap();
        let got: Value =
            serde_json::from_slice(&fs::read(dir.path().join("stdin.json")).unwrap()).unwrap();
        assert_eq!(got["config"], json!({}));
        assert_eq!(got["context"]["name"], "env");
    }

    #[test]
    fn unrepresentable_floats_are_errors() {
        for (src, key) in [
            ("x = nan", "x"),
            ("a = { b = [1.0, inf] }", "a.b[1]"),
            ("[t]\nn = -inf", "t.n"),
        ] {
            let config: toml::Table = src.parse().unwrap();
            let p = ScriptProvider::new(
                "s".parse().unwrap(),
                &"/nonexistent/x.sh".parse().unwrap(),
                Path::new("/"),
                true,
                config,
            );
            // Fails before anything is spawned.
            let msg = run(&p).unwrap_err().to_string();
            assert!(msg.contains(&format!("{key:?}")), "{src:?}: {msg}");
            assert!(msg.contains("\"s\""), "{msg}");
            assert!(msg.contains("/nonexistent/x.sh"), "{msg}");
            assert!(msg.contains("NaN"), "{msg}");
        }
    }

    #[test]
    fn non_utf8_context_paths_are_errors() {
        let bad = PathBuf::from(OsStr::from_bytes(b"/w/\xffx"));
        let p = provider("s", "/nonexistent/x.sh", Path::new("/"));
        for field in ["workspace", "home", "session_dir"] {
            let mut c = ctx();
            match field {
                "workspace" => c.workspace = bad.clone(),
                "home" => c.home = bad.clone(),
                _ => c.session_dir = bad.clone(),
            }
            let msg = p.manifest(&c).unwrap_err().to_string();
            assert!(msg.contains(field), "{field}: {msg}");
            assert!(msg.contains("UTF-8"), "{field}: {msg}");
            assert!(msg.contains("\"s\""), "{field}: {msg}");
        }
    }

    #[test]
    fn relative_source_is_resolved_against_base_dir() {
        let dir = TempDir::new().unwrap();
        fs::create_dir(dir.path().join("scripts")).unwrap();
        write_script(
            &dir.path().join("scripts"),
            "gen.sh",
            "#!/bin/sh\nprintf '{\"version\":1,\"fs\":{\"ro\":[\"/rel\"]}}'\n",
        );
        let canonical = fs::canonicalize(dir.path()).unwrap().join("scripts/gen.sh");
        let p = provider("s", "scripts/gen.sh", dir.path());
        assert_eq!(
            p.protected_paths().unwrap(),
            std::slice::from_ref(&canonical)
        );
        let out = run(&p).unwrap();
        assert_eq!(out.manifest.grants.fs.ro.len(), 1);

        // `.` and `..` are normalized away.
        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();
        let p = provider("s", "./../scripts/./gen.sh", &sub);
        assert_eq!(p.protected_paths().unwrap(), [canonical]);
        run(&p).unwrap();
    }

    #[test]
    fn symlinked_script_protects_and_runs_the_target() {
        let dir = TempDir::new().unwrap();
        fs::create_dir(dir.path().join("real")).unwrap();
        let a = write_script(
            &dir.path().join("real"),
            "a.sh",
            "#!/bin/sh\nprintf '{\"version\":1,\"fs\":{\"ro\":[\"/a\"]}}'\n",
        );
        let b = write_script(
            &dir.path().join("real"),
            "b.sh",
            "#!/bin/sh\nprintf '{\"version\":1,\"fs\":{\"ro\":[\"/b\"],\"rw\":[\"/b\"]}}'\n",
        );
        let link = dir.path().join("link.sh");
        std::os::unix::fs::symlink("real/a.sh", &link).unwrap();
        let p = provider("s", "link.sh", dir.path());
        // The target is protected, not the symlink.
        assert_eq!(
            p.protected_paths().unwrap(),
            [fs::canonicalize(&a).unwrap()]
        );

        // The resolution is cached: repointing the symlink afterwards does
        // not change which file runs, so the protected file is the executed
        // one.
        fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&b, &link).unwrap();
        let out = run(&p).unwrap();
        assert_eq!(out.manifest.grants.fs.ro.len(), 1);
        assert!(out.manifest.grants.fs.rw.is_empty(), "ran b.sh");
        assert_eq!(
            p.protected_paths().unwrap(),
            [fs::canonicalize(&a).unwrap()]
        );

        // A fresh provider resolves the new target, also when it runs first.
        let p = provider("s", "link.sh", dir.path());
        assert_eq!(run(&p).unwrap().manifest.grants.fs.rw.len(), 1);
        assert_eq!(
            p.protected_paths().unwrap(),
            [fs::canonicalize(&b).unwrap()]
        );
    }

    #[test]
    fn dangling_symlink_is_a_resolve_error() {
        let dir = TempDir::new().unwrap();
        std::os::unix::fs::symlink("missing.sh", dir.path().join("link.sh")).unwrap();
        let p = provider("s", "link.sh", dir.path());
        let e = p.protected_paths().unwrap_err();
        assert!(matches!(e, ProviderError::Resolve { .. }), "{e:?}");
        assert!(e.to_string().contains("link.sh"), "{e}");
    }

    #[test]
    fn absolute_source_is_used_as_is() {
        let scripts = TempDir::new().unwrap();
        let other = TempDir::new().unwrap();
        let abs = write_script(
            scripts.path(),
            "gen.sh",
            "#!/bin/sh\npwd > ./cwd.txt\nprintf '{\"version\":1}'\n",
        );
        let p = provider("s", abs.to_str().unwrap(), other.path());
        assert_eq!(
            p.protected_paths().unwrap(),
            [fs::canonicalize(&abs).unwrap()]
        );
        run(&p).unwrap();
        // The current directory is still `base_dir`.
        let cwd = fs::read_to_string(other.path().join("cwd.txt")).unwrap();
        assert_eq!(
            fs::canonicalize(cwd.trim()).unwrap(),
            fs::canonicalize(other.path()).unwrap()
        );
    }

    #[test]
    fn non_zero_exit() {
        let (_dir, e) = err("echo 'nix: evaluation failed' >&2\necho junk\nexit 3\n");
        assert!(matches!(e, ProviderError::Failed { .. }), "{e:?}");
        let msg = e.to_string();
        assert!(msg.contains("exited with code 3"), "{msg}");
        assert!(msg.contains("stderr:\nnix: evaluation failed"), "{msg}");
        // Trimmed.
        assert!(msg.ends_with("evaluation failed"), "{msg:?}");
        assert!(msg.contains("\"env\""), "{msg}");
        assert!(msg.contains("run.sh"), "{msg}");

        let (_dir, e) = err("exit 1\n");
        let msg = e.to_string();
        assert!(msg.contains("exited with code 1"), "{msg}");
        assert!(msg.contains("stderr was empty"), "{msg}");
    }

    #[test]
    fn non_zero_exit_with_a_valid_manifest_still_fails() {
        let (_dir, e) = err("printf '{\"version\":1}'\nexit 2\n");
        assert!(e.to_string().contains("code 2"), "{e}");
    }

    #[test]
    fn killed_by_signal() {
        let (_dir, e) = err("echo dying >&2\nkill -9 $$\n");
        let msg = e.to_string();
        assert!(msg.contains("signal 9 (SIGKILL)"), "{msg}");
        assert!(msg.contains("dying"), "{msg}");
    }

    #[test]
    fn invalid_manifests() {
        for (body, needle) in [
            ("printf 'not json'", "expected"),
            ("printf ''", "EOF"),
            ("printf '[]'", "map"),
            ("printf '{\"fs\": {}}'", "missing field `version`"),
            (
                "printf '{\"version\": 2}'",
                "unsupported manifest version 2",
            ),
            ("printf '{\"version\": 1, \"bogus\": {}}'", "bogus"),
        ] {
            let (_dir, e) = err(body);
            assert!(
                matches!(e, ProviderError::InvalidManifest { .. }),
                "{body}: {e:?}"
            );
            let msg = e.to_string();
            assert!(msg.contains("invalid manifest"), "{body}: {msg}");
            assert!(msg.contains(needle), "{body}: {msg}");
            assert!(msg.contains("\"env\""), "{body}: {msg}");
            assert!(msg.contains("run.sh"), "{body}: {msg}");
        }
    }

    #[test]
    fn stdout_must_be_utf8() {
        let (_dir, e) = err("printf '{\"version\":1,\"x\":\"\\377\"}'\n");
        assert!(matches!(e, ProviderError::StdoutNotUtf8 { .. }), "{e:?}");
        assert!(e.to_string().contains("UTF-8"), "{e}");
    }

    #[test]
    fn missing_script() {
        let dir = TempDir::new().unwrap();
        let p = provider("env", "nope.sh", dir.path());
        for e in [run(&p).unwrap_err(), p.protected_paths().unwrap_err()] {
            let ProviderError::Resolve { error, .. } = &e else {
                panic!("{e:?}");
            };
            assert_eq!(error.kind(), io::ErrorKind::NotFound);
            let msg = e.to_string();
            assert!(msg.contains("cannot resolve"), "{msg}");
            assert!(msg.contains("nope.sh"), "{msg}");
            assert!(msg.contains("\"env\""), "{msg}");
        }
    }

    #[test]
    fn base_dir_that_is_a_file() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("f");
        fs::write(&file, "").unwrap();
        let p = provider("env", "/bin/sh", &file);
        // The (absolute) script resolves, but the working directory is bad.
        let e = run(&p).unwrap_err();
        let ProviderError::BaseDir { dir: d, error, .. } = &e else {
            panic!("{e:?}");
        };
        assert_eq!(d, &file);
        assert_eq!(error.kind(), io::ErrorKind::NotADirectory);
        assert!(e.to_string().contains("its directory"), "{e}");
    }

    #[test]
    fn script_that_is_not_executable() {
        let dir = TempDir::new().unwrap();
        let path = write_script(
            dir.path(),
            "run.sh",
            "#!/bin/sh\nprintf '{\"version\":1}'\n",
        );
        {
            let _guard = EXEC_LOCK.write().unwrap_or_else(|e| e.into_inner());
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        }
        let p = provider("env", "run.sh", dir.path());
        let e = run(&p).unwrap_err();
        let ProviderError::Spawn { error, .. } = &e else {
            panic!("{e:?}");
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(e.to_string().contains("run.sh"), "{e}");
    }

    /// Shell snippet setting `$s` to 1 MiB of `x`, without external tools.
    const MIB: &str = "s=x\ni=0\nwhile [ $i -lt 20 ]; do s=\"$s$s\"; i=$((i+1)); done\n";

    #[test]
    fn large_io_without_reading_stdin_does_not_deadlock() {
        let dir = TempDir::new().unwrap();
        write_script(
            dir.path(),
            "run.sh",
            &format!(
                "#!/bin/sh\n{MIB}printf '{{\"version\":1,\"env\":{{\"set\":{{\"PAD\":\"%s\"}}}}}}' \"$s\"\n\
                 printf '%s' \"$s\" >&2\n"
            ),
        );
        // Much more input than a pipe buffer holds, never read.
        let mut config = toml::Table::new();
        config.insert("pad".into(), "y".repeat(4 << 20).into());
        let p = ScriptProvider::new(
            "env".parse().unwrap(),
            &"run.sh".parse().unwrap(),
            dir.path(),
            true,
            config,
        );
        let out = run(&p).unwrap();
        let (_, pad) = out.manifest.grants.env.set.iter().next().unwrap();
        assert_eq!(pad.as_str().len(), 1 << 20);
    }

    #[test]
    fn stdout_over_the_limit() {
        let (_dir, e) = err(&format!(
            "{MIB}printf '{{\"version\":1,\"x\":\"'\nj=0\nwhile [ $j -lt 17 ]; do printf '%s' \"$s\"; j=$((j+1)); done\n"
        ));
        assert!(matches!(e, ProviderError::StdoutTooLarge { .. }), "{e:?}");
        let msg = e.to_string();
        assert!(msg.contains(&STDOUT_LIMIT.to_string()), "{msg}");
        assert!(msg.contains("run.sh"), "{msg}");
    }

    #[test]
    fn stdout_at_the_limit_is_read() {
        // Exactly the limit is accepted (and then rejected as a manifest).
        let (_dir, e) = err(&format!(
            "{MIB}j=0\nwhile [ $j -lt 16 ]; do printf '%s' \"$s\"; j=$((j+1)); done\n"
        ));
        assert!(matches!(e, ProviderError::InvalidManifest { .. }), "{e:?}");
    }

    #[test]
    fn overflow_kills_the_whole_process_group() {
        // The background `sleep` holds stdout and stderr open; unless it is
        // killed too, reading them would block for 30 seconds.
        let (_dir, e) = err(&format!(
            "sleep 30 &\n{MIB}j=0\nwhile [ $j -lt 17 ]; do printf '%s' \"$s\"; j=$((j+1)); done\n"
        ));
        assert!(matches!(e, ProviderError::StdoutTooLarge { .. }), "{e:?}");
    }

    #[test]
    fn script_leads_its_own_session_and_process_group() {
        // /proc/<pid>/stat: pid (comm) state ppid pgrp session tty_nr ...
        // (`comm` is "run.sh", without spaces). tty_nr 0 means no
        // controlling terminal.
        let (_dir, p) = setup(
            "read -r line < /proc/$$/stat\nset -- $line\n\
             if [ \"$5\" = \"$$\" ] && [ \"$6\" = \"$$\" ] && [ \"$7\" = 0 ]; then\n\
             printf '{\"version\":1}'\nelse echo \"pgrp=$5 sid=$6 tty=$7 pid=$$\" >&2; exit 1; fi\n",
        );
        run(&p).unwrap();
    }

    #[test]
    fn control_characters_in_stderr_are_escaped() {
        let (_dir, e) = err("printf 'a\\033]52;c;aGk=\\007b\\r\\tc\\nd\\302\\233e' >&2\nexit 1\n");
        let ProviderError::Failed { stderr, .. } = &e else {
            panic!("{e:?}");
        };
        assert_eq!(stderr, "a\\u{1b}]52;c;aGk=\\u{7}b\\r\tc\nd\\u{9b}e");
        let msg = e.to_string();
        assert!(!msg.contains('\u{1b}'), "{msg:?}");
        assert!(!msg.contains('\u{7}'), "{msg:?}");
        assert!(!msg.contains('\u{9b}'), "{msg:?}");
        assert!(!msg.contains('\r'), "{msg:?}");
    }

    #[test]
    fn huge_stderr_is_truncated() {
        let (_dir, e) = err(&format!(
            "{MIB}printf 'BEGIN' >&2\nprintf '%s' \"$s\" >&2\nexit 1\n"
        ));
        let ProviderError::Failed { stderr, .. } = &e else {
            panic!("{e:?}");
        };
        assert!(stderr.starts_with("BEGINxxx"), "{}", &stderr[..20]);
        assert!(stderr.len() < STDERR_LIMIT + 100, "{}", stderr.len());
        let discarded = (1 << 20) + 5 - STDERR_LIMIT;
        assert!(
            stderr.ends_with(&format!(" [... {discarded} more bytes discarded]")),
            "{}",
            &stderr[stderr.len() - 60..]
        );
        let msg = e.to_string();
        assert!(msg.contains("stderr:\nBEGINxxx"), "{}", &msg[..200]);
        assert!(msg.contains("exited with code 1"), "{}", &msg[..200]);
    }

    #[test]
    fn protected_paths() {
        let dir = TempDir::new().unwrap();
        let a = write_script(dir.path(), "a.sh", "#!/bin/sh\n");
        let p = provider("s", "a.sh", dir.path());
        assert_eq!(
            p.protected_paths().unwrap(),
            [fs::canonicalize(&a).unwrap()]
        );
        // Through the trait object too.
        let boxed: Box<dyn Provider> = Box::new(p);
        assert_eq!(
            boxed.protected_paths().unwrap(),
            [fs::canonicalize(&a).unwrap()]
        );

        // `protect = false`: nothing, and the path is not even resolved.
        let p = ScriptProvider::new(
            "s".parse().unwrap(),
            &"/nonexistent/a.sh".parse().unwrap(),
            dir.path(),
            false,
            toml::Table::new(),
        );
        assert!(p.protected_paths().unwrap().is_empty());
    }
}
