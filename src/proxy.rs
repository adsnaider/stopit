//! The domain-filtering proxy of `network = "proxy"` (DESIGN.md §8).
//!
//! A sandbox in proxy mode has only `lo`. `__init` starts a bridge in the
//! sandbox ([`run_bridge`]) that listens on `127.0.0.1:1080` and
//! `[::1]:1080` and passes each connection to the proxy's Unix socket,
//! mounted at [`SANDBOX_PROXY_SOCKET`]. The proxy ([`Proxy`]) runs on the
//! host, in the supervisor or the server, and speaks both HTTP `CONNECT`
//! and SOCKS5 `CONNECT` with a host name, telling them apart by the first
//! byte. It allows a connection only when all of these hold.
//!
//! * The host is a name in `allow_domains`, exactly, never an IP address.
//! * The port is 443 or 80 ([`ALLOWED_PORTS`]).
//! * The host's addresses, resolved on the host, include one that is not
//!   host-local ([`is_host_local`]), which is the one it connects to.
//! * The client's first bytes, if they are a TLS record of any kind or an
//!   SSLv2 hello, are a ClientHello whose server name (SNI) equals the
//!   host.
//!
//! Traffic that does not start with a TLS record passes unchecked once the
//! host is allowed, as plain HTTP's `Host` header could name another site
//! on the same address just as SNI could. The proxy forwards bytes and
//! never decrypts them, so domain fronting through a CDN that permits it
//! goes unseen (§11).

use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::manifest::Domain;

/// Where the proxy's socket appears in the sandbox.
pub const SANDBOX_PROXY_SOCKET: &str = "/run/stopit/proxy.sock";

/// The port the bridge listens on in the sandbox, on both loopback
/// addresses.
pub const BRIDGE_PORT: u16 = 1080;

/// The ports a tunnel may reach: HTTPS, and HTTP for clients that tunnel
/// to it. Both protocols speak first from the client's side, which the
/// TLS check relies on.
pub const ALLOWED_PORTS: [u16; 2] = [443, 80];

/// The environment a proxy-mode sandbox gets, unless `env.set` names a
/// variable itself. Both spellings, since tools read one or the other.
/// `socks5h` makes SOCKS clients send the host name rather than resolve it,
/// which they could not in the sandbox. `NODE_USE_ENV_PROXY` makes Node.js
/// 24 and later use the others.
pub fn proxy_env() -> Vec<(&'static str, String)> {
    let http = format!("http://127.0.0.1:{BRIDGE_PORT}");
    let socks = format!("socks5h://127.0.0.1:{BRIDGE_PORT}");
    let local = "localhost,127.0.0.1,::1".to_owned();
    vec![
        ("HTTP_PROXY", http.clone()),
        ("http_proxy", http.clone()),
        ("HTTPS_PROXY", http.clone()),
        ("https_proxy", http),
        ("ALL_PROXY", socks.clone()),
        ("all_proxy", socks),
        ("NO_PROXY", local.clone()),
        ("no_proxy", local),
        ("NODE_USE_ENV_PROXY", "1".to_owned()),
    ]
}

/// Domains that accept uploads, by themselves or as a parent domain:
/// code hosts, paste and file sharing sites, chat webhooks, cloud storage,
/// model APIs, container registries, and the publishing side of package
/// registries. The startup summary lists them, since a sandbox can send
/// data out through them, unlike through a read-only package mirror.
const UPLOAD_DOMAINS: [&str; 28] = [
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "codeberg.org",
    "pastebin.com",
    "paste.rs",
    "transfer.sh",
    "anthropic.com",
    "openai.com",
    "googleapis.com",
    "amazonaws.com",
    "blob.core.windows.net",
    "discord.com",
    "slack.com",
    "dropbox.com",
    "dropboxapi.com",
    "box.com",
    "drive.google.com",
    "registry.npmjs.org",
    "upload.pypi.org",
    "crates.io",
    "huggingface.co",
    "docker.io",
    "ghcr.io",
    "quay.io",
    "gcr.io",
    "pkg.dev",
    "azurecr.io",
];

/// Whether `domain` accepts uploads ([`UPLOAD_DOMAINS`]). It does when it
/// is one of them or below one, except that `crates.io` counts only
/// itself, not the read-only `index.crates.io` and `static.crates.io`.
pub fn accepts_uploads(domain: &str) -> bool {
    UPLOAD_DOMAINS.iter().any(|&base| {
        domain == base
            || (base != "crates.io"
                && domain
                    .strip_suffix(base)
                    .is_some_and(|rest| rest.ends_with('.')))
    })
}

/// How long a client has, in all, to send its request, and again to send
/// its TLS ClientHello.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long connecting to all the addresses of a host may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// How long connecting to one address may take at least, when a host has
/// several.
const MIN_ADDRESS_TIMEOUT: Duration = Duration::from_secs(3);

/// The most connections one proxy serves at once.
const MAX_CONNECTIONS: usize = 256;

/// The most connections the bridge passes on at once. Above the proxy's,
/// so the proxy is the one that refuses, and says so.
const MAX_BRIDGE_CONNECTIONS: usize = 2 * MAX_CONNECTIONS;

/// The longest HTTP request head the proxy reads.
const MAX_REQUEST_HEAD: usize = 8 << 10;

/// The longest TLS ClientHello the proxy reads to find the server name.
const MAX_CLIENT_HELLO: usize = 64 << 10;

/// The most distinct refusals a proxy remembers for its report.
const MAX_DENIED_KEPT: usize = 10;

/// The longest host name a refusal records, in characters.
const MAX_HOST_SHOWN: usize = 253;

/// How a proxy decides, apart from its allowlist.
#[derive(Clone)]
pub struct ProxyOptions {
    /// Resolves a host name and port to addresses.
    pub resolve: Resolver,
    /// Whether an address belongs to the host itself ([`is_host_local`]).
    pub is_local: fn(IpAddr) -> bool,
    /// The most connections served at once.
    pub max_connections: usize,
    /// How long a client has for its request, and for its ClientHello.
    pub handshake_timeout: Duration,
}

impl Default for ProxyOptions {
    fn default() -> Self {
        ProxyOptions {
            // An absolute name, so the resolver never tries the host's
            // search domains after a failure.
            resolve: Arc::new(|host, port| {
                Ok((format!("{host}."), port).to_socket_addrs()?.collect())
            }),
            is_local: is_host_local,
            max_connections: MAX_CONNECTIONS,
            handshake_timeout: HANDSHAKE_TIMEOUT,
        }
    }
}

/// Resolves a host name and port to addresses.
pub type Resolver = Arc<dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync>;

/// A proxy serving one sandbox, on a Unix socket of the host. Dropping it
/// stops it, removes the socket and shuts down the host connections it
/// still holds.
pub struct Proxy {
    path: PathBuf,
    shared: Arc<Shared>,
    /// Written to wake the accepting thread when the proxy stops.
    wake: OwnedFd,
    thread: Option<JoinHandle<()>>,
}

/// What a proxy's threads share.
struct Shared {
    allow: BTreeSet<Domain>,
    options: ProxyOptions,
    stop: AtomicBool,
    active: AtomicUsize,
    denied: Mutex<Denied>,
    /// The host connections open, by connection number.
    upstreams: Mutex<std::collections::HashMap<u64, TcpStream>>,
}

/// What a proxy refused.
#[derive(Debug, Default)]
struct Denied {
    /// The first [`MAX_DENIED_KEPT`] distinct refusals, each a host and
    /// why.
    entries: Vec<String>,
    /// How many refusals there were, the forgotten ones too.
    count: usize,
}

impl Proxy {
    /// Starts a proxy allowing `allow`, listening on a new socket at
    /// `path`, which must not exist.
    pub fn start(path: PathBuf, allow: BTreeSet<Domain>) -> io::Result<Proxy> {
        Self::start_with(path, allow, ProxyOptions::default())
    }

    /// [`start`](Self::start), deciding with `options`.
    pub fn start_with(
        path: PathBuf,
        allow: BTreeSet<Domain>,
        options: ProxyOptions,
    ) -> io::Result<Proxy> {
        let listener = UnixListener::bind(&path)?;
        let started = (|| {
            listener.set_nonblocking(true)?;
            let (woken, wake) = cloexec_pipe()?;
            let shared = Arc::new(Shared {
                allow,
                options,
                stop: AtomicBool::new(false),
                active: AtomicUsize::new(0),
                denied: Mutex::new(Denied::default()),
                upstreams: Mutex::default(),
            });
            let thread_shared = shared.clone();
            let thread =
                spawn_without_signals("proxy", move || serve(listener, woken, thread_shared))?;
            Ok((shared, wake, thread))
        })();
        match started {
            Ok((shared, wake, thread)) => Ok(Proxy {
                path,
                shared,
                wake,
                thread: Some(thread),
            }),
            Err(e) => {
                let _ = std::fs::remove_file(&path);
                Err(e)
            }
        }
    }

    /// The socket's host path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// How many connections the proxy serves now.
    #[cfg(test)]
    fn active(&self) -> usize {
        self.shared.active.load(Ordering::SeqCst)
    }

    /// The refusals so far, the first few distinct ones as a host and why,
    /// and how many refusals there were in all.
    pub fn denied(&self) -> (Vec<String>, usize) {
        let denied = lock(&self.shared.denied);
        (denied.entries.clone(), denied.count)
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        // Wakes the accepting thread, which then sees `stop`.
        let _ = rustix::io::write(&self.wake, b"x");
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.path);
        for upstream in lock(&self.shared.upstreams).values() {
            let _ = upstream.shutdown(Shutdown::Both);
        }
    }
}

/// Spawns a thread with every signal blocked, which its own threads
/// inherit. The supervisor relies on catching its signals in the thread
/// that waits for them, never in a proxy thread.
pub(crate) fn spawn_without_signals<F>(name: &str, f: F) -> io::Result<JoinHandle<()>>
where
    F: FnOnce() + Send + 'static,
{
    // SAFETY: plain libc calls on local, initialized signal sets.
    let old = unsafe {
        let mut all: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut all);
        // Faults stay deliverable, so a crash in a proxy thread reports
        // itself rather than killing the process unseen.
        for fault in [
            libc::SIGSEGV,
            libc::SIGBUS,
            libc::SIGILL,
            libc::SIGFPE,
            libc::SIGTRAP,
        ] {
            libc::sigdelset(&mut all, fault);
        }
        let mut old: libc::sigset_t = std::mem::zeroed();
        match libc::pthread_sigmask(libc::SIG_BLOCK, &all, &mut old) {
            0 => old,
            e => return Err(io::Error::from_raw_os_error(e)),
        }
    };
    let spawned = std::thread::Builder::new().name(name.into()).spawn(f);
    // SAFETY: restores the mask saved above.
    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut()) };
    spawned
}

/// A close-on-exec pipe, the read end and then the write end.
pub(crate) fn cloexec_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    use std::os::fd::FromRawFd;
    let mut fds = [0; 2];
    // SAFETY: `fds` has room for the two descriptors `pipe2` writes.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `pipe2` returned two new descriptors, owned from here on.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// A report for after the run of `count` refusals, of which `entries` are
/// the first few distinct ones, or `None` without any.
pub fn denied_report(entries: &[String], count: usize) -> Option<String> {
    if count == 0 {
        return None;
    }
    let mut names = entries.join(", ");
    if count > entries.len() && entries.len() == MAX_DENIED_KEPT {
        names.push_str(", ...");
    }
    let connections = match count {
        1 => "1 connection".to_owned(),
        n => format!("{n} connections"),
    };
    Some(format!(
        "the network proxy refused {connections}, to {names}; network.allow_domains lists \
         the names a sandbox may reach, on ports 443 and 80"
    ))
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

fn serve(listener: UnixListener, woken: OwnedFd, shared: Arc<Shared>) {
    let mut number = 0u64;
    loop {
        if shared.stop.load(Ordering::SeqCst) {
            return;
        }
        let mut fds = [
            libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: woken.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: valid pollfds for the duration of the call.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if fds[1].revents != 0 {
            return;
        }
        if ready < 0 {
            continue;
        }
        let mut conn = match listener.accept() {
            Ok((conn, _)) => conn,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(_) => {
                // Out of descriptors, perhaps. Connections get a chance to
                // end.
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        let _ = conn.set_nonblocking(false);
        if shared.active.load(Ordering::SeqCst) >= shared.options.max_connections {
            // The reply reads as an HTTP error, and ends a SOCKS client's
            // greeting too.
            let _ = conn.set_write_timeout(Some(Duration::from_millis(100)));
            let _ = write_http(
                &mut conn,
                503,
                "Service Unavailable",
                "stopit: the network proxy serves as many connections as it may\n",
            );
            record_denied(&shared.denied, "(the proxy was full)");
            continue;
        }
        shared.active.fetch_add(1, Ordering::SeqCst);
        number += 1;
        let conn_shared = shared.clone();
        let spawned = std::thread::Builder::new()
            .name("proxy connection".into())
            .spawn(move || {
                let open = Open {
                    shared: &conn_shared,
                    number,
                };
                let slot = Slot(&conn_shared.active);
                let _ = handle(conn, slot, &open);
                lock(&conn_shared.upstreams).remove(&number);
            });
        if spawned.is_err() {
            shared.active.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// A connection's place in the count of those served, given back when
/// dropped.
struct Slot<'a>(&'a AtomicUsize);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Records a refusal, `entry`, in `denied`.
fn record_denied(denied: &Mutex<Denied>, entry: &str) {
    let mut denied = lock(denied);
    denied.count += 1;
    if denied.entries.len() < MAX_DENIED_KEPT && !denied.entries.iter().any(|e| e == entry) {
        denied.entries.push(entry.to_owned());
    }
}

/// One connection being served.
struct Open<'a> {
    shared: &'a Shared,
    number: u64,
}

impl Open<'_> {
    /// Records that `host` was refused, and `why` if not for being
    /// unlisted, before the client hears of it.
    fn deny(&self, host: &str, why: Option<&str>) -> Refusal {
        let mut shown: String = host.chars().take(MAX_HOST_SHOWN).collect();
        if shown.is_empty() {
            shown = "\"\"".to_owned();
        }
        if let Some(why) = why {
            shown = format!("{shown} ({why})");
        }
        record_denied(&self.shared.denied, &shown);
        Refusal::Denied
    }

    /// Records `upstream`, unless the proxy is stopping, when it is shut
    /// down instead.
    fn record(&self, upstream: &TcpStream) -> bool {
        let mut upstreams = lock(&self.shared.upstreams);
        // Under the lock, so a stopping proxy either sees this one or this
        // one sees it stopping.
        if self.shared.stop.load(Ordering::SeqCst) {
            return false;
        }
        match upstream.try_clone() {
            Ok(copy) => {
                upstreams.insert(self.number, copy);
                true
            }
            Err(_) => false,
        }
    }
}

/// Why a connection did not go through.
#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    /// The host or its traffic is not allowed: not in the list, another
    /// port, only host-local addresses, or a mismatched server name.
    Denied,
    /// Anything else, such as a malformed request, a lost client or an
    /// unreachable host.
    Failed,
}

/// The two ways of asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Http,
    Socks5,
}

/// Reads exactly `buf.len()` bytes from `conn` before `deadline`.
fn read_exact_by(conn: &mut UnixStream, buf: &mut [u8], deadline: Instant) -> io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = read_by(conn, &mut buf[filled..], deadline)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        filled += n;
    }
    Ok(())
}

/// Reads what `conn` has, waiting no longer than `deadline`.
fn read_by(conn: &mut UnixStream, buf: &mut [u8], deadline: Instant) -> io::Result<usize> {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        conn.set_read_timeout(Some(left))?;
        match conn.read(buf) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            // A read timeout shows as `EAGAIN`.
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Err(io::ErrorKind::TimedOut.into());
            }
            result => return result,
        }
    }
}

/// Serves one client. It reads the request, checks it, connects, checks
/// the TLS server name, and then relays both ways until either side
/// closes.
///
/// `slot` is moved into a local, which drops before the parameters, so a
/// refused client finds its place free once it sees the close.
fn handle(mut client: UnixStream, slot: Slot<'_>, open: &Open<'_>) -> Result<(), Refusal> {
    let _slot = slot;
    let options = &open.shared.options;
    let deadline = Instant::now() + options.handshake_timeout;
    let mut first = [0u8; 1];
    read_exact_by(&mut client, &mut first, deadline).map_err(|_| Refusal::Failed)?;
    let protocol = if first[0] == 5 {
        Protocol::Socks5
    } else {
        Protocol::Http
    };
    let (asked, port) = match protocol {
        Protocol::Socks5 => socks5_request(&mut client, open, deadline)?,
        Protocol::Http => http_request(&mut client, first[0], deadline)?,
    };
    let refuse = |client: &mut UnixStream, why: Why| {
        let _ = reply_refusal(client, protocol, &asked, why);
    };
    let Some(host) = allowed_host(&asked, &open.shared.allow) else {
        let denied = open.deny(&normalize(&asked), None);
        refuse(&mut client, Why::NotAllowed);
        return Err(denied);
    };
    if !ALLOWED_PORTS.contains(&port) {
        let denied = open.deny(&host, Some(&format!("port {port}")));
        refuse(&mut client, Why::Port);
        return Err(denied);
    }
    let addrs = match (options.resolve)(&host, port) {
        Ok(addrs) if !addrs.is_empty() => addrs,
        _ => {
            refuse(&mut client, Why::Unresolved);
            return Err(Refusal::Failed);
        }
    };
    let mut usable: Vec<SocketAddr> = addrs
        .iter()
        .copied()
        .filter(|a| !(options.is_local)(a.ip()))
        .collect();
    if usable.is_empty() {
        let denied = open.deny(&host, Some("only addresses of the host itself"));
        refuse(&mut client, Why::HostLocal);
        return Err(denied);
    }
    // IPv4 first, as a broken IPv6 path is the more common, and the
    // connect timeout shared out.
    usable.sort_by_key(|a| a.is_ipv6());
    let each = (CONNECT_TIMEOUT / usable.len() as u32).max(MIN_ADDRESS_TIMEOUT);
    let Some(upstream) = usable
        .iter()
        .find_map(|a| TcpStream::connect_timeout(a, each).ok())
    else {
        refuse(&mut client, Why::Unreachable);
        return Err(Refusal::Failed);
    };
    if !open.record(&upstream) {
        return Err(Refusal::Failed);
    }
    reply_success(&mut client, protocol).map_err(|_| Refusal::Failed)?;
    let deadline = Instant::now() + options.handshake_timeout;
    let first = match read_first_bytes(&mut client, deadline) {
        Ok(First::Plain(bytes)) => bytes,
        Ok(First::Hello(bytes, Some(name))) if normalize(&name) == host => bytes,
        // A ClientHello for another name or for none, or another TLS
        // record first. The proxy closes both sides, and the host never
        // gets a byte.
        Ok(First::Hello(_, Some(name))) => {
            // Escaped where the report is printed.
            let shown: String = name.chars().take(MAX_HOST_SHOWN).collect();
            return Err(open.deny(&host, Some(&format!("TLS name {shown}"))));
        }
        Ok(First::Hello(_, None)) => {
            return Err(open.deny(&host, Some("a TLS hello without one server name")));
        }
        Ok(First::BadTls) => {
            return Err(open.deny(&host, Some("TLS that does not start with a hello")));
        }
        Err(_) => return Err(Refusal::Failed),
    };
    let _ = client.set_read_timeout(None);
    relay(client, upstream, first);
    Ok(())
}

/// Why a request is refused, for the reply.
#[derive(Debug, Clone, Copy)]
enum Why {
    NotAllowed,
    Port,
    HostLocal,
    Unresolved,
    Unreachable,
    BadRequest,
}

/// The name in `host`, lowercase and without a trailing dot, if it is in
/// `allow`.
fn allowed_host(host: &str, allow: &BTreeSet<Domain>) -> Option<String> {
    let name = normalize(host);
    let domain: Domain = name.parse().ok()?;
    allow.contains(&domain).then_some(name)
}

/// `host` lowercase, without one trailing dot.
fn normalize(host: &str) -> String {
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

/// Whether `ip` belongs to the host itself or its link. That covers
/// loopback, unspecified and link-local addresses, and their IPv4-mapped
/// IPv6 forms. The filter is narrow on purpose, since an allowed name that
/// resolves to the host's own interface addresses, or to a cloud metadata
/// address outside link-local, is one the user chose to trust.
pub fn is_host_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_host_local(IpAddr::V4(v4));
            }
            v6.is_loopback() || v6.is_unspecified() || v6.is_unicast_link_local()
        }
    }
}

/// Reads an HTTP request whose first byte is `first`, and returns the host
/// and port of its `CONNECT`. Anything else gets an error reply.
fn http_request(
    client: &mut UnixStream,
    first: u8,
    deadline: Instant,
) -> Result<(String, u16), Refusal> {
    let mut head = vec![first];
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_REQUEST_HEAD {
            let _ = write_http(client, 431, "Request Header Fields Too Large", "");
            return Err(Refusal::Failed);
        }
        read_exact_by(client, &mut byte, deadline).map_err(|_| Refusal::Failed)?;
        head.push(byte[0]);
    }
    let line = head.split(|&b| b == b'\r').next().unwrap_or_default();
    let line = String::from_utf8_lossy(line);
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        let _ = write_http(client, 400, "Bad Request", "stopit: malformed request\n");
        return Err(Refusal::Failed);
    };
    if !version.starts_with("HTTP/1.") {
        let _ = write_http(client, 400, "Bad Request", "stopit: not HTTP/1\n");
        return Err(Refusal::Failed);
    }
    if method != "CONNECT" {
        let _ = write_http(
            client,
            405,
            "Method Not Allowed",
            "stopit: the network proxy only tunnels with CONNECT, as HTTPS clients do; \
             plain HTTP through it is not supported\n",
        );
        return Err(Refusal::Failed);
    }
    match split_host_port(target) {
        Some(target) => Ok(target),
        None => {
            let _ = reply_refusal(client, Protocol::Http, target, Why::BadRequest);
            Err(Refusal::Failed)
        }
    }
}

/// `host:port`. The host must not be bracketed, as only a name may follow.
fn split_host_port(target: &str) -> Option<(String, u16)> {
    let (host, port) = target.rsplit_once(':')?;
    let port: u16 = port.parse().ok().filter(|&p| p != 0)?;
    if host.is_empty() || host.contains([':', '[', ']']) {
        return None;
    }
    Some((host.to_owned(), port))
}

/// Reads a SOCKS5 greeting, the version byte already read, and its
/// request, and returns the host name and port. IP addresses are refused,
/// as are other commands than `CONNECT`.
fn socks5_request(
    client: &mut UnixStream,
    open: &Open<'_>,
    deadline: Instant,
) -> Result<(String, u16), Refusal> {
    let read = |client: &mut UnixStream, buf: &mut [u8]| {
        read_exact_by(client, buf, deadline).map_err(|_| Refusal::Failed)
    };
    let mut count = [0u8; 1];
    read(client, &mut count)?;
    let mut methods = vec![0u8; count[0] as usize];
    read(client, &mut methods)?;
    if !methods.contains(&0) {
        // No method without authentication on offer.
        let _ = client.write_all(&[5, 0xff]);
        return Err(Refusal::Failed);
    }
    client.write_all(&[5, 0]).map_err(|_| Refusal::Failed)?;
    let mut request = [0u8; 4];
    read(client, &mut request)?;
    let [version, command, _, kind] = request;
    if version != 5 {
        return Err(Refusal::Failed);
    }
    if command != 1 {
        let _ = socks5_reply(client, 7);
        return Err(Refusal::Failed);
    }
    let host = match kind {
        3 => {
            let mut len = [0u8; 1];
            read(client, &mut len)?;
            let mut name = vec![0u8; len[0] as usize];
            read(client, &mut name)?;
            String::from_utf8_lossy(&name).into_owned()
        }
        1 | 4 => {
            // The allowlist holds names only, so an address is refused.
            let mut rest = vec![0u8; if kind == 1 { 4 } else { 16 } + 2];
            read(client, &mut rest)?;
            let ip: IpAddr = if kind == 1 {
                <[u8; 4]>::try_from(&rest[..4]).unwrap().into()
            } else {
                <[u8; 16]>::try_from(&rest[..16]).unwrap().into()
            };
            let denied = open.deny(&ip.to_string(), None);
            let _ = socks5_reply(client, 2);
            return Err(denied);
        }
        _ => {
            let _ = socks5_reply(client, 8);
            return Err(Refusal::Failed);
        }
    };
    let mut port = [0u8; 2];
    read(client, &mut port)?;
    Ok((host, u16::from_be_bytes(port)))
}

fn socks5_reply(client: &mut UnixStream, code: u8) -> io::Result<()> {
    client.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0])
}

fn write_http(client: &mut UnixStream, status: u16, reason: &str, body: &str) -> io::Result<()> {
    write!(
        client,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
}

fn reply_success(client: &mut UnixStream, protocol: Protocol) -> io::Result<()> {
    match protocol {
        Protocol::Http => client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n"),
        Protocol::Socks5 => socks5_reply(client, 0),
    }
}

fn reply_refusal(
    client: &mut UnixStream,
    protocol: Protocol,
    host: &str,
    why: Why,
) -> io::Result<()> {
    // The host is the sandbox's text, so it is shown escaped and cut short.
    let shown: String = crate::escape::escape_message(host)
        .chars()
        .take(MAX_HOST_SHOWN)
        .collect();
    let (status, reason, socks, body) = match why {
        Why::NotAllowed => (
            403,
            "Forbidden",
            2,
            format!("stopit: {shown} is not in network.allow_domains\n"),
        ),
        Why::Port => (
            403,
            "Forbidden",
            2,
            format!("stopit: the network proxy reaches {shown} on ports 443 and 80 only\n"),
        ),
        Why::HostLocal => (
            403,
            "Forbidden",
            2,
            format!("stopit: {shown} resolves only to addresses of the host itself\n"),
        ),
        Why::Unresolved => (
            502,
            "Bad Gateway",
            4,
            format!("stopit: cannot resolve {shown}\n"),
        ),
        Why::Unreachable => (
            502,
            "Bad Gateway",
            5,
            format!("stopit: cannot connect to {shown}\n"),
        ),
        Why::BadRequest => (
            400,
            "Bad Request",
            1,
            "stopit: CONNECT needs host:port with a host name\n".to_owned(),
        ),
    };
    match protocol {
        Protocol::Http => write_http(client, status, reason, &body),
        Protocol::Socks5 => socks5_reply(client, socks),
    }
}

/// The record type of a TLS handshake.
const TLS_HANDSHAKE: u8 = 0x16;

/// The record types of TLS: change cipher spec, alert, handshake,
/// application data and heartbeat.
const TLS_RECORD_TYPES: std::ops::RangeInclusive<u8> = 0x14..=0x18;

/// What a client sent first in its tunnel.
#[derive(Debug, PartialEq, Eq)]
enum First {
    /// Bytes that are not a TLS record, as read.
    Plain(Vec<u8>),
    /// A complete ClientHello in handshake records, as read, and its
    /// server name if it has exactly one.
    Hello(Vec<u8>, Option<String>),
    /// TLS that does not start with a ClientHello: another record type, a
    /// record of another type before the hello is complete, an SSLv2
    /// hello, or a hello too long to read.
    BadTls,
}

/// Whether `data` starts like an SSLv2 ClientHello: a two-byte length with
/// the top bit set, then message type 1.
fn looks_like_sslv2_hello(data: &[u8]) -> bool {
    data.len() >= 3 && data[0] & 0x80 != 0 && data[2] == 1
}

/// Reads the client's first bytes and tells what they are ([`First`]). It
/// reads only as far as it must, and each byte of a ClientHello once.
fn read_first_bytes(client: &mut UnixStream, deadline: Instant) -> io::Result<First> {
    let mut data = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut more = |client: &mut UnixStream, data: &mut Vec<u8>| -> io::Result<bool> {
        let n = read_by(client, &mut chunk, deadline)?;
        data.extend_from_slice(&chunk[..n]);
        Ok(n > 0)
    };
    if !more(client, &mut data)? {
        return Ok(First::Plain(data));
    }
    // A first byte with the top bit set may start an SSLv2 hello, which
    // takes three bytes to tell.
    while data[0] & 0x80 != 0 && data.len() < 3 {
        if !more(client, &mut data)? {
            return Ok(First::Plain(data));
        }
    }
    if looks_like_sslv2_hello(&data) {
        return Ok(First::BadTls);
    }
    if !TLS_RECORD_TYPES.contains(&data[0]) {
        return Ok(First::Plain(data));
    }
    if data[0] != TLS_HANDSHAKE {
        return Ok(First::BadTls);
    }
    // Whole records, each parsed once, until the hello is complete.
    let mut parsed = 0;
    let mut handshake = Vec::new();
    loop {
        while let Some(header) = data.get(parsed..parsed + 5) {
            if header[0] != TLS_HANDSHAKE {
                return Ok(First::BadTls);
            }
            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let Some(record) = data.get(parsed + 5..parsed + 5 + len) else {
                break;
            };
            handshake.extend_from_slice(record);
            parsed += 5 + len;
            if handshake.len() >= 4 {
                let message = u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]]);
                if handshake.len() >= 4 + message as usize {
                    let name = server_name_in(&handshake);
                    return Ok(First::Hello(data, name));
                }
            }
        }
        if data.len() >= MAX_CLIENT_HELLO {
            return Ok(First::BadTls);
        }
        if !more(client, &mut data)? {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
    }
}

/// The handshake bytes of the whole TLS handshake records at the start of
/// `data`.
fn handshake_bytes(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = data;
    while rest.len() >= 5 && rest[0] == TLS_HANDSHAKE {
        let len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
        let Some(record) = rest.get(5..5 + len) else {
            break;
        };
        out.extend_from_slice(record);
        rest = &rest[5 + len..];
    }
    out
}

/// The server name of the TLS ClientHello in the records at the start of
/// `data` ([`server_name_in`]).
pub fn server_name(data: &[u8]) -> Option<String> {
    server_name_in(&handshake_bytes(data))
}

/// The server name of the ClientHello message at the start of
/// `handshake`. That is the `host_name` entry of its `server_name`
/// extension, if it has exactly one such extension with exactly one such
/// entry.
fn server_name_in(handshake: &[u8]) -> Option<String> {
    let mut r = Reader(handshake);
    if r.u8()? != 1 {
        return None; // Not a ClientHello.
    }
    let len = r.u24()?;
    let body = r.take(len)?;
    let mut r = Reader(body);
    r.take(2 + 32)?; // Version and random.
    let session = r.u8()? as usize;
    r.take(session)?;
    let suites = r.u16()? as usize;
    r.take(suites)?;
    let compression = r.u8()? as usize;
    r.take(compression)?;
    let extensions = r.u16()? as usize;
    let mut r = Reader(r.take(extensions)?);
    let mut found = None;
    while !r.0.is_empty() {
        let kind = r.u16()?;
        let len = r.u16()? as usize;
        let data = r.take(len)?;
        if kind != 0 {
            continue;
        }
        if found.is_some() {
            return None; // Two server_name extensions.
        }
        let mut e = Reader(data);
        let list = e.u16()? as usize;
        let mut list = Reader(e.take(list)?);
        let mut names = Vec::new();
        while !list.0.is_empty() {
            let name_type = list.u8()?;
            let len = list.u16()? as usize;
            let name = list.take(len)?;
            if name_type == 0 {
                names.push(name);
            }
        }
        let [name] = names[..] else {
            return None;
        };
        found = Some(String::from_utf8(name.to_vec()).ok()?);
    }
    found
}

/// A cursor over big-endian TLS fields.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = (self.0.get(..n)?, self.0.get(n..)?);
        self.0 = rest;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Option<usize> {
        let b = self.take(3)?;
        Some(u32::from_be_bytes([0, b[0], b[1], b[2]]) as usize)
    }
}

/// Relays between `client` and `upstream` until both directions end, after
/// sending `upstream` the client's bytes read so far, `first`.
fn relay(client: UnixStream, upstream: TcpStream, first: Vec<u8>) {
    let (Ok(client_reader), Ok(upstream_writer)) = (client.try_clone(), upstream.try_clone())
    else {
        return;
    };
    let upload = std::thread::Builder::new()
        .name("proxy upload".into())
        .spawn(move || {
            let mut from = client_reader;
            let mut to = upstream_writer;
            if to.write_all(&first).is_ok() {
                let _ = io::copy(&mut from, &mut to);
            }
            let _ = to.shutdown(Shutdown::Write);
        });
    let mut from = upstream;
    let mut to = client;
    let _ = io::copy(&mut from, &mut to);
    let _ = to.shutdown(Shutdown::Write);
    match upload {
        Ok(upload) => {
            let _ = upload.join();
        }
        Err(_) => {
            let _ = from.shutdown(Shutdown::Both);
        }
    }
}

/// The bridge in the sandbox. It accepts connections on `listeners` and
/// passes each to the proxy socket at `socket`, until `parent`, a pidfd of
/// the sandbox's first process, says that process has exited.
pub fn run_bridge(listeners: Vec<std::net::TcpListener>, socket: &Path, parent: OwnedFd) -> ! {
    for listener in &listeners {
        // A connection reset between `poll` and `accept` must not leave the
        // bridge in `accept`, blind to the pidfd.
        if listener.set_nonblocking(true).is_err() {
            // SAFETY: ends this process without running anything of the
            // parent's.
            unsafe { libc::_exit(1) };
        }
    }
    let active = Arc::new(AtomicUsize::new(0));
    loop {
        let mut fds: Vec<libc::pollfd> = std::iter::once(parent.as_raw_fd())
            .chain(listeners.iter().map(|l| l.as_raw_fd()))
            .map(|fd| libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        // SAFETY: valid pollfds for the duration of the call.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if n < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            // SAFETY: as above.
            unsafe { libc::_exit(1) };
        }
        if fds[0].revents != 0 {
            // SAFETY: as above.
            unsafe { libc::_exit(0) };
        }
        for (listener, pollfd) in listeners.iter().zip(&fds[1..]) {
            if pollfd.revents == 0 {
                continue;
            }
            let Ok((conn, _)) = listener.accept() else {
                continue;
            };
            let _ = conn.set_nonblocking(false);
            if active.load(Ordering::SeqCst) >= MAX_BRIDGE_CONNECTIONS {
                continue;
            }
            let Ok(upstream) = UnixStream::connect(socket) else {
                continue;
            };
            active.fetch_add(1, Ordering::SeqCst);
            let done = active.clone();
            let spawned = std::thread::Builder::new().spawn(move || {
                bridge_one(conn, upstream);
                done.fetch_sub(1, Ordering::SeqCst);
            });
            if spawned.is_err() {
                active.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }
}

fn bridge_one(conn: TcpStream, upstream: UnixStream) {
    let (Ok(conn_reader), Ok(upstream_writer)) = (conn.try_clone(), upstream.try_clone()) else {
        return;
    };
    let up = std::thread::Builder::new().spawn(move || {
        let mut from = conn_reader;
        let mut to = upstream_writer;
        let _ = io::copy(&mut from, &mut to);
        let _ = to.shutdown(Shutdown::Write);
    });
    let mut from = upstream;
    let mut to = conn;
    let _ = io::copy(&mut from, &mut to);
    let _ = to.shutdown(Shutdown::Write);
    if let Ok(up) = up {
        let _ = up.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, TcpListener};

    /// Extensions of a ClientHello, built for tests.
    #[derive(Default)]
    struct Hello {
        /// Each `server_name` extension, as its entries of type and name.
        server_names: Vec<Vec<(u8, Vec<u8>)>>,
        /// Whether the hello has an extensions block at all.
        no_extensions: bool,
    }

    impl Hello {
        fn named(names: &[&str]) -> Hello {
            Hello {
                server_names: if names.is_empty() {
                    vec![]
                } else {
                    vec![names.iter().map(|n| (0, n.as_bytes().to_vec())).collect()]
                },
                no_extensions: false,
            }
        }

        /// The message in TLS records of at most `record` bytes.
        fn bytes(&self, record: usize) -> Vec<u8> {
            let mut extensions = Vec::new();
            // A GREASE extension and another, which the parser skips.
            extensions.extend_from_slice(&[0x0a, 0x0a, 0x00, 0x00]);
            extensions.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
            for entries in &self.server_names {
                let mut list = Vec::new();
                for (kind, name) in entries {
                    list.push(*kind);
                    list.extend_from_slice(&(name.len() as u16).to_be_bytes());
                    list.extend_from_slice(name);
                }
                let mut ext = (list.len() as u16).to_be_bytes().to_vec();
                ext.extend_from_slice(&list);
                extensions.extend_from_slice(&[0, 0]);
                extensions.extend_from_slice(&(ext.len() as u16).to_be_bytes());
                extensions.extend_from_slice(&ext);
            }
            let mut body = vec![3, 3];
            body.extend_from_slice(&[7; 32]);
            body.push(0); // No session id.
            body.extend_from_slice(&[0, 2, 0x13, 0x01]); // One cipher suite.
            body.extend_from_slice(&[1, 0]); // No compression.
            if !self.no_extensions {
                body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
                body.extend_from_slice(&extensions);
            }
            let mut handshake = vec![1];
            handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
            handshake.extend_from_slice(&body);
            let mut out = Vec::new();
            for chunk in handshake.chunks(record) {
                out.extend_from_slice(&[TLS_HANDSHAKE, 3, 1]);
                out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
                out.extend_from_slice(chunk);
            }
            out
        }
    }

    fn client_hello(names: &[&str], record: usize) -> Vec<u8> {
        Hello::named(names).bytes(record)
    }

    /// A TLS warning alert record, which some servers skip before a hello.
    const ALERT: [u8; 7] = [0x15, 3, 1, 0, 2, 1, 0x5a];

    #[test]
    fn the_server_name_is_read_from_whole_records_only() {
        for record in [16384, 40, 7] {
            let hello = client_hello(&["example.org"], record);
            assert_eq!(server_name(&hello).as_deref(), Some("example.org"));
            // Cut short, it names nothing.
            assert_eq!(server_name(&hello[..hello.len() - 1]), None);
        }
        assert_eq!(server_name(&client_hello(&[], 16384)), None);
        let without = Hello {
            no_extensions: true,
            ..Hello::default()
        };
        assert_eq!(server_name(&without.bytes(16384)), None);
        // Two names in one extension, or two extensions, are ambiguous.
        assert_eq!(server_name(&client_hello(&["a.org", "b.org"], 16384)), None);
        let two = Hello {
            server_names: vec![vec![(0, b"a.org".to_vec())], vec![(0, b"a.org".to_vec())]],
            ..Hello::default()
        };
        assert_eq!(server_name(&two.bytes(16384)), None);
        // An empty list, or entries of another type only, name nothing; an
        // entry of another type next to a host name does not count.
        for entries in [vec![], vec![(1, b"a.org".to_vec())]] {
            let hello = Hello {
                server_names: vec![entries],
                ..Hello::default()
            };
            assert_eq!(server_name(&hello.bytes(16384)), None);
        }
        let mixed = Hello {
            server_names: vec![vec![(1, b"x".to_vec()), (0, b"a.org".to_vec())]],
            ..Hello::default()
        };
        assert_eq!(server_name(&mixed.bytes(16384)).as_deref(), Some("a.org"));
        // Not a handshake, or not a ClientHello.
        assert_eq!(server_name(b"GET / HTTP/1.1\r\n\r\n"), None);
        let mut hello = client_hello(&["example.org"], 16384);
        hello[5] = 2;
        assert_eq!(server_name(&hello), None);
        // Lengths past the end are not trusted.
        let mut hello = client_hello(&["example.org"], 16384);
        let at = hello.len() - "example.org".len() - 2;
        hello[at] = 0xff;
        assert_eq!(server_name(&hello), None);
    }

    /// What [`read_first_bytes`] makes of `chunks`, written one after the
    /// other, and then of the end of the stream.
    fn first_of(chunks: Vec<Vec<u8>>) -> io::Result<First> {
        let (mut ours, mut theirs) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            for chunk in chunks {
                let _ = ours.write_all(&chunk);
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        let first = read_first_bytes(&mut theirs, Instant::now() + Duration::from_secs(10));
        writer.join().unwrap();
        first
    }

    #[test]
    fn only_a_tls_record_that_is_a_client_hello_passes() {
        let hello = client_hello(&["a.org"], 30);
        // Whole, and one byte per write.
        for chunks in [
            vec![hello.clone()],
            hello.iter().map(|&b| vec![b]).collect(),
        ] {
            assert_eq!(
                first_of(chunks).unwrap(),
                First::Hello(hello.clone(), Some("a.org".into()))
            );
        }
        // Bytes that are not TLS pass as read.
        assert_eq!(
            first_of(vec![b"GET / HTTP/1.1\r\n".to_vec()]).unwrap(),
            First::Plain(b"GET / HTTP/1.1\r\n".to_vec())
        );
        assert_eq!(first_of(vec![]).unwrap(), First::Plain(vec![]));
        assert_eq!(
            first_of(vec![vec![0x80]]).unwrap(),
            First::Plain(vec![0x80])
        );
        // Any other TLS record first, an SSLv2 hello, and a record of
        // another type before the hello is complete, are bad.
        let mut alert_first = ALERT.to_vec();
        alert_first.extend_from_slice(&hello);
        // After the first whole record of the hello.
        let mut interleaved = hello[..35].to_vec();
        interleaved.extend_from_slice(&ALERT);
        interleaved.extend_from_slice(&hello[35..]);
        for chunks in [
            vec![alert_first],
            vec![vec![0x14, 3, 1, 0, 1, 1]],
            vec![vec![0x17, 3, 3, 0, 0]],
            vec![vec![0x80, 0x2e, 0x01, 0x03, 0x01]],
            vec![interleaved],
        ] {
            assert_eq!(
                first_of(chunks.clone()).unwrap(),
                First::BadTls,
                "{chunks:?}"
            );
        }
        // A hello that never ends within the limit is bad too, and one cut
        // off by the end of the stream an error.
        let mut endless = vec![TLS_HANDSHAKE, 3, 1, 0xff, 0xff, 1, 0xff, 0xff, 0xff];
        endless.resize(5 + 0xffff, 0);
        assert_eq!(first_of(vec![endless]).unwrap(), First::BadTls);
        assert!(first_of(vec![hello[..hello.len() - 1].to_vec()]).is_err());
    }

    #[test]
    fn a_slow_first_byte_runs_out_of_time() {
        let (_ours, mut theirs) = UnixStream::pair().unwrap();
        let start = Instant::now();
        let e = read_first_bytes(&mut theirs, start + Duration::from_millis(200)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn host_local_addresses_are_recognized_in_every_form() {
        let local: [IpAddr; 9] = [
            Ipv4Addr::new(127, 0, 0, 1).into(),
            Ipv4Addr::new(127, 1, 2, 3).into(),
            Ipv4Addr::UNSPECIFIED.into(),
            Ipv4Addr::new(169, 254, 169, 254).into(),
            Ipv6Addr::LOCALHOST.into(),
            Ipv6Addr::UNSPECIFIED.into(),
            "fe80::1".parse().unwrap(),
            "::ffff:127.0.0.1".parse().unwrap(),
            "::ffff:169.254.0.1".parse().unwrap(),
        ];
        for ip in local {
            assert!(is_host_local(ip), "{ip}");
        }
        let remote: [IpAddr; 5] = [
            Ipv4Addr::new(8, 8, 8, 8).into(),
            Ipv4Addr::new(10, 0, 0, 1).into(),
            Ipv4Addr::new(128, 0, 0, 1).into(),
            "2001:4860:4860::8888".parse().unwrap(),
            "::ffff:8.8.8.8".parse().unwrap(),
        ];
        for ip in remote {
            assert!(!is_host_local(ip), "{ip}");
        }
    }

    #[test]
    fn hosts_must_be_listed_names_exactly() {
        let allow: BTreeSet<Domain> = ["example.org".parse().unwrap()].into();
        for ok in ["example.org", "EXAMPLE.org", "example.org."] {
            assert_eq!(
                allowed_host(ok, &allow).as_deref(),
                Some("example.org"),
                "{ok}"
            );
        }
        for bad in [
            "www.example.org",
            "org",
            "example.org..",
            "93.184.215.14",
            "example.org:443",
            "",
            "exa\u{1b}mple.org",
            "exa\0mple.org",
        ] {
            assert_eq!(allowed_host(bad, &allow), None, "{bad:?}");
        }
        assert_eq!(split_host_port("a.org:443"), Some(("a.org".into(), 443)));
        for bad in [
            "a.org",
            "a.org:0",
            "a.org:x",
            ":443",
            "[::1]:443",
            "::1:443",
        ] {
            assert_eq!(split_host_port(bad), None, "{bad}");
        }
    }

    #[test]
    fn upload_domains_include_their_subdomains() {
        for yes in [
            "github.com",
            "gist.github.com",
            "api.anthropic.com",
            "crates.io",
            "storage.googleapis.com",
            "mybucket.s3.amazonaws.com",
            "ghcr.io",
            "registry-1.docker.io",
            "us-docker.pkg.dev",
        ] {
            assert!(accepts_uploads(yes), "{yes}");
        }
        for no in [
            "index.crates.io",
            "static.crates.io",
            "cache.nixos.org",
            "notgithub.com",
            "github.com.evil.org",
            "pypi.org",
            "files.pythonhosted.org",
        ] {
            assert!(!accepts_uploads(no), "{no}");
        }
    }

    #[test]
    fn the_report_names_the_first_refusals_and_counts_all() {
        assert_eq!(denied_report(&[], 0), None);
        assert_eq!(
            denied_report(&["a.org".into()], 1).unwrap(),
            "the network proxy refused 1 connection, to a.org; network.allow_domains lists \
             the names a sandbox may reach, on ports 443 and 80"
        );
        let many: Vec<String> = (0..MAX_DENIED_KEPT).map(|i| format!("h{i}.org")).collect();
        let report = denied_report(&many, 30).unwrap();
        assert!(report.contains("refused 30 connections"), "{report}");
        assert!(report.contains("h9.org, ..."), "{report}");
    }

    /// The address the tests treat as the host's own.
    const LOCAL: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 9);

    /// A proxy allowing `allowed.test`, `local.test` and `nowhere.test`.
    /// The first resolves to `upstream` whatever the port, the second to
    /// [`LOCAL`], and the third to nothing.
    struct Fixture {
        proxy: Proxy,
        _dir: tempfile::TempDir,
    }

    fn fixture_with(upstream: SocketAddr, tune: impl FnOnce(&mut ProxyOptions)) -> Fixture {
        let dir = tempfile::TempDir::new().unwrap();
        let allow: BTreeSet<Domain> = ["allowed.test", "local.test", "nowhere.test"]
            .into_iter()
            .map(|d| d.parse().unwrap())
            .collect();
        let mut options = ProxyOptions {
            resolve: Arc::new(move |host, port| match host {
                "allowed.test" => Ok(vec![upstream]),
                "local.test" => Ok(vec![SocketAddr::new(LOCAL.into(), port)]),
                _ => Err(io::Error::other("no such host")),
            }),
            is_local: |ip| ip == IpAddr::V4(LOCAL),
            ..ProxyOptions::default()
        };
        tune(&mut options);
        let proxy = Proxy::start_with(dir.path().join("p.sock"), allow, options).unwrap();
        Fixture { proxy, _dir: dir }
    }

    fn fixture(upstream: SocketAddr) -> Fixture {
        fixture_with(upstream, |_| {})
    }

    impl Fixture {
        fn connect(&self) -> UnixStream {
            let conn = UnixStream::connect(self.proxy.path()).unwrap();
            conn.set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            conn
        }
    }

    /// Reads what `conn` sends until it closes.
    fn rest(conn: &mut impl Read) -> Vec<u8> {
        let mut out = Vec::new();
        let _ = conn.read_to_end(&mut out);
        out
    }

    /// Reads an HTTP response head.
    fn response_head(conn: &mut UnixStream) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match conn.read(&mut byte) {
                Ok(1) => head.push(byte[0]),
                _ => break,
            }
        }
        String::from_utf8_lossy(&head).into_owned()
    }

    /// An upstream server on the loopback that answers each connection with
    /// `pong` after reading what it is sent until the sender stops writing,
    /// and reports what it read.
    fn upstream() -> (SocketAddr, std::sync::mpsc::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut conn) = conn else { return };
                let tx = tx.clone();
                std::thread::spawn(move || {
                    let got = rest(&mut conn);
                    let _ = conn.write_all(b"pong");
                    let _ = tx.send(got);
                });
            }
        });
        (addr, rx)
    }

    /// Opens a tunnel to `allowed.test:443`.
    fn tunnel(f: &Fixture) -> UnixStream {
        let mut conn = f.connect();
        conn.write_all(b"CONNECT Allowed.Test.:443 HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        assert_eq!(
            response_head(&mut conn),
            "HTTP/1.1 200 Connection established\r\n\r\n"
        );
        conn
    }

    #[test]
    fn connect_with_a_matching_server_name_reaches_the_host() {
        let (addr, got) = upstream();
        let f = fixture(addr);
        let hello = client_hello(&["ALLOWED.test"], 30);
        let mut conn = tunnel(&f);
        conn.write_all(&hello).unwrap();
        conn.write_all(b"after").unwrap();
        conn.shutdown(Shutdown::Write).unwrap();
        assert_eq!(rest(&mut conn), b"pong");
        let mut want = hello.clone();
        want.extend_from_slice(b"after");
        assert_eq!(got.recv_timeout(Duration::from_secs(10)).unwrap(), want);
        assert_eq!(f.proxy.denied(), (vec![], 0));

        // Bytes that are not TLS pass unchecked.
        let mut conn = tunnel(&f);
        conn.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        conn.shutdown(Shutdown::Write).unwrap();
        assert_eq!(rest(&mut conn), b"pong");
        assert_eq!(
            got.recv_timeout(Duration::from_secs(10)).unwrap(),
            b"GET / HTTP/1.1\r\n\r\n"
        );
    }

    #[test]
    fn tls_for_another_name_or_none_never_reaches_the_host() {
        let (addr, got) = upstream();
        let f = fixture(addr);
        let mut alert_first = ALERT.to_vec();
        alert_first.extend_from_slice(&client_hello(&["evil.example"], 16384));
        for first in [
            client_hello(&["evil.example"], 16384),
            client_hello(&[], 16384),
            client_hello(&["allowed.test", "evil.example"], 16384),
            alert_first,
            vec![0x80, 0x2e, 0x01, 0x03, 0x01],
        ] {
            let mut conn = tunnel(&f);
            conn.write_all(&first).unwrap();
            assert_eq!(rest(&mut conn), b"", "{first:?}");
            // The host saw the connection close with nothing sent.
            assert_eq!(got.recv_timeout(Duration::from_secs(10)).unwrap(), b"");
        }
        let (entries, count) = f.proxy.denied();
        assert_eq!(count, 5);
        assert_eq!(
            entries,
            [
                "allowed.test (TLS name evil.example)",
                "allowed.test (a TLS hello without one server name)",
                "allowed.test (TLS that does not start with a hello)",
            ]
        );
    }

    #[test]
    fn refusals_say_why_and_are_counted() {
        // No upstream is reached in any of these.
        let f = fixture("192.0.2.1:9".parse().unwrap());
        let ask = |request: &str| {
            let mut conn = f.connect();
            conn.write_all(request.as_bytes()).unwrap();
            let head = response_head(&mut conn);
            let body = String::from_utf8_lossy(&rest(&mut conn)).into_owned();
            (head, body)
        };
        let (head, body) = ask("CONNECT Other.Test:443 HTTP/1.1\r\n\r\n");
        assert!(head.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{head}");
        assert_eq!(body, "stopit: Other.Test is not in network.allow_domains\n");
        ask("CONNECT other.test:443 HTTP/1.1\r\n\r\n");
        let (head, _) = ask("CONNECT 93.184.215.14:443 HTTP/1.1\r\n\r\n");
        assert!(head.starts_with("HTTP/1.1 403"), "{head}");
        let (head, body) = ask("CONNECT allowed.test:22 HTTP/1.1\r\n\r\n");
        assert!(head.starts_with("HTTP/1.1 403"), "{head}");
        assert!(body.contains("on ports 443 and 80 only"), "{body}");
        let (head, body) = ask("CONNECT local.test:443 HTTP/1.1\r\n\r\n");
        assert!(head.starts_with("HTTP/1.1 403"), "{head}");
        assert!(body.contains("addresses of the host itself"), "{body}");
        let (head, _) = ask("CONNECT nowhere.test:443 HTTP/1.1\r\n\r\n");
        assert!(head.starts_with("HTTP/1.1 502"), "{head}");
        let (head, body) = ask("GET http://allowed.test/ HTTP/1.1\r\n\r\n");
        assert!(head.starts_with("HTTP/1.1 405"), "{head}");
        assert!(body.contains("only tunnels with CONNECT"), "{body}");
        for bad in [
            "CONNECT allowed.test HTTP/1.1\r\n\r\n",
            "CONNECT [::1]:443 HTTP/1.1\r\n\r\n",
            "CONNECT allowed.test:443\r\n\r\n",
            "CONNECT allowed.test:443 HTTP/2\r\n\r\n",
        ] {
            let (head, _) = ask(bad);
            assert!(head.starts_with("HTTP/1.1 400"), "{bad:?}: {head}");
        }
        let (head, _) = ask(&format!(
            "CONNECT a:1 HTTP/1.1\r\nX: {}\r\n\r\n",
            "x".repeat(9000)
        ));
        assert!(head.starts_with("HTTP/1.1 431"), "{head}");
        // A host the sandbox names is escaped in the reply.
        let (_, body) = ask("CONNECT \u{7}\u{1b}X.test:443 HTTP/1.1\r\n\r\n");
        assert!(!body.contains(['\u{1b}', '\u{7}']), "{body:?}");
        assert!(body.contains("is not in network.allow_domains"), "{body:?}");
        let (entries, count) = f.proxy.denied();
        assert_eq!(count, 6, "{entries:?}");
        assert_eq!(
            entries[..4],
            [
                "other.test",
                "93.184.215.14",
                "allowed.test (port 22)",
                "local.test (only addresses of the host itself)"
            ]
        );
    }

    #[test]
    fn socks5_connects_by_name_only() {
        let (addr, got) = upstream();
        let f = fixture(addr);
        let socks = |request: &[u8]| {
            let mut conn = f.connect();
            conn.write_all(&[5, 1, 0]).unwrap();
            let mut choice = [0u8; 2];
            conn.read_exact(&mut choice).unwrap();
            assert_eq!(choice, [5, 0]);
            conn.write_all(request).unwrap();
            let mut reply = [0u8; 10];
            conn.read_exact(&mut reply).unwrap();
            (conn, reply[1])
        };
        let name = |host: &[u8], port: u16| {
            let mut r = vec![5, 1, 0, 3, host.len() as u8];
            r.extend_from_slice(host);
            r.extend_from_slice(&port.to_be_bytes());
            r
        };
        let (mut conn, code) = socks(&name(b"allowed.test", 443));
        assert_eq!(code, 0);
        conn.write_all(b"raw").unwrap();
        conn.shutdown(Shutdown::Write).unwrap();
        assert_eq!(rest(&mut conn), b"pong");
        assert_eq!(got.recv_timeout(Duration::from_secs(10)).unwrap(), b"raw");
        // Not listed, empty, with a NUL, as long as SOCKS allows, an
        // address, or another command.
        assert_eq!(socks(&name(b"other.test", 443)).1, 2);
        assert_eq!(socks(&name(b"", 443)).1, 2);
        assert_eq!(socks(&name(b"allowed.test\0.evil", 443)).1, 2);
        assert_eq!(socks(&name(&[b'a'; 255], 443)).1, 2);
        let mut v4 = vec![5, 1, 0, 1];
        v4.extend_from_slice(&[93, 184, 215, 14, 1, 187]);
        assert_eq!(socks(&v4).1, 2);
        let mut bind = name(b"allowed.test", 443);
        bind[1] = 2;
        assert_eq!(socks(&bind).1, 7);
        // A client offering only authentication is turned away.
        let mut conn = f.connect();
        conn.write_all(&[5, 1, 2]).unwrap();
        let mut choice = [0u8; 2];
        conn.read_exact(&mut choice).unwrap();
        assert_eq!(choice, [5, 0xff]);
        let (entries, count) = f.proxy.denied();
        assert_eq!(count, 5, "{entries:?}");
        assert_eq!(entries[1], "\"\"");
        assert!(entries[3].len() <= MAX_HOST_SHOWN, "{entries:?}");
    }

    #[test]
    fn a_full_proxy_says_so_and_a_slow_client_runs_out_of_time() {
        let (addr, _got) = upstream();
        let f = fixture_with(addr, |o| {
            o.max_connections = 1;
            o.handshake_timeout = Duration::from_millis(500);
        });
        // One client sends its request a byte at a time, too slowly.
        let mut slow = f.connect();
        slow.write_all(b"C").unwrap();
        let start = Instant::now();
        while f.proxy.active() == 0 {
            assert!(start.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(10));
        }
        // The proxy has no room for another meanwhile.
        let mut other = f.connect();
        assert!(response_head(&mut other).starts_with("HTTP/1.1 503"));
        assert_eq!(f.proxy.denied().0, ["(the proxy was full)"]);
        // The slow one is dropped once its time is up, though it keeps
        // sending.
        let start = Instant::now();
        let mut closed = false;
        while start.elapsed() < Duration::from_secs(5) {
            if slow.write_all(b"O").is_err() {
                closed = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(closed, "the slow client was not dropped");
        assert!(start.elapsed() < Duration::from_secs(3));
        assert_eq!(f.proxy.active(), 0);
        // And then there is room again.
        let mut conn = tunnel(&f);
        conn.write_all(b"x").unwrap();
    }

    #[test]
    fn stopping_the_proxy_ends_its_connections_and_removes_the_socket() {
        // An upstream that never closes.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let held = std::thread::spawn(move || listener.accept().map(|(conn, _)| conn));
        let f = fixture(addr);
        let mut conn = tunnel(&f);
        conn.write_all(b"plain").unwrap();
        let mut upstream = held.join().unwrap().unwrap();
        let mut buf = [0u8; 5];
        upstream.read_exact(&mut buf).unwrap();
        let path = f.proxy.path().to_owned();
        drop(f.proxy);
        assert!(!path.exists());
        // The host side sees the end, and so does the client.
        upstream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        assert_eq!(upstream.read(&mut buf).unwrap(), 0);
        assert_eq!(rest(&mut conn), b"");
    }

    #[test]
    fn proxy_threads_take_no_signal() {
        let (addr, _got) = upstream();
        let f = fixture(addr);
        // A connection makes the proxy start a thread of its own as well.
        let _conn = tunnel(&f);
        let task = std::fs::read_dir("/proc/self/task").unwrap();
        let mut checked = 0;
        for entry in task.flatten() {
            let path = entry.path();
            let name = std::fs::read_to_string(path.join("comm")).unwrap_or_default();
            // The kernel keeps 15 bytes of a thread's name.
            if !["proxy", "proxy connectio", "proxy upload"].contains(&name.trim_end()) {
                continue;
            }
            // Threads of other tests come and go meanwhile.
            let Ok(status) = std::fs::read_to_string(path.join("status")) else {
                continue;
            };
            let Some(blocked) = status.lines().find_map(|l| l.strip_prefix("SigBlk:")) else {
                continue;
            };
            let blocked = blocked.trim().to_owned();
            let mask = u64::from_str_radix(&blocked, 16).unwrap();
            for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGWINCH] {
                assert!(mask & (1 << (signal - 1)) != 0, "{name}: {blocked}");
            }
            checked += 1;
        }
        assert!(checked >= 2, "{checked}");
    }
}
