//! The domain-filtering proxy of `network = "proxy"` (DESIGN.md §8).
//!
//! A sandbox in proxy mode has only `lo`. `__init` starts a bridge in the
//! sandbox ([`run_bridge`]) that listens on `127.0.0.1:1080` and
//! `[::1]:1080` and passes each connection to the proxy's Unix socket,
//! mounted at [`SANDBOX_PROXY_SOCKET`]. The proxy ([`Proxy`]) runs on the
//! host, in the supervisor or the server, and speaks both HTTP `CONNECT`
//! and SOCKS5 `CONNECT` with a host name, telling them apart by the first
//! byte. It allows a connection only when:
//!
//! * the host is a name in `allow_domains`, exactly, never an IP address;
//! * the host's addresses, resolved on the host, include one that is not
//!   host-local ([`is_host_local`]), which is the one it connects to;
//! * the client's first bytes, if they start a TLS handshake, carry a
//!   server name (SNI) equal to the host.
//!
//! Traffic that does not start with a TLS handshake passes unchecked once
//! the host is allowed, as plain HTTP's `Host` header could name another
//! site on the same address just as SNI could. The proxy forwards bytes and
//! never decrypts them, so domain fronting through a CDN that permits it
//! goes unseen (§11).

use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::manifest::Domain;

/// Where the proxy's socket appears in the sandbox.
pub const SANDBOX_PROXY_SOCKET: &str = "/run/stopit/proxy.sock";

/// The port the bridge listens on in the sandbox, on both loopback
/// addresses.
pub const BRIDGE_PORT: u16 = 1080;

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
/// model APIs, and the publishing side of package registries. The startup
/// summary tags them, since a sandbox can send data out through them,
/// unlike through a read-only package mirror.
const UPLOAD_DOMAINS: [&str; 22] = [
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
];

/// Whether `domain` accepts uploads ([`UPLOAD_DOMAINS`]): it is one of
/// them, or below one. `crates.io` counts only itself, not the read-only
/// `index.crates.io` and `static.crates.io`.
pub fn accepts_uploads(domain: &str) -> bool {
    UPLOAD_DOMAINS.iter().any(|&base| {
        domain == base
            || (base != "crates.io"
                && domain
                    .strip_suffix(base)
                    .is_some_and(|rest| rest.ends_with('.')))
    })
}

/// How long a client has to send its request, and its TLS ClientHello.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long connecting to each address of a host may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// The most connections one proxy serves at once.
const MAX_CONNECTIONS: usize = 256;

/// The longest HTTP request head the proxy reads.
const MAX_REQUEST_HEAD: usize = 8 << 10;

/// The longest TLS ClientHello the proxy reads to find the server name.
const MAX_CLIENT_HELLO: usize = 64 << 10;

/// The most distinct denied hosts a proxy remembers for its report.
const MAX_DENIED_KEPT: usize = 10;

/// A proxy serving one sandbox, on a Unix socket of the host. Dropping it
/// stops it and removes the socket. Connections already passed on keep
/// going until either side closes.
pub struct Proxy {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    /// Written to wake the accepting thread when the proxy stops.
    wake: std::os::fd::OwnedFd,
    denied: Arc<Mutex<Denied>>,
    upstreams: Upstreams,
    thread: Option<JoinHandle<()>>,
}

/// Resolves a host name and port to addresses, as the proxy's
/// [`ToSocketAddrs`] does; tests give their own.
pub type Resolver = Arc<dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync>;

/// The host connections a proxy has open, by connection number, so that
/// stopping it ends them even if the far side never closes.
type Upstreams = Arc<Mutex<std::collections::HashMap<u64, TcpStream>>>;

/// The hosts a proxy refused.
#[derive(Debug, Default)]
struct Denied {
    /// The first [`MAX_DENIED_KEPT`] distinct ones.
    hosts: Vec<String>,
    /// How many refusals there were, the forgotten hosts' too.
    count: usize,
}

impl Proxy {
    /// Starts a proxy allowing `allow`, listening on a new socket at
    /// `path`, which must not exist.
    pub fn start(path: PathBuf, allow: BTreeSet<Domain>) -> io::Result<Proxy> {
        Self::start_with(
            path,
            allow,
            Arc::new(|host, port| Ok((host, port).to_socket_addrs()?.collect())),
        )
    }

    /// [`start`](Self::start), resolving names with `resolve`.
    pub fn start_with(
        path: PathBuf,
        allow: BTreeSet<Domain>,
        resolve: Resolver,
    ) -> io::Result<Proxy> {
        let listener = UnixListener::bind(&path)?;
        listener.set_nonblocking(true)?;
        let (woken, wake) = cloexec_pipe()?;
        let stop = Arc::new(AtomicBool::new(false));
        let denied = Arc::new(Mutex::new(Denied::default()));
        let upstreams = Upstreams::default();
        let allow = Arc::new(allow);
        let thread = {
            let stop = stop.clone();
            let denied = denied.clone();
            let upstreams = upstreams.clone();
            std::thread::Builder::new()
                .name("proxy".into())
                .spawn(move || serve(listener, woken, allow, resolve, stop, denied, upstreams))?
        };
        Ok(Proxy {
            path,
            stop,
            wake,
            denied,
            upstreams,
            thread: Some(thread),
        })
    }

    /// The socket's host path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The hosts refused so far, the first few distinct ones, and how many
    /// refusals there were in all.
    pub fn denied(&self) -> (Vec<String>, usize) {
        let denied = self.denied.lock().unwrap_or_else(|e| e.into_inner());
        (denied.hosts.clone(), denied.count)
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wakes the accepting thread, which then sees `stop`.
        let _ = rustix::io::write(&self.wake, b"x");
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.path);
        for upstream in lock(&self.upstreams).values() {
            let _ = upstream.shutdown(Shutdown::Both);
        }
    }
}

/// A close-on-exec pipe: the read end, then the write end.
fn cloexec_pipe() -> io::Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    use std::os::fd::FromRawFd;
    let mut fds = [0; 2];
    // SAFETY: `fds` has room for the two descriptors `pipe2` writes.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `pipe2` returned two new descriptors, owned from here on.
    Ok(unsafe {
        (
            std::os::fd::OwnedFd::from_raw_fd(fds[0]),
            std::os::fd::OwnedFd::from_raw_fd(fds[1]),
        )
    })
}

/// A report of what `proxy` refused, for after the run, or `None`.
pub fn denied_report(hosts: &[String], count: usize) -> Option<String> {
    if count == 0 {
        return None;
    }
    let mut names = hosts.join(", ");
    if count > hosts.len() && hosts.len() == MAX_DENIED_KEPT {
        names.push_str(", ...");
    }
    let connections = match count {
        1 => "1 connection".to_owned(),
        n => format!("{n} connections"),
    };
    Some(format!(
        "the network proxy refused {connections}, to {names}; allow a domain with \
         network.allow_domains"
    ))
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

#[allow(clippy::too_many_arguments)]
fn serve(
    listener: UnixListener,
    woken: std::os::fd::OwnedFd,
    allow: Arc<BTreeSet<Domain>>,
    resolve: Resolver,
    stop: Arc<AtomicBool>,
    denied: Arc<Mutex<Denied>>,
    upstreams: Upstreams,
) {
    let active = Arc::new(AtomicUsize::new(0));
    let mut number = 0u64;
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let mut fds = [
            libc::pollfd {
                fd: std::os::fd::AsRawFd::as_raw_fd(&listener),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: std::os::fd::AsRawFd::as_raw_fd(&woken),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: valid pollfds for the duration of the call.
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 || fds[1].revents != 0 {
            if fds[1].revents != 0 {
                return;
            }
            continue;
        }
        let conn = match listener.accept() {
            Ok((conn, _)) => conn,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(_) => {
                // Out of descriptors, say: give connections a chance to end.
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        let _ = conn.set_nonblocking(false);
        if active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
            continue;
        }
        active.fetch_add(1, Ordering::SeqCst);
        number += 1;
        let allow = allow.clone();
        let resolve = resolve.clone();
        let denied = denied.clone();
        let done = active.clone();
        let upstreams = upstreams.clone();
        let stop = stop.clone();
        let spawned = std::thread::Builder::new()
            .name("proxy connection".into())
            .spawn(move || {
                let open = Open {
                    upstreams: &upstreams,
                    stop: &stop,
                    denied: &denied,
                    number,
                };
                let _ = handle(conn, &allow, &*resolve, &open);
                lock(&upstreams).remove(&number);
                done.fetch_sub(1, Ordering::SeqCst);
            });
        if spawned.is_err() {
            active.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// Where a connection records its host connection.
struct Open<'a> {
    upstreams: &'a Upstreams,
    stop: &'a AtomicBool,
    denied: &'a Mutex<Denied>,
    number: u64,
}

impl Open<'_> {
    /// Records that `host` was refused, before the client hears of it.
    fn deny(&self, host: &str) -> Refusal {
        let mut denied = lock(self.denied);
        denied.count += 1;
        if denied.hosts.len() < MAX_DENIED_KEPT && !denied.hosts.iter().any(|h| h == host) {
            // The sandbox's text: kept short.
            denied.hosts.push(host.chars().take(253).collect());
        }
        Refusal::Denied
    }

    /// Records `upstream`, unless the proxy is stopping, when it is shut
    /// down instead.
    fn record(&self, upstream: &TcpStream) -> bool {
        let mut upstreams = lock(self.upstreams);
        // Under the lock, so a stopping proxy either sees this one or this
        // one sees it stopping.
        if self.stop.load(Ordering::SeqCst) {
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
    /// The host, as the client named it, is not allowed: not in the list,
    /// only host-local addresses, or a mismatched server name.
    Denied,
    /// Anything else: a malformed request, a lost client, an unreachable
    /// host.
    Failed,
}

/// The two ways of asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Http,
    Socks5,
}

/// Serves one client: reads its request, checks it, connects, checks the
/// TLS server name, and then relays both ways until either side closes.
fn handle(
    mut client: UnixStream,
    allow: &BTreeSet<Domain>,
    resolve: &(dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync),
    open: &Open<'_>,
) -> Result<(), Refusal> {
    let _ = client.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
    let mut first = [0u8; 1];
    client.read_exact(&mut first).map_err(|_| Refusal::Failed)?;
    let protocol = if first[0] == 5 {
        Protocol::Socks5
    } else {
        Protocol::Http
    };
    let target = match protocol {
        Protocol::Socks5 => socks5_request(&mut client, open)?,
        Protocol::Http => http_request(&mut client, first[0])?,
    };
    let refuse = |client: &mut UnixStream, why: Why| {
        let _ = reply_refusal(client, protocol, &target.0, why);
    };
    let Some(host) = allowed_host(&target.0, allow) else {
        let denied = open.deny(&target.0);
        refuse(&mut client, Why::NotAllowed);
        return Err(denied);
    };
    let addrs = match resolve(&host, target.1) {
        Ok(addrs) => addrs,
        Err(_) => {
            refuse(&mut client, Why::Unresolved);
            return Err(Refusal::Failed);
        }
    };
    let usable: Vec<SocketAddr> = addrs
        .iter()
        .copied()
        .filter(|a| !is_host_local(a.ip()))
        .collect();
    if usable.is_empty() {
        if addrs.is_empty() {
            refuse(&mut client, Why::Unresolved);
            return Err(Refusal::Failed);
        }
        let denied = open.deny(&host);
        refuse(&mut client, Why::HostLocal);
        return Err(denied);
    }
    let Some(upstream) = usable
        .iter()
        .find_map(|a| TcpStream::connect_timeout(a, CONNECT_TIMEOUT).ok())
    else {
        refuse(&mut client, Why::Unreachable);
        return Err(Refusal::Failed);
    };
    if !open.record(&upstream) {
        return Err(Refusal::Failed);
    }
    reply_success(&mut client, protocol).map_err(|_| Refusal::Failed)?;
    let hello = read_client_hello(&mut client).map_err(|_| Refusal::Failed)?;
    if hello.first() == Some(&TLS_HANDSHAKE) {
        match server_name(&hello) {
            Some(name) if normalize(&name) == host => {}
            // A handshake for another name, or for none: closed, without a
            // byte to the host.
            _ => return Err(open.deny(&host)),
        }
    }
    let _ = client.set_read_timeout(None);
    relay(client, upstream, &hello);
    Ok(())
}

/// Why a request is refused, for the reply.
#[derive(Debug, Clone, Copy)]
enum Why {
    NotAllowed,
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

/// Whether `ip` belongs to the host itself or its link: loopback,
/// unspecified, link-local, and their IPv4-mapped IPv6 forms.
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
fn http_request(client: &mut UnixStream, first: u8) -> Result<(String, u16), Refusal> {
    let mut head = vec![first];
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_REQUEST_HEAD {
            let _ = write_http(client, 431, "Request Header Fields Too Large", "");
            return Err(Refusal::Failed);
        }
        client.read_exact(&mut byte).map_err(|_| Refusal::Failed)?;
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

/// `host:port`, where the host is not bracketed: a name.
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
fn socks5_request(client: &mut UnixStream, open: &Open<'_>) -> Result<(String, u16), Refusal> {
    let mut count = [0u8; 1];
    client.read_exact(&mut count).map_err(|_| Refusal::Failed)?;
    let mut methods = vec![0u8; count[0] as usize];
    client
        .read_exact(&mut methods)
        .map_err(|_| Refusal::Failed)?;
    if !methods.contains(&0) {
        // No method without authentication on offer.
        let _ = client.write_all(&[5, 0xff]);
        return Err(Refusal::Failed);
    }
    client.write_all(&[5, 0]).map_err(|_| Refusal::Failed)?;
    let mut request = [0u8; 4];
    client
        .read_exact(&mut request)
        .map_err(|_| Refusal::Failed)?;
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
            client.read_exact(&mut len).map_err(|_| Refusal::Failed)?;
            let mut name = vec![0u8; len[0] as usize];
            client.read_exact(&mut name).map_err(|_| Refusal::Failed)?;
            String::from_utf8_lossy(&name).into_owned()
        }
        1 | 4 => {
            // An address: the allowlist holds names only.
            let mut rest = vec![0u8; if kind == 1 { 4 } else { 16 } + 2];
            client.read_exact(&mut rest).map_err(|_| Refusal::Failed)?;
            let ip: IpAddr = if kind == 1 {
                <[u8; 4]>::try_from(&rest[..4]).unwrap().into()
            } else {
                <[u8; 16]>::try_from(&rest[..16]).unwrap().into()
            };
            let denied = open.deny(&ip.to_string());
            let _ = socks5_reply(client, 2);
            return Err(denied);
        }
        _ => {
            let _ = socks5_reply(client, 8);
            return Err(Refusal::Failed);
        }
    };
    let mut port = [0u8; 2];
    client.read_exact(&mut port).map_err(|_| Refusal::Failed)?;
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
    // The host is the sandbox's text: shown escaped, cut short.
    let shown: String = crate::escape::escape_message(host)
        .chars()
        .take(256)
        .collect();
    let (status, reason, socks, body) = match why {
        Why::NotAllowed => (
            403,
            "Forbidden",
            2,
            format!("stopit: {shown} is not in network.allow_domains\n"),
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

/// The first byte of a TLS handshake record.
const TLS_HANDSHAKE: u8 = 0x16;

/// Reads the client's first bytes: one read when they do not start a TLS
/// handshake, else whole records until the ClientHello is complete, at
/// most [`MAX_CLIENT_HELLO`] bytes.
fn read_client_hello(client: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut data = vec![0u8; 4096];
    let n = client.read(&mut data)?;
    data.truncate(n);
    if data.first() != Some(&TLS_HANDSHAKE) {
        return Ok(data);
    }
    let mut chunk = [0u8; 4096];
    while !client_hello_complete(&data) {
        if data.len() >= MAX_CLIENT_HELLO {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ClientHello too long",
            ));
        }
        let n = client.read(&mut chunk)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        data.extend_from_slice(&chunk[..n]);
    }
    Ok(data)
}

/// The handshake bytes in the TLS records at the start of `data`, as far
/// as they are complete.
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

/// Whether `data` holds a whole handshake message in its first TLS
/// records.
fn client_hello_complete(data: &[u8]) -> bool {
    let handshake = handshake_bytes(data);
    if handshake.len() < 4 {
        return false;
    }
    let len = u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]]) as usize;
    handshake.len() >= 4 + len
}

/// The server name of the TLS ClientHello at the start of `data`: the
/// `host_name` entry of its `server_name` extension, if it has exactly one
/// such entry.
pub fn server_name(data: &[u8]) -> Option<String> {
    let handshake = handshake_bytes(data);
    let mut r = Reader(&handshake);
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
/// sending `upstream` the client's bytes read so far.
fn relay(client: UnixStream, upstream: TcpStream, first: &[u8]) {
    let (Ok(client_reader), Ok(upstream_writer)) = (client.try_clone(), upstream.try_clone())
    else {
        return;
    };
    let first = first.to_vec();
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

/// The bridge in the sandbox: accepts connections on `listeners` and passes
/// each to the proxy socket at `socket`, until `parent`, a pidfd of the
/// sandbox's first process, says it has exited.
pub fn run_bridge(
    listeners: Vec<std::net::TcpListener>,
    socket: &Path,
    parent: std::os::fd::OwnedFd,
) -> ! {
    use std::os::fd::AsRawFd;
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
            std::process::exit(1);
        }
        if fds[0].revents != 0 {
            std::process::exit(0);
        }
        for (listener, pollfd) in listeners.iter().zip(&fds[1..]) {
            if pollfd.revents == 0 {
                continue;
            }
            let Ok((conn, _)) = listener.accept() else {
                continue;
            };
            if active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
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
    use std::net::{Ipv4Addr, Ipv6Addr, TcpListener, UdpSocket};

    /// A ClientHello naming `names` in its `server_name` extension (none
    /// at all without names), cut into TLS records of at most `record`
    /// bytes.
    fn client_hello(names: &[&str], record: usize) -> Vec<u8> {
        let mut extensions = Vec::new();
        // An extension before the server name, which the parser skips.
        extensions.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
        if !names.is_empty() {
            let mut list = Vec::new();
            for name in names {
                list.push(0);
                list.extend_from_slice(&(name.len() as u16).to_be_bytes());
                list.extend_from_slice(name.as_bytes());
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
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
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

    #[test]
    fn the_server_name_is_read_from_whole_records_only() {
        for record in [16384, 40, 7] {
            let hello = client_hello(&["example.org"], record);
            assert_eq!(server_name(&hello).as_deref(), Some("example.org"));
            assert!(client_hello_complete(&hello), "{record}");
            // Cut short, it is incomplete and names nothing.
            let cut = &hello[..hello.len() - 1];
            assert!(!client_hello_complete(cut), "{record}");
            assert_eq!(server_name(cut), None);
        }
        assert_eq!(server_name(&client_hello(&[], 16384)), None);
        // Two names are ambiguous.
        assert_eq!(server_name(&client_hello(&["a.org", "b.org"], 16384)), None);
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
    fn the_report_names_the_first_hosts_and_counts_all() {
        assert_eq!(denied_report(&[], 0), None);
        assert_eq!(
            denied_report(&["a.org".into()], 1).unwrap(),
            "the network proxy refused 1 connection, to a.org; allow a domain with \
             network.allow_domains"
        );
        let many: Vec<String> = (0..MAX_DENIED_KEPT).map(|i| format!("h{i}.org")).collect();
        let report = denied_report(&many, 30).unwrap();
        assert!(report.contains("refused 30 connections"), "{report}");
        assert!(report.contains("h9.org, ..."), "{report}");
    }

    /// A non-loopback address of this host to listen on, which the proxy
    /// does not refuse, or `None` without one.
    fn host_address() -> Option<IpAddr> {
        let probe = UdpSocket::bind("0.0.0.0:0").ok()?;
        // No packet is sent: connecting a UDP socket only picks a route.
        probe.connect("192.0.2.1:9").ok()?;
        let ip = probe.local_addr().ok()?.ip();
        (!is_host_local(ip)).then_some(ip)
    }

    /// A proxy allowing `allowed.test` and `local.test`, the first resolving
    /// to `upstream`, the second to the host's loopback.
    struct Fixture {
        proxy: Proxy,
        _dir: tempfile::TempDir,
    }

    fn fixture(upstream: SocketAddr) -> Fixture {
        let dir = tempfile::TempDir::new().unwrap();
        let allow: BTreeSet<Domain> = ["allowed.test", "local.test", "nowhere.test"]
            .into_iter()
            .map(|d| d.parse().unwrap())
            .collect();
        let resolve: Resolver = Arc::new(move |host, port| match host {
            "allowed.test" => Ok(vec![SocketAddr::new(upstream.ip(), port)]),
            "local.test" => Ok(vec![
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port),
                SocketAddr::new("::ffff:127.0.0.1".parse().unwrap(), port),
            ]),
            _ => Err(io::Error::other("no such host")),
        });
        let proxy = Proxy::start_with(dir.path().join("p.sock"), allow, resolve).unwrap();
        Fixture { _dir: dir, proxy }
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
            if conn.read(&mut byte).unwrap() == 0 {
                break;
            }
            head.push(byte[0]);
        }
        String::from_utf8_lossy(&head).into_owned()
    }

    /// An upstream server that answers each connection with `pong` after
    /// reading what it is sent until the sender stops writing, and reports
    /// what it read.
    fn upstream(ip: IpAddr) -> (SocketAddr, std::sync::mpsc::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind((ip, 0)).unwrap();
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

    #[test]
    fn connect_with_a_matching_server_name_reaches_the_host() {
        let Some(ip) = host_address() else {
            eprintln!("skipping: no non-loopback address");
            return;
        };
        let (addr, got) = upstream(ip);
        let f = fixture(addr);
        let hello = client_hello(&["ALLOWED.test"], 30);
        let mut conn = f.connect();
        write!(
            conn,
            "CONNECT Allowed.Test.:{} HTTP/1.1\r\nHost: x\r\n\r\n",
            addr.port()
        )
        .unwrap();
        assert_eq!(
            response_head(&mut conn),
            "HTTP/1.1 200 Connection established\r\n\r\n"
        );
        conn.write_all(&hello).unwrap();
        conn.write_all(b"after").unwrap();
        conn.shutdown(Shutdown::Write).unwrap();
        assert_eq!(rest(&mut conn), b"pong");
        let mut want = hello.clone();
        want.extend_from_slice(b"after");
        assert_eq!(got.recv_timeout(Duration::from_secs(10)).unwrap(), want);
        assert_eq!(f.proxy.denied(), (vec![], 0));

        // Bytes that do not start a handshake pass unchecked.
        let mut conn = f.connect();
        write!(
            conn,
            "CONNECT allowed.test:{} HTTP/1.0\r\n\r\n",
            addr.port()
        )
        .unwrap();
        response_head(&mut conn);
        conn.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        conn.shutdown(Shutdown::Write).unwrap();
        assert_eq!(rest(&mut conn), b"pong");
        assert_eq!(
            got.recv_timeout(Duration::from_secs(10)).unwrap(),
            b"GET / HTTP/1.1\r\n\r\n"
        );
    }

    #[test]
    fn a_handshake_for_another_name_or_none_never_reaches_the_host() {
        let Some(ip) = host_address() else {
            eprintln!("skipping: no non-loopback address");
            return;
        };
        let (addr, got) = upstream(ip);
        let f = fixture(addr);
        for names in [
            &["evil.example"][..],
            &[],
            &["allowed.test", "evil.example"],
        ] {
            let mut conn = f.connect();
            write!(
                conn,
                "CONNECT allowed.test:{} HTTP/1.1\r\n\r\n",
                addr.port()
            )
            .unwrap();
            assert!(response_head(&mut conn).starts_with("HTTP/1.1 200"));
            conn.write_all(&client_hello(names, 16384)).unwrap();
            assert_eq!(rest(&mut conn), b"", "{names:?}");
            // The host saw the connection close with nothing sent.
            assert_eq!(
                got.recv_timeout(Duration::from_secs(10)).unwrap(),
                b"",
                "{names:?}"
            );
        }
        assert_eq!(f.proxy.denied(), (vec!["allowed.test".to_owned()], 3));
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
        let (head, body) = ask("CONNECT other.test:443 HTTP/1.1\r\n\r\n");
        assert!(head.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{head}");
        assert_eq!(body, "stopit: other.test is not in network.allow_domains\n");
        // A name resolving only to the host's loopback, in any form.
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
        let (hosts, count) = f.proxy.denied();
        assert_eq!(count, 3, "{hosts:?}");
        assert_eq!(hosts[..2], ["other.test", "local.test"]);
    }

    #[test]
    fn socks5_connects_by_name_only() {
        let Some(ip) = host_address() else {
            eprintln!("skipping: no non-loopback address");
            return;
        };
        let (addr, got) = upstream(ip);
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
        let name = |host: &str, port: u16| {
            let mut r = vec![5, 1, 0, 3, host.len() as u8];
            r.extend_from_slice(host.as_bytes());
            r.extend_from_slice(&port.to_be_bytes());
            r
        };
        let (mut conn, code) = socks(&name("allowed.test", addr.port()));
        assert_eq!(code, 0);
        conn.write_all(b"raw").unwrap();
        conn.shutdown(Shutdown::Write).unwrap();
        assert_eq!(rest(&mut conn), b"pong");
        assert_eq!(got.recv_timeout(Duration::from_secs(10)).unwrap(), b"raw");
        // Not listed, an address, or another command.
        assert_eq!(socks(&name("other.test", 443)).1, 2);
        let mut v4 = vec![5, 1, 0, 1];
        v4.extend_from_slice(&[93, 184, 215, 14, 1, 187]);
        assert_eq!(socks(&v4).1, 2);
        let mut bind = name("allowed.test", 443);
        bind[1] = 2;
        assert_eq!(socks(&bind).1, 7);
        // A client offering only authentication is turned away.
        let mut conn = f.connect();
        conn.write_all(&[5, 1, 2]).unwrap();
        let mut choice = [0u8; 2];
        conn.read_exact(&mut choice).unwrap();
        assert_eq!(choice, [5, 0xff]);
        assert_eq!(f.proxy.denied().1, 2);
    }

    #[test]
    fn stopping_the_proxy_ends_its_connections_and_removes_the_socket() {
        let Some(ip) = host_address() else {
            eprintln!("skipping: no non-loopback address");
            return;
        };
        // An upstream that never closes.
        let listener = TcpListener::bind((ip, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let held = std::thread::spawn(move || listener.accept().map(|(conn, _)| conn));
        let f = fixture(addr);
        let mut conn = f.connect();
        write!(
            conn,
            "CONNECT allowed.test:{} HTTP/1.1\r\n\r\n",
            addr.port()
        )
        .unwrap();
        assert!(response_head(&mut conn).starts_with("HTTP/1.1 200"));
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
}
