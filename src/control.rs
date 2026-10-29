//! The control socket between `stopit run` and `stopit server` (DESIGN.md
//! §5.5).
//!
//! The server listens on a Unix stream socket in its session's private
//! `control/` directory and accepts connections only from its own user
//! ([`peer_uid`]). A client first sends one byte carrying the three
//! descriptors that become the sandbox's stdin, stdout and stderr
//! ([`send_stdio`]), then frames, each a 4-byte big-endian length and that
//! many bytes of JSON, at most [`MAX_FRAME`]. Byte strings, which need not
//! be UTF-8, travel as hex.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// The largest frame either side accepts. It has room for a command line
/// and an environment as large as the kernel allows (`ARG_MAX`, 2 MiB), in
/// hex.
pub const MAX_FRAME: usize = 8 << 20;

/// What a client asks of the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientMessage {
    /// Run a command in a profile's sandbox, on the descriptors sent first.
    Run {
        /// `--profile`, if given.
        profile: Option<String>,
        /// The command and its arguments.
        #[serde(with = "hex_list")]
        command: Vec<Vec<u8>>,
        /// The client's whole environment, which the server filters for the
        /// profile.
        #[serde(with = "hex_pairs")]
        env: Vec<(Vec<u8>, Vec<u8>)>,
        /// Whether the descriptors include the slave of the client's PTY.
        pty: bool,
        /// `--quiet`: no startup summary.
        quiet: bool,
    },
    /// A signal the client caught, for the server to pass to the sandbox.
    Signal {
        /// The signal number.
        signal: i32,
    },
}

/// What the server tells a client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServerMessage {
    /// The sandbox started; print these lines (warnings and the summary,
    /// formatted and escaped) to stderr.
    Started {
        /// The lines.
        lines: Vec<String>,
        /// Whether the client's output filter passes OSC 52 clipboard
        /// writes (`terminal.clipboard_write = "allow"`).
        clipboard_allow: bool,
    },
    /// The sandbox ended; exit with this status.
    Exit {
        /// The exit status.
        code: u8,
    },
    /// The request failed before the sandbox started.
    Error {
        /// What went wrong, unescaped.
        message: String,
    },
}

/// Name and value pairs of byte strings, as an environment.
type BytePairs = Vec<(Vec<u8>, Vec<u8>)>;

/// Hex encoding of byte strings in JSON.
mod hex_list {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub(super) fn decode<E: serde::de::Error>(s: &str) -> Result<Vec<u8>, E> {
        if s.len() % 2 != 0 {
            return Err(E::custom("odd-length hex string"));
        }
        (0..s.len())
            .step_by(2)
            .map(|i| {
                s.get(i..i + 2)
                    .filter(|pair| pair.bytes().all(|b| b.is_ascii_hexdigit()))
                    .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                    .ok_or_else(|| E::custom("invalid hex string"))
            })
            .collect()
    }

    pub(super) fn serialize<S: Serializer>(list: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(list.iter().map(|b| encode(b)))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|s| decode(s))
            .collect()
    }
}

/// Hex encoding of pairs of byte strings in JSON.
mod hex_pairs {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::hex_list::{decode, encode};

    pub(super) fn serialize<S: Serializer>(
        pairs: &[(Vec<u8>, Vec<u8>)],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.collect_seq(pairs.iter().map(|(k, v)| (encode(k), encode(v))))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<super::BytePairs, D::Error> {
        Vec::<(String, String)>::deserialize(d)?
            .iter()
            .map(|(k, v)| Ok((decode(k)?, decode(v)?)))
            .collect()
    }
}

/// Writes `message` as one frame.
pub fn write_frame<T: Serialize>(mut sock: &UnixStream, message: &T) -> io::Result<()> {
    let body = serde_json::to_vec(message).map_err(io::Error::other)?;
    if body.len() > MAX_FRAME {
        return Err(io::Error::other(format!(
            "the request is {} bytes, more than the {MAX_FRAME} a control message may have; \
             the command line or the environment is too large",
            body.len()
        )));
    }
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    sock.write_all(&frame)
}

/// Reads one frame, or `None` at the end of the stream between frames.
pub fn read_frame<T: DeserializeOwned>(mut sock: &UnixStream) -> io::Result<Option<T>> {
    let mut len = [0u8; 4];
    match sock.read(&mut len[..1])? {
        0 => return Ok(None),
        _ => sock.read_exact(&mut len[1..])?,
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control message too large",
        ));
    }
    let mut body = vec![0u8; len];
    sock.read_exact(&mut body)?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Sends `fds` (stdin, stdout and stderr for the sandbox) with one byte.
pub fn send_stdio(sock: &UnixStream, fds: [BorrowedFd<'_>; 3]) -> io::Result<()> {
    let raw: [RawFd; 3] = fds.map(|fd| fd.as_raw_fd());
    let byte = *b"F";
    let mut iov = libc::iovec {
        iov_base: byte.as_ptr() as *mut libc::c_void,
        iov_len: 1,
    };
    // SAFETY: `CMSG_SPACE` is a pure computation.
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of_val(&raw) as u32) } as usize;
    let mut control = vec![0u8; space];
    // SAFETY: `msg` points at `iov` and `control`, both alive for the call;
    // the control buffer is `CMSG_SPACE` bytes for three descriptors, and
    // the header and data are written within it.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(&raw) as u32) as _;
        std::ptr::copy_nonoverlapping(
            raw.as_ptr().cast::<u8>(),
            libc::CMSG_DATA(cmsg),
            std::mem::size_of_val(&raw),
        );
        loop {
            match libc::sendmsg(sock.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) {
                1 => return Ok(()),
                -1 if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => {}
                -1 => return Err(io::Error::last_os_error()),
                _ => return Err(io::Error::other("short write of the descriptor byte")),
            }
        }
    }
}

/// Receives the byte [`send_stdio`] sends and exactly three descriptors
/// with it, close-on-exec. Anything else is an error, and every descriptor
/// received is closed.
pub fn recv_stdio(sock: &UnixStream) -> io::Result<[OwnedFd; 3]> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // Room for more than three, so extra descriptors are seen and closed
    // rather than truncated away unnoticed.
    // SAFETY: `CMSG_SPACE` is a pure computation.
    let space = unsafe { libc::CMSG_SPACE((8 * std::mem::size_of::<RawFd>()) as u32) } as usize;
    let mut control = vec![0u8; space];
    let mut received: Vec<OwnedFd> = Vec::new();
    // SAFETY: as in `send_stdio`; the kernel writes at most `space` bytes of
    // control data, and every descriptor read from it is taken ownership of
    // exactly once.
    let (n, flags) = unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        let n = loop {
            let n = libc::recvmsg(sock.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC);
            if n >= 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                break n;
            }
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(cmsg);
                let len = (*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                for i in 0..len / std::mem::size_of::<RawFd>() {
                    let fd = std::ptr::read_unaligned(data.cast::<RawFd>().add(i));
                    received.push(OwnedFd::from_raw_fd(fd));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
        (n, msg.msg_flags)
    };
    if n != 1 || byte[0] != b'F' || flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the client did not send its descriptors",
        ));
    }
    let count = received.len();
    received.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the client sent {count} descriptors instead of 3"),
        )
    })
}

/// The user id of the process at the other end of `sock`.
pub fn peer_uid(sock: &UnixStream) -> io::Result<u32> {
    Ok(rustix::net::sockopt::socket_peercred(sock)?.uid.as_raw())
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;

    use super::*;

    #[test]
    fn frames_round_trip_and_end_cleanly() {
        let (a, b) = UnixStream::pair().unwrap();
        let run = ClientMessage::Run {
            profile: Some("harness".into()),
            command: vec![b"ls".to_vec(), vec![0xff, b'-']],
            env: vec![(b"TERM".to_vec(), b"xterm".to_vec())],
            pty: true,
            quiet: false,
        };
        write_frame(&a, &run).unwrap();
        write_frame(&a, &ClientMessage::Signal { signal: 2 }).unwrap();
        drop(a);
        assert_eq!(read_frame::<ClientMessage>(&b).unwrap(), Some(run));
        assert_eq!(
            read_frame::<ClientMessage>(&b).unwrap(),
            Some(ClientMessage::Signal { signal: 2 })
        );
        assert_eq!(read_frame::<ClientMessage>(&b).unwrap(), None);
    }

    #[test]
    fn bad_frames_are_errors() {
        // Too long, cut short, and not the expected message.
        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(&(MAX_FRAME as u32 + 1).to_be_bytes()).unwrap();
        assert_eq!(
            read_frame::<ServerMessage>(&b).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(&[0, 0, 0, 9, b'{']).unwrap();
        drop(a);
        assert!(read_frame::<ServerMessage>(&b).is_err());
        let (a, b) = UnixStream::pair().unwrap();
        write_frame(&a, &ClientMessage::Signal { signal: 1 }).unwrap();
        assert!(read_frame::<ServerMessage>(&b).is_err());
        let (mut a, b) = UnixStream::pair().unwrap();
        let body = br#"{"type":"exit","code":0,"extra":1}"#;
        a.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
        a.write_all(body).unwrap();
        assert!(read_frame::<ServerMessage>(&b).is_err());
    }

    #[test]
    fn stdio_descriptors_pass_and_must_be_three() {
        let (a, b) = UnixStream::pair().unwrap();
        let (r, w) = std::io::pipe().unwrap();
        send_stdio(&a, [r.as_fd(), w.as_fd(), w.as_fd()]).unwrap();
        let [fd0, fd1, _fd2] = recv_stdio(&b).unwrap();
        for fd in [&fd0, &fd1] {
            assert!(
                rustix::io::fcntl_getfd(fd)
                    .unwrap()
                    .contains(rustix::io::FdFlags::CLOEXEC)
            );
        }
        rustix::io::write(&fd1, b"x").unwrap();
        let mut buf = [0u8; 1];
        rustix::io::read(&fd0, &mut buf).unwrap();
        assert_eq!(&buf, b"x");

        // A plain byte without descriptors is refused.
        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(b"F").unwrap();
        assert!(recv_stdio(&b).is_err());
        assert_eq!(peer_uid(&b).unwrap(), rustix::process::getuid().as_raw());
    }

    #[test]
    fn byte_strings_travel_as_hex() {
        let run = ClientMessage::Run {
            profile: None,
            command: vec![vec![0x00, 0xff, b'a']],
            env: vec![(b"K".to_vec(), vec![])],
            pty: false,
            quiet: true,
        };
        let json = serde_json::to_string(&run).unwrap();
        assert!(json.contains(r#""command":["00ff61"]"#), "{json}");
        assert!(json.contains(r#""env":[["4b",""]]"#), "{json}");
        for bad in ["0", "zz", "0g", "+f", "-1"] {
            let json = format!(
                r#"{{"type":"run","profile":null,"command":["{bad}"],"env":[],"pty":false,"quiet":false}}"#
            );
            assert!(
                serde_json::from_str::<ClientMessage>(&json).is_err(),
                "{bad}"
            );
        }
    }

    /// Sends `byte` with `fds` attached, as `send_stdio` does.
    fn send_raw(sock: &UnixStream, byte: u8, fds: &[RawFd]) {
        let buf = [byte];
        let mut iov = libc::iovec {
            iov_base: buf.as_ptr() as *mut libc::c_void,
            iov_len: 1,
        };
        let data = std::mem::size_of_val(fds) as u32;
        // SAFETY: as in `send_stdio`, for `fds.len()` descriptors.
        unsafe {
            let space = libc::CMSG_SPACE(data) as usize;
            let mut control = vec![0u8; space.max(1)];
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            if !fds.is_empty() {
                msg.msg_control = control.as_mut_ptr().cast();
                msg.msg_controllen = space as _;
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                (*cmsg).cmsg_level = libc::SOL_SOCKET;
                (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                (*cmsg).cmsg_len = libc::CMSG_LEN(data) as _;
                std::ptr::copy_nonoverlapping(
                    fds.as_ptr().cast::<u8>(),
                    libc::CMSG_DATA(cmsg),
                    data as usize,
                );
            }
            assert_eq!(libc::sendmsg(sock.as_raw_fd(), &msg, 0), 1);
        }
    }

    #[test]
    fn anything_but_three_descriptors_and_the_marker_is_refused() {
        let (r, _w) = std::io::pipe().unwrap();
        let fd = r.as_raw_fd();
        for (byte, count) in [(b'F', 2), (b'F', 4), (b'F', 12), (b'X', 3)] {
            let (a, b) = UnixStream::pair().unwrap();
            send_raw(&a, byte, &vec![fd; count]);
            let e = recv_stdio(&b).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{byte} {count}: {e}");
        }
    }
}
