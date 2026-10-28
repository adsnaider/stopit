//! Making untrusted text safe to print on the user's terminal.
//!
//! Anything stopit prints can carry bytes that configuration, a script
//! provider or the filesystem (often sandbox-writable) control: paths,
//! patterns, a script's stderr, a command name. Printed raw, a terminal
//! escape sequence in them could rewrite the screen, set the clipboard or
//! worse (DESIGN.md §5.3). Two functions, for two shapes of text:
//!
//! * [`escape_bytes`] for one value, such as a command name: unambiguous,
//!   so `\` is escaped too and every byte can be told apart.
//! * [`escape_message`] for a whole rendered message (an error or warning
//!   with its values already formatted in, often with `{:?}`): the same
//!   characters are escaped, but `\` is kept, so the escapes `{:?}` already
//!   wrote are not doubled, and so are line breaks and tabs, which messages
//!   use for layout (a script's stderr spans lines). Safe, not unambiguous:
//!   a message is no single value to recover anyway.
//!
//! [`shell_quote`] is for a value inside a command a message suggests
//! (`stopit allow --workspace <dir>`): quoted for bash and zsh, so that the
//! command can be pasted as printed, and as safe as [`escape_bytes`].
//!
//! Both escape exactly the characters `char::escape_debug` escapes, but for
//! the exceptions named: control characters (C0, DEL and C1, as `\u{1b}`),
//! format characters such as the bidi override U+202E and the zero-width
//! space U+200B, U+2028 and U+2029, and unassigned and private-use ones.

use std::fmt::Write as _;

/// `bytes` as printable text: every character `char::escape_debug` escapes
/// (see the module documentation), bytes that are not UTF-8 as `\xff`, and
/// `\` as `\\`, so the result is unambiguous and carries no terminal escape
/// sequence or text-direction trick. Everything else, other Unicode and
/// quotes included, is kept.
///
/// For one value the sandbox controls (a command name) printed to the
/// user's terminal.
pub fn escape_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            // `escape_debug` also escapes `\`, and the quotes, which stay.
            if matches!(c, '\'' | '"') {
                out.push(c);
            } else {
                out.extend(c.escape_debug());
            }
        }
        for b in chunk.invalid() {
            let _ = write!(out, "\\x{b:02x}");
        }
    }
    out
}

/// `message` with every character escaped that [`escape_bytes`] escapes,
/// except `\`, the quotes, `\n` and `\t`, which are kept (see the module
/// documentation).
///
/// For a whole rendered error or warning printed to the user's terminal.
pub fn escape_message(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    for c in message.chars() {
        if matches!(c, '\\' | '\'' | '"' | '\n' | '\t') {
            out.push(c);
        } else {
            out.extend(c.escape_debug());
        }
    }
    out
}

/// `arg` (a path, say) quoted for bash or zsh, for a command that a message
/// suggests, so that it can be pasted as it is printed: unchanged if every
/// character is one neither treats specially (`A-Z`, `a-z`, `0-9` and
/// `_@%+=:,./-`, but not `=` first, which zsh expands), else in single
/// quotes, each `'` written `'\''`.
///
/// Single quotes cannot hold what [`escape_bytes`] escapes (control
/// characters, and deceptive ones such as bidi overrides and zero-width
/// spaces, which must not reach the terminal) nor bytes that are not UTF-8,
/// so an `arg` with any of these is ANSI-C quoted instead (`$'…'`, which
/// POSIX sh and fish lack), each such byte as `\xHH`, and `\` and `'` as
/// `\\` and `\'`. The result is the same argument, and safe to print:
/// [`escape_message`] leaves it unchanged.
pub fn shell_quote(arg: &[u8]) -> String {
    let plain = |b: u8| b.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&b);
    if arg.first().is_some_and(|&b| b != b'=') && arg.iter().all(|&b| plain(b)) {
        return String::from_utf8_lossy(arg).into_owned();
    }
    // Whether `c` cannot be shown as it is.
    let escaped = |c: char| !matches!(c, '\\' | '\'' | '"') && c.escape_debug().nth(1).is_some();
    let printable = arg
        .utf8_chunks()
        .all(|chunk| chunk.invalid().is_empty() && !chunk.valid().chars().any(escaped));
    if printable {
        let text = String::from_utf8_lossy(arg);
        return format!("'{}'", text.replace('\'', "'\\''"));
    }
    let mut out = String::from("$'");
    for chunk in arg.utf8_chunks() {
        for c in chunk.valid().chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                '\'' => out.push_str("\\'"),
                c if escaped(c) => {
                    for b in c.encode_utf8(&mut [0; 4]).bytes() {
                        let _ = write!(out, "\\x{b:02x}");
                    }
                }
                c => out.push(c),
            }
        }
        for b in chunk.invalid() {
            let _ = write!(out, "\\x{b:02x}");
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_makes_control_bytes_and_invalid_utf8_visible() {
        assert_eq!(escape_bytes(b"plain-name_1.2"), "plain-name_1.2");
        assert_eq!(escape_bytes("héllo ✓".as_bytes()), "héllo ✓");
        assert_eq!(escape_bytes(b"a\x1b[2Jb"), "a\\u{1b}[2Jb");
        assert_eq!(escape_bytes(b"a\nb\tc\rd"), "a\\nb\\tc\\rd");
        assert_eq!(escape_bytes(b"\x7f"), "\\u{7f}");
        // C1, as UTF-8.
        assert_eq!(escape_bytes("\u{9b}".as_bytes()), "\\u{9b}");
        assert_eq!(escape_bytes(b"x\xff\xfey"), "x\\xff\\xfey");
        assert_eq!(escape_bytes(b"back\\slash"), "back\\\\slash");
        for b in 0u8..=255 {
            let escaped = escape_bytes(&[b]);
            assert!(
                !escaped.chars().any(char::is_control),
                "{b:#x}: {escaped:?}"
            );
        }
    }

    #[test]
    fn escaping_covers_format_and_separator_characters() {
        // Bidi override, zero-width space, line and paragraph separators:
        // invisible or deceptive, so shown by code point.
        let both: [fn(&[u8]) -> String; 2] = [escape_bytes, |b| {
            escape_message(std::str::from_utf8(b).unwrap())
        }];
        for f in both {
            assert_eq!(f("a\u{202e}b".as_bytes()), "a\\u{202e}b");
            assert_eq!(f("a\u{200b}b".as_bytes()), "a\\u{200b}b");
            assert_eq!(f("a\u{2028}b".as_bytes()), "a\\u{2028}b");
            assert_eq!(f("a\u{2029}b".as_bytes()), "a\\u{2029}b");
            // Quotes are kept, as plain text.
            assert_eq!(f(b"it's \"x\""), "it's \"x\"");
        }
    }

    #[test]
    fn shell_quoting_quotes_only_what_needs_it() {
        // Plain paths print as they are.
        assert_eq!(shell_quote(b"/home/u/proj-1.2/a_b"), "/home/u/proj-1.2/a_b");
        assert_eq!(shell_quote(b"/a/b@c%d+e=f:g,h"), "/a/b@c%d+e=f:g,h");
        // Anything else in single quotes, `'` closed, escaped and reopened;
        // `=` first too, which zsh would expand (`=ls` is `/bin/ls`).
        assert_eq!(shell_quote(b"=ls"), "'=ls'");
        assert_eq!(shell_quote(b""), "''");
        assert_eq!(shell_quote(b"/a b"), "'/a b'");
        assert_eq!(shell_quote(b"/it's"), "'/it'\\''s'");
        assert_eq!(
            shell_quote(b"/$x;`y`*?~!\\\"&|<>(){}[]#"),
            "'/$x;`y`*?~!\\\"&|<>(){}[]#'"
        );
        assert_eq!(shell_quote("/héllo ✓".as_bytes()), "'/héllo ✓'");
        // Control characters, deceptive ones and bytes that are not UTF-8
        // are written as `\xHH` in ANSI-C quotes, the rest kept.
        assert_eq!(shell_quote(b"/a\x1b[2Jb"), "$'/a\\x1b[2Jb'");
        assert_eq!(shell_quote(b"/a\nb"), "$'/a\\x0ab'");
        assert_eq!(shell_quote(b"/x\xff'\\"), "$'/x\\xff\\'\\\\'");
        assert_eq!(shell_quote("/é\u{202e}".as_bytes()), "$'/é\\xe2\\x80\\xae'");
        // What is printed is safe, and left alone by message escaping.
        for b in 0u8..=255 {
            let quoted = shell_quote(&[b'/', b]);
            assert!(!quoted.chars().any(char::is_control), "{b:#x}: {quoted:?}");
            assert_eq!(escape_message(&quoted), quoted, "{b:#x}");
        }
    }

    #[test]
    fn shell_quoting_round_trips_through_bash() {
        // Every byte but NUL (which no path or argument holds), alone and
        // inside a path, and some multibyte and awkward strings: bash reads
        // each back as the original.
        let mut args: Vec<Vec<u8>> = (1u8..=255)
            .flat_map(|b| [vec![b], vec![b'/', b, b'x', b]])
            .collect();
        for s in [
            "",
            "=ls",
            "/héllo ✓",
            "/a\u{202e}b\u{200b}c",
            "/\u{9b}2J",
            "/it's \"x\" \\n $HOME `id` $(id)",
            "/日本語/\u{1f600}",
        ] {
            args.push(s.as_bytes().to_vec());
        }
        args.push(b"/x\xe2\x80/\xff\xfe'\\".to_vec());
        let script = std::iter::once("printf '%s\\0'".to_owned())
            .chain(args.iter().map(|a| shell_quote(a)))
            .collect::<Vec<_>>()
            .join(" ");
        let out = match std::process::Command::new("bash")
            .arg("-c")
            .arg(&script)
            .env("LC_ALL", "C")
            .output()
        {
            Ok(out) => out,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipping: bash is not on PATH");
                return;
            }
            Err(e) => panic!("cannot run bash: {e}"),
        };
        assert!(out.status.success(), "{out:?}");
        let mut back: Vec<&[u8]> = out.stdout.split(|&b| b == 0).collect();
        // After the last NUL.
        assert_eq!(back.pop(), Some(&b""[..]));
        assert_eq!(back.len(), args.len());
        for (arg, back) in args.iter().zip(back) {
            assert_eq!(
                back,
                arg.as_slice(),
                "{:?} as {}",
                escape_bytes(arg),
                shell_quote(arg)
            );
        }
    }

    #[test]
    fn messages_keep_layout_and_existing_escapes() {
        assert_eq!(escape_message("héllo ✓"), "héllo ✓");
        // Line breaks and tabs stay; a carriage return does not (it could
        // overwrite the line it ends).
        assert_eq!(escape_message("a\nb\tc\rd"), "a\nb\tc\\rd");
        // What `{:?}` already escaped is not escaped again.
        let debug = format!("{:?}", "/a\u{1b}b\\c");
        assert_eq!(debug, "\"/a\\u{1b}b\\\\c\"");
        assert_eq!(escape_message(&debug), debug);
        assert_eq!(
            escape_message("x\x1b]52;c;aGk=\x07y"),
            "x\\u{1b}]52;c;aGk=\\u{7}y"
        );
        assert_eq!(escape_message("\u{9b}2J"), "\\u{9b}2J");
        for c in (0u32..=0x10ffff).filter_map(char::from_u32) {
            let escaped = escape_message(c.encode_utf8(&mut [0; 4]));
            assert!(
                escaped
                    .chars()
                    .all(|e| !e.is_control() || e == '\n' || e == '\t'),
                "{c:?}: {escaped:?}"
            );
        }
    }
}
