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
