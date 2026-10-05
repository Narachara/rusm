//! rusm: an assembly REPL. A Rust port of rappel.

use anyhow::{Context, Result};

pub mod arch;
pub mod asm;
pub mod display;
pub mod elf;
pub mod notebook;
pub mod repl;
pub mod session;
pub mod tracee;
pub mod tui;

/// Parse a decimal or `0x`-prefixed hexadecimal number.
pub fn parse_u64(s: &str) -> Result<u64> {
    let r = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => s.parse(),
    };
    r.with_context(|| format!("invalid number: {s}"))
}

/// Parse hex-encoded bytes, e.g. `deadbeef` or `0xdeadbeef`.
pub fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if !s.len().is_multiple_of(2) {
        anyhow::bail!("hex data must have an even number of digits");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(s.get(i..i + 2).context("invalid hex")?, 16).context("invalid hex")
        })
        .collect()
}

/// Decode `\n`, `\t`, `\r`, `\0`, `\\` and `\xNN` escapes.
pub fn unescape(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            let mut buf = [0; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            continue;
        }
        match chars.next() {
            Some('n') => out.push(b'\n'),
            Some('t') => out.push(b'\t'),
            Some('r') => out.push(b'\r'),
            Some('0') => out.push(0),
            Some('\\') => out.push(b'\\'),
            Some('x') => {
                let hex: String = chars.by_ref().take(2).collect();
                out.push(
                    u8::from_str_radix(&hex, 16).with_context(|| format!("bad escape \\x{hex}"))?,
                );
            }
            other => anyhow::bail!(
                "unknown escape \\{}",
                other.map_or(String::new(), String::from)
            ),
        }
    }
    Ok(out)
}

/// Inverse of [`unescape`] for display and saving: printable ASCII stays,
/// everything else is escaped.
pub fn escape(data: &[u8]) -> String {
    let mut s = String::new();
    for &b in data {
        match b {
            b'\n' => s.push_str("\\n"),
            b'\t' => s.push_str("\\t"),
            b'\r' => s.push_str("\\r"),
            b'\\' => s.push_str("\\\\"),
            0x20..=0x7e => s.push(b as char),
            _ => s.push_str(&format!("\\x{b:02x}")),
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_round_trip() {
        let raw = b"hi\n\t\\\x00\xff";
        assert_eq!(unescape(&escape(raw)).unwrap(), raw);
        assert_eq!(unescape(r"a\x41\n").unwrap(), b"aA\n");
        assert!(unescape(r"\q").is_err());
    }
}
