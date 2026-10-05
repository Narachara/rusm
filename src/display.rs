//! Plain-text rendering, rappel style. The TUI will render `RegState`
//! directly; this is for pipe mode and the line REPL.

use std::fmt::Write;

use crate::arch::{Insn, RegState};
use crate::session::Outcome;
use crate::tracee::Output;

const HIGHLIGHT: &str = "\x1b[1;31m";
const RESET: &str = "\x1b[0m";

pub fn regs(cur: &RegState, prev: Option<&RegState>, all: bool, color: bool) -> String {
    let mut out = String::new();
    let hl = |changed: bool, s: String| {
        if color && changed {
            format!("{HIGHLIGHT}{s}{RESET}")
        } else {
            s
        }
    };

    for row in cur.gp.chunks(3) {
        let cells: Vec<_> = row
            .iter()
            .map(|r| {
                let changed = prev
                    .and_then(|p| p.gp.iter().find(|o| o.name == r.name))
                    .is_some_and(|o| o.value != r.value);
                format!("{:>3}={}", r.name, hl(changed, format!("{:016x}", r.value)))
            })
            .collect();
        writeln!(out, "{}", cells.join(" ")).unwrap();
    }

    let flags: Vec<_> = cur
        .flags
        .iter()
        .map(|f| {
            let changed = prev
                .and_then(|p| p.flags.iter().find(|o| o.name == f.name))
                .is_some_and(|o| o.set != f.set);
            format!("{}:{}", f.name, hl(changed, (f.set as u8).to_string()))
        })
        .collect();
    writeln!(out, "[{}]", flags.join(", ")).unwrap();

    let segs: Vec<_> = cur
        .extra
        .iter()
        .filter(|r| !r.name.ends_with("_base"))
        .map(|r| format!("{}={:04x}", r.name, r.value))
        .collect();
    writeln!(
        out,
        "{}            {}={:08x}",
        segs.join("  "),
        cur.flags_name,
        cur.flags_raw
    )
    .unwrap();

    if all {
        for (name, v) in &cur.vector {
            let changed = prev
                .and_then(|p| p.vector.iter().find(|o| &o.0 == name))
                .is_some_and(|o| o.1 != *v);
            writeln!(out, "{name:>6}={}", hl(changed, format!("{v:032x}"))).unwrap();
        }
    }
    out
}

pub fn outcome(o: &Outcome) -> Option<String> {
    match o {
        Outcome::Done => None,
        Outcome::Signal { sig, addr: Some(a) } => Some(format!("stopped: {sig} at {a:#x}")),
        Outcome::Signal { sig, addr: None } => Some(format!("stopped: {sig}")),
        Outcome::StrayTrap { at } => Some(format!(
            "stopped at {at:#x} before the end of the code: ran into a label with no code after it, \
             a function without `ret`, or an int3"
        )),
        Outcome::Timeout => Some("stopped: timed out (still running, interrupted)".into()),
        Outcome::WaitingForInput => Some(
            "waiting for input on stdin: .input TEXT sends TEXT and a newline, .eof closes stdin"
                .into(),
        ),
        Outcome::Exited { status } => {
            let why = if libc::WIFSIGNALED(*status) {
                format!("killed by signal {}", libc::WTERMSIG(*status))
            } else {
                format!("exited with code {}", libc::WEXITSTATUS(*status))
            };
            Some(format!("process {why}; started a fresh one"))
        }
    }
}

pub fn disasm(insns: &[Insn]) -> String {
    let mut out = String::new();
    for i in insns {
        let bytes: String = i.bytes.iter().map(|b| format!("{b:02x}")).collect();
        writeln!(out, "{:016x}  {bytes:<20} {}", i.addr, i.text).unwrap();
    }
    out
}

pub fn hexdump(addr: u64, data: &[u8]) -> String {
    let mut out = String::new();
    for (i, row) in data.chunks(16).enumerate() {
        let hex: Vec<_> = row.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = row
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        writeln!(
            out,
            "{:016x}  {:<47}  {ascii}",
            addr + (i * 16) as u64,
            hex.join(" ")
        )
        .unwrap();
    }
    out
}

/// Program output for plain text modes: stdout as is, stderr lines marked.
pub fn output(out: &Output) -> String {
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    if !s.is_empty() && !s.ends_with('\n') {
        s.push('\n');
    }
    for line in String::from_utf8_lossy(&out.stderr).lines() {
        writeln!(s, "stderr: {line}").unwrap();
    }
    s
}
