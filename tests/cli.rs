//! Pipe mode through the real binary.

use std::io::Write;
use std::process::{Command, Stdio};

fn rusm(args: &[&str], src: &str) -> (String, String, bool) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rusm"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(src.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        String::from_utf8_lossy(&out.stdout).into(),
        String::from_utf8_lossy(&out.stderr).into(),
        out.status.success(),
    )
}

#[test]
fn prints_program_output_before_registers() {
    let (out, _, ok) = rusm(
        &[],
        "mov eax, 1\nmov edi, 1\nlea rsi, [rel m]\nmov edx, 3\nsyscall\nsection .data\nm: db \"hi\", 10\n",
    );
    assert!(ok);
    assert!(out.starts_with("hi\nrax=0000000000000003"), "{out}");
}

#[test]
fn stdin_option_feeds_the_program() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("in.txt");
    std::fs::write(&file, "abcdef").unwrap();
    let src = "sub rsp, 64\nxor eax, eax\nxor edi, edi\nmov rsi, rsp\nmov edx, 64\nsyscall\n";
    let (out, _, ok) = rusm(&["--stdin", file.to_str().unwrap()], src);
    assert!(ok);
    assert!(out.starts_with("rax=0000000000000006"), "{out}");
    // without --stdin the program reads EOF instead of hanging
    let (out, _, _) = rusm(&[], src);
    assert!(out.starts_with("rax=0000000000000000"), "{out}");
}
