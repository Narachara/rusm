//! Minimal line-based REPL, a stand-in until the ratatui notebook UI lands.

use std::io::{self, BufRead, IsTerminal, Write};

use anyhow::Result;

use crate::display;
use crate::session::{Outcome, Session};

const HELP: &str = "\
Commands:
  .help                 show this help
  .regs                 show registers
  .allregs on|off       also show vector / FP registers
  .disasm on|off        show disassembly of each snippet
  .read ADDR [LEN]      hexdump tracee memory (default 64 bytes)
  .write ADDR HEX       write hex-encoded bytes to tracee memory
  .maps                 show /proc/<pid>/maps
  .begin / .end         collect multiple lines and run them as one block
  .input TEXT           send TEXT and a newline to the program's stdin
                        (escapes: \\n \\t \\0 \\xNN); resumes a waiting read
  .eof                  close the program's stdin
  .restart              start a fresh process
  .quit                 exit
Anything else is assembled and executed.
Data and bss (use .begin / .end for multi-line snippets):
  section .data         initialized data: msg: db \"hi\", 10
  section .rodata       constants, placed after .data
  section .bss          zeroed space: buf: resb 64
  section .text         back to code (snippets start in .text)
  Address data RIP-relative: lea rsi, [rel msg] / mov rax, [rel buf]
  Example:
    .begin
    lea rsi, [rel msg]
    section .data
    msg: db \"hi\", 10
    .end";

pub struct ReplOpts {
    pub allregs: bool,
    pub disasm: bool,
}

pub fn run(sess: &mut Session, mut opts: ReplOpts) -> Result<()> {
    let color = io::stdout().is_terminal();
    let stdin = io::stdin();
    let mut block: Option<String> = None;

    print!("{}", display::regs(&sess.regs, None, opts.allregs, color));

    // End address of a run that is waiting for stdin, to resume it.
    let mut waiting: Option<u64> = None;

    loop {
        print!("{}", if block.is_some() { "... " } else { "> " });
        io::stdout().flush()?;

        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            println!();
            return Ok(());
        }
        let line = line.trim_end_matches('\n');
        let trimmed = line.trim();

        let src = if let Some(buf) = block.as_mut() {
            if trimmed != ".end" {
                buf.push_str(line);
                buf.push('\n');
                continue;
            }
            block.take().unwrap()
        } else if let Some(cmd) = trimmed.strip_prefix('.') {
            let mut args = cmd.split_whitespace();
            let name = args.next().unwrap_or("");
            let res = match name {
                "quit" | "exit" | "q" => return Ok(()),
                "help" | "h" => {
                    println!("{HELP}");
                    Ok(())
                }
                "regs" | "info" => {
                    print!("{}", display::regs(&sess.regs, None, opts.allregs, color));
                    Ok(())
                }
                "allregs" => {
                    opts.allregs = args.next() != Some("off");
                    Ok(())
                }
                "disasm" => {
                    opts.disasm = args.next() != Some("off");
                    Ok(())
                }
                "input" | "eof" => {
                    let res = if name == "eof" {
                        sess.close_stdin();
                        Ok(())
                    } else {
                        let text = cmd.strip_prefix("input").unwrap_or("").trim_start();
                        crate::unescape(text).and_then(|mut d| {
                            d.push(b'\n');
                            sess.write_stdin(&d)
                        })
                    };
                    match (res, waiting.take()) {
                        (Err(e), w) => {
                            waiting = w;
                            Err(e)
                        }
                        (Ok(()), Some(end)) => sess.resume(end).map(|o| {
                            show_run(sess, &o, &opts, color);
                            if o == Outcome::WaitingForInput {
                                waiting = Some(end);
                            }
                        }),
                        (Ok(()), None) => Ok(()),
                    }
                }
                "begin" => {
                    block = Some(String::new());
                    Ok(())
                }
                "maps" | "showmap" => sess.maps().map(|m| print!("{m}")),
                "restart" => sess
                    .restart()
                    .map(|_| print!("{}", display::regs(&sess.regs, None, opts.allregs, color))),
                "read" => cmd_read(sess, args.next(), args.next()),
                "write" => cmd_write(sess, args.next(), args.next()),
                other => {
                    println!("unknown command .{other} (try .help)");
                    Ok(())
                }
            };
            if let Err(e) = res {
                println!("error: {e:#}");
            }
            continue;
        } else if trimmed.is_empty() {
            continue;
        } else {
            line.to_string()
        };

        let asm = match sess.assemble(&src) {
            Ok(a) => a,
            Err(errs) => {
                for e in errs {
                    println!("asm error: {e}");
                }
                continue;
            }
        };
        if asm.code.is_empty() && asm.data.is_empty() {
            continue;
        }
        if opts.disasm {
            print!(
                "{}",
                display::disasm(&sess.arch().disassemble(
                    &asm.code,
                    sess.start(),
                    &Default::default()
                ))
            );
        }
        waiting = None;
        match sess.run_assembled(&asm) {
            Ok(outcome) => {
                show_run(sess, &outcome, &opts, color);
                if outcome == Outcome::WaitingForInput {
                    waiting = Some(sess.start() + asm.code.len() as u64);
                }
            }
            Err(e) => println!("error: {e:#}"),
        }
    }
}

fn show_run(sess: &mut Session, outcome: &Outcome, opts: &ReplOpts, color: bool) {
    for ev in sess.take_syscalls() {
        println!("{} = {}  ({})", ev.call, ev.ret, ev.note);
    }
    print!("{}", display::output(&sess.take_output()));
    if let Some(msg) = display::outcome(outcome) {
        println!("{msg}");
    }
    print!(
        "{}",
        display::regs(&sess.regs, sess.prev_regs.as_ref(), opts.allregs, color)
    );
}

fn cmd_read(sess: &Session, addr: Option<&str>, len: Option<&str>) -> Result<()> {
    let addr = crate::parse_u64(addr.ok_or_else(|| anyhow::anyhow!("usage: .read ADDR [LEN]"))?)?;
    let len = len.map(crate::parse_u64).transpose()?.unwrap_or(64) as usize;
    print!("{}", display::hexdump(addr, &sess.read_mem(addr, len)?));
    Ok(())
}

fn cmd_write(sess: &Session, addr: Option<&str>, hex: Option<&str>) -> Result<()> {
    let (Some(addr), Some(hex)) = (addr, hex) else {
        anyhow::bail!("usage: .write ADDR HEX");
    };
    let addr = crate::parse_u64(addr)?;
    let data = crate::parse_hex(hex)?;
    sess.write_mem(addr, &data)
}
