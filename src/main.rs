//! rusm: an assembly REPL. A Rust port of rappel.

use std::io::{self, IsTerminal, Read};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;

use rusm::arch::{self, ArchKind};
use rusm::notebook::Notebook;
use rusm::session::{self, Outcome, Session};
use rusm::{asm, display, parse_u64, repl, tui};

#[derive(Parser)]
#[command(
    version,
    about = "Assembly REPL: run snippets and inspect registers and memory"
)]
struct Cli {
    /// Notebook file to open (cells separated by `;; %%` lines)
    notebook: Option<PathBuf>,
    /// Target architecture (defaults to the host)
    #[arg(long, value_enum)]
    arch: Option<ArchKind>,
    /// Assembler backend
    #[arg(long = "asm", value_enum, default_value = "nasm")]
    assembler: asm::Backend,
    /// Address code is loaded and executed at (page aligned)
    #[arg(long, default_value = "0x400000", value_parser = parse_u64)]
    start: u64,
    /// Treat stdin as raw machine code instead of assembly
    #[arg(short, long)]
    raw: bool,
    /// Deliver signals to the tracee (lets it die from SIGSEGV etc.)
    #[arg(short, long)]
    pass_signals: bool,
    /// Save the generated tracee executable to FILE
    #[arg(short, long, value_name = "FILE")]
    save: Option<PathBuf>,
    /// Show all registers (vector / FP)
    #[arg(short = 'x', long)]
    allregs: bool,
    /// Show disassembly of executed code
    #[arg(short, long)]
    disasm: bool,
    /// Interrupt code that runs longer than this many milliseconds
    #[arg(long, default_value_t = 1000)]
    timeout_ms: u64,
    /// Feed FILE to the program's stdin in pipe mode (default: empty)
    #[arg(long, value_name = "FILE")]
    stdin: Option<PathBuf>,
    /// Keep address space randomization (stack address differs per run)
    #[arg(long)]
    aslr: bool,
    /// Use the plain line REPL instead of the notebook UI
    #[arg(long)]
    plain: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("rusm: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();

    let kind = match cli.arch.or_else(ArchKind::host) {
        Some(k) => k,
        None => anyhow::bail!("unsupported host architecture; pass --arch"),
    };
    let arch = arch::create(kind);
    let asm = asm::create(cli.assembler, kind)?;
    let mut sess = Session::new(
        arch,
        asm,
        session::Options {
            start: cli.start,
            pass_signals: cli.pass_signals,
            timeout: Duration::from_millis(cli.timeout_ms),
            aslr: cli.aslr,
            save_exe: cli.save,
        },
    )?;

    if io::stdin().is_terminal() && !cli.plain {
        tui::run(Notebook::new(sess)?, cli.notebook)?;
        return Ok(ExitCode::SUCCESS);
    }
    if io::stdin().is_terminal() {
        repl::run(
            &mut sess,
            repl::ReplOpts {
                allregs: cli.allregs,
                disasm: cli.disasm,
            },
        )?;
        return Ok(ExitCode::SUCCESS);
    }

    // Pipe mode: run all of stdin as one snippet and print the result.
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let asm = if cli.raw {
        rusm::asm::Assembled {
            code: input,
            ..Default::default()
        }
    } else {
        match sess.assemble(&String::from_utf8_lossy(&input)) {
            Ok(a) => a,
            Err(errs) => {
                for e in errs {
                    eprintln!("asm error: {e}");
                }
                return Ok(ExitCode::FAILURE);
            }
        }
    };
    if cli.disasm {
        print!(
            "{}",
            display::disasm(
                &sess
                    .arch()
                    .disassemble(&asm.code, sess.start(), &Default::default())
            )
        );
    }
    if let Some(path) = &cli.stdin {
        let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        sess.write_stdin(&data)?;
    }
    // Stdin of rusm is the source code; the program sees EOF after --stdin.
    sess.close_stdin();
    let outcome = sess.run_assembled(&asm)?;
    for ev in sess.take_syscalls() {
        eprintln!("{} = {}  ({})", ev.call, ev.ret, ev.note);
    }
    let out = sess.take_output();
    print!("{}", String::from_utf8_lossy(&out.stdout));
    eprint!("{}", String::from_utf8_lossy(&out.stderr));
    if let Some(msg) = display::outcome(&outcome) {
        eprintln!("{msg}");
    }
    let color = io::stdout().is_terminal();
    print!(
        "{}",
        display::regs(&sess.regs, sess.prev_regs.as_ref(), cli.allregs, color)
    );
    Ok(if outcome == Outcome::Done {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}
