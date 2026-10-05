//! End-to-end tests: real tracee, real nasm. Require ptrace permission.

use std::time::Duration;

use nix::sys::signal::Signal;
use rusm::arch::{self, ArchKind, RegState};
use rusm::asm::{self, Backend};
use rusm::session::{Options, Outcome, Session};

const START: u64 = 0x400000;

fn session() -> Session {
    let kind = ArchKind::X86_64;
    Session::new(
        arch::create(kind),
        asm::create(Backend::Nasm, kind).unwrap(),
        Options {
            start: START,
            pass_signals: false,
            timeout: Duration::from_millis(300),
            aslr: false,
            save_exe: None,
        },
    )
    .unwrap()
}

fn exec(s: &mut Session, src: &str) -> Outcome {
    let asm = s.assemble(src).expect("assembles");
    s.run_assembled(&asm).unwrap()
}

fn reg(r: &RegState, name: &str) -> u64 {
    r.gp.iter().find(|g| g.name == name).unwrap().value
}

#[test]
fn state_persists_between_runs() {
    let mut s = session();
    assert_eq!(exec(&mut s, "mov rax, 0x1337\npush rax"), Outcome::Done);
    let sp = s.regs.sp;
    assert_eq!(exec(&mut s, "pop rbx\ninc rbx"), Outcome::Done);
    assert_eq!(reg(&s.regs, "rbx"), 0x1338);
    assert_eq!(s.regs.sp, sp + 8);
    assert_eq!(reg(s.prev_regs.as_ref().unwrap(), "rbx"), 0);
}

#[test]
fn pc_points_after_code() {
    let mut s = session();
    exec(&mut s, "nop\nnop\nnop");
    assert_eq!(s.regs.pc, START + 3);
}

#[test]
fn stale_code_is_overwritten() {
    let mut s = session();
    exec(&mut s, "inc rax\ninc rax\ninc rax\ninc rax");
    exec(&mut s, "xor eax, eax");
    let mem = s.read_mem(START, 16).unwrap();
    assert_eq!(&mem[..2], &[0x31, 0xc0]);
    assert!(mem[2..12].iter().all(|&b| b == 0xcc));
}

#[test]
fn segfault_is_reported_not_fatal() {
    let mut s = session();
    assert_eq!(
        exec(&mut s, "mov rax, [0x10]"),
        Outcome::Signal {
            sig: Signal::SIGSEGV,
            addr: Some(0x10)
        }
    );
    assert_eq!(exec(&mut s, "mov rax, 1"), Outcome::Done);
    assert_eq!(reg(&s.regs, "rax"), 1);
}

#[test]
fn exit_respawns_process() {
    let mut s = session();
    exec(&mut s, "mov rbx, 7");
    let Outcome::Exited { status } = exec(&mut s, "mov eax, 60\nmov edi, 42\nsyscall") else {
        panic!("expected exit");
    };
    assert_eq!(libc::WEXITSTATUS(status), 42);
    assert_eq!(exec(&mut s, "nop"), Outcome::Done);
    assert_eq!(reg(&s.regs, "rbx"), 0, "fresh process");
}

#[test]
fn infinite_loop_times_out() {
    let mut s = session();
    assert_eq!(exec(&mut s, "jmp $"), Outcome::Timeout);
    assert_eq!(exec(&mut s, "mov rcx, 3"), Outcome::Done);
}

#[test]
fn asm_errors_have_cell_line_numbers() {
    let s = session();
    let errs = s.assemble("nop\nbogus rax").unwrap_err();
    assert_eq!(errs[0].line, Some(2));
}

#[test]
fn flags_are_decoded() {
    let mut s = session();
    exec(&mut s, "xor eax, eax");
    assert!(s.regs.flags.iter().any(|f| f.name == "zf" && f.set));
}

#[test]
fn disassembles_cell() {
    let s = session();
    let code = s.assemble("push rbp\nmov rbp, rsp").unwrap().code;
    let insns = s.arch().disassemble(&code, START, &Default::default());
    let text: Vec<_> = insns.iter().map(|i| i.text.as_str()).collect();
    assert_eq!(text, ["push rbp", "mov rbp, rsp"]);
}

#[test]
fn stack_is_stable_without_aslr() {
    let a = session().regs.sp;
    let b = session().regs.sp;
    assert_eq!(a, b);
}

#[test]
fn explicit_int3_is_a_stray_trap() {
    let mut s = session();
    assert_eq!(exec(&mut s, "int3\nnop"), Outcome::StrayTrap { at: START });
}

#[test]
fn pipe_mode_loads_data_section() {
    let mut s = session();
    exec(&mut s, "mov rax, [rel v]\nsection .data\nv: dq 0x1122");
    assert_eq!(reg(&s.regs, "rax"), 0x1122);
}

#[test]
fn execve_intercepted_at_session_level() {
    let mut s = session();
    let src = "mov rax, 59\nmov rbx, 0x0068732f6e69622f\npush rbx\nmov rdi, rsp\nxor rsi, rsi\nxor rdx, rdx\nsyscall";
    let o = exec(&mut s, src);
    assert_eq!(o, Outcome::Done);
    let calls = s.take_syscalls();
    assert_eq!(
        calls.len(),
        1,
        "expected 1 intercepted syscall, got {calls:?}"
    );
    assert_eq!(calls[0].name, "execve");
    assert_eq!(reg(&s.regs, "rax"), 0);
}
