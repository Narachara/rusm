//! Cross-cell calls, jumps, labels and data. Real tracee, real nasm.

use std::time::Duration;

use rusm::arch::{self, ArchKind};
use rusm::asm::{self, Backend};
use rusm::notebook::{CellState, Notebook};
use rusm::session::{Options, Outcome, Session};

fn notebook() -> Notebook {
    let kind = ArchKind::X86_64;
    let sess = Session::new(
        arch::create(kind),
        asm::create(Backend::Nasm, kind).unwrap(),
        Options {
            start: 0x400000,
            pass_signals: false,
            timeout: Duration::from_millis(300),
            aslr: false,
            save_exe: None,
        },
    )
    .unwrap();
    Notebook::new(sess).unwrap()
}

fn submit(nb: &mut Notebook, src: &str) -> usize {
    match nb.submit(src) {
        Ok(i) => i,
        Err(rusm::notebook::Error::Asm(e)) => panic!("asm error in {src:?}: {e:?}"),
        Err(rusm::notebook::Error::Other(e)) => panic!("{e:#}"),
    }
}

fn reg(nb: &Notebook, name: &str) -> u64 {
    nb.live
        .regs
        .gp
        .iter()
        .find(|r| r.name == name)
        .unwrap()
        .value
}

const STRLEN: &str = ";; def
strlen:
    xor eax, eax
.loop:
    cmp byte [rdi + rax], 0
    je .done
    inc rax
    jmp .loop
.done:
    ret";

#[test]
fn def_cells_are_placed_not_run() {
    let mut nb = notebook();
    let i = submit(&mut nb, ";; def\nf: mov rax, 99\nret");
    assert!(matches!(nb.cells[i].state, CellState::Defined(_)));
    assert_eq!(reg(&nb, "rax"), 0, "definition did not execute");
    assert_eq!(nb.symbols["f"], nb.cells[i].addr);
}

#[test]
fn calls_function_and_data_from_earlier_cells() {
    let mut nb = notebook();
    submit(&mut nb, STRLEN);
    submit(&mut nb, ";; def\nmsg: db \"hello\", 0");
    submit(&mut nb, "lea rdi, [rel msg]\ncall strlen");
    assert_eq!(nb.live.outcome, Outcome::Done);
    assert_eq!(reg(&nb, "rax"), 5);
}

#[test]
fn labels_from_run_cells_are_visible_too() {
    let mut nb = notebook();
    submit(&mut nb, "jmp over\nf: mov rbx, 7\nret\nover:");
    submit(&mut nb, "call f");
    assert_eq!(reg(&nb, "rbx"), 7);
    // jump back into an earlier cell and return via a pushed address
    submit(&mut nb, "mov rbx, 0\npush back\njmp f\nback:");
    assert_eq!(reg(&nb, "rbx"), 7);
}

#[test]
fn later_cells_can_redefine_a_label() {
    let mut nb = notebook();
    submit(&mut nb, ";; def\nf: mov rax, 1\nret");
    submit(&mut nb, ";; def\nf: mov rax, 2\nret");
    submit(&mut nb, "call f");
    assert_eq!(reg(&nb, "rax"), 2);
}

#[test]
fn data_is_writable() {
    let mut nb = notebook();
    submit(&mut nb, ";; def\ncounter: dq 0");
    submit(&mut nb, "inc qword [rel counter]");
    submit(&mut nb, "inc qword [rel counter]\nmov rax, [rel counter]");
    assert_eq!(reg(&nb, "rax"), 2);
}

#[test]
fn editing_a_definition_replays_dependents() {
    let mut nb = notebook();
    let def = submit(&mut nb, ";; def\nf: mov rax, 1\nret");
    submit(&mut nb, "call f");
    nb.edit(def, ";; def\nf: mov rax, 42\nret").unwrap();
    assert_eq!(reg(&nb, "rax"), 42);
}

#[test]
fn deleting_a_definition_breaks_dependents() {
    let mut nb = notebook();
    submit(&mut nb, ";; def\nf: ret");
    submit(&mut nb, "call f");
    nb.delete(0).unwrap();
    assert!(matches!(nb.cells[0].state, CellState::AsmError(_)));
}

#[test]
fn code_survives_process_exit() {
    let mut nb = notebook();
    submit(&mut nb, ";; def\nf: mov rbx, 5\nret");
    submit(&mut nb, "mov eax, 60\nxor edi, edi\nsyscall");
    assert!(matches!(nb.live.outcome, Outcome::Exited { .. }));
    submit(&mut nb, "call f");
    assert_eq!(nb.live.outcome, Outcome::Done);
    assert_eq!(reg(&nb, "rbx"), 5);
}

#[test]
fn cells_do_not_overlap() {
    let mut nb = notebook();
    let a = submit(&mut nb, "nop\nnop\nnop");
    let b = submit(&mut nb, "nop");
    assert!(nb.cells[b].addr >= nb.cells[a].addr + 4);
    assert_eq!(nb.cells[b].addr % 16, 0);
}

#[test]
fn symbolizes_and_disassembles_with_labels() {
    let mut nb = notebook();
    submit(&mut nb, STRLEN);
    let at = nb.symbols["strlen"];
    assert_eq!(nb.symbolize(at + 2).as_deref(), Some("strlen.loop"));
    assert_eq!(nb.symbolize(at + 3).as_deref(), Some("strlen.loop+0x1"));
    let i = submit(&mut nb, "call strlen");
    let c = &nb.cells[i];
    let insns = nb
        .sess
        .arch()
        .disassemble(&c.code, c.addr, &nb.symbols_by_addr());
    assert_eq!(insns[0].text, "call strlen");
}

#[test]
fn addresses_in_unlabeled_cells_use_cell_names() {
    let mut nb = notebook();
    submit(&mut nb, ";; def\nf: ret");
    let i = submit(&mut nb, "nop\nnop");
    let at = nb.cells[i].addr;
    assert_eq!(nb.symbolize(at + 1).as_deref(), Some("cell2+0x1"));
    let j = submit(&mut nb, "jmp .x\n.x: nop");
    let c = &nb.cells[j];
    let insns = nb
        .sess
        .arch()
        .disassemble(&c.code, c.addr, &nb.symbols_by_addr());
    assert_eq!(insns[0].text, "jmp short cell3+0x2");
}

#[test]
fn asm_error_keeps_notebook_unchanged() {
    let mut nb = notebook();
    submit(&mut nb, "mov rax, 1");
    assert!(nb.submit("call nowhere").is_err());
    assert_eq!(nb.cells.len(), 1);
    let i = 0;
    assert!(nb.edit(i, "mov rax,").is_err());
    assert_eq!(nb.cells[0].src, "mov rax, 1");
    assert_eq!(reg(&nb, "rax"), 1);
}

#[test]
fn labels_named_like_instructions() {
    let mut nb = notebook();
    // `str` and `in` are x86 instructions but valid label names.
    submit(&mut nb, "str:");
    submit(&mut nb, ";; def\nin: db 7");
    submit(&mut nb, "mov rax, str\nmovzx ebx, byte [rel in]");
    assert_eq!(reg(&nb, "rax"), nb.symbols["str"]);
    assert_eq!(reg(&nb, "rbx"), 7);
    // and a later cell can still redefine one
    submit(&mut nb, ";; def\nstr: db 0");
}

#[test]
fn data_sections_go_to_the_data_region() {
    let mut nb = notebook();
    let i = submit(
        &mut nb,
        ";; def\nsection .data\nmsg: db \"hi\", 0\nsection .bss\nbuf: resb 64\nsection .rodata\nk: dq 7",
    );
    let data = nb.sess.data_range();
    let c = &nb.cells[i];
    assert!(c.code.is_empty(), "nothing in .text");
    assert_eq!(nb.symbols["msg"], data.start);
    assert!(data.contains(&nb.symbols["buf"]) && data.contains(&nb.symbols["k"]));
    assert!(c.bss >= 64);

    // the next cell's data starts after the .bss reservation
    let j = submit(&mut nb, ";; def\nsection .data\nafter: db 1");
    assert!(
        nb.symbols["after"] >= nb.symbols["buf"] + 64,
        "no overlap with .bss"
    );
    assert!(nb.cells[j].data_addr > nb.cells[i].data_addr);

    // code uses it all; .bss is zeroed and writable
    submit(
        &mut nb,
        "mov byte [rel buf + 63], 0x55\nmovzx eax, byte [rel msg + 1]\nmov rbx, [rel k]\nmovzx ecx, byte [rel buf + 63]\nmov rdx, [rel buf]",
    );
    assert_eq!(reg(&nb, "rax"), b'i' as u64);
    assert_eq!(reg(&nb, "rbx"), 7);
    assert_eq!(reg(&nb, "rcx"), 0x55);
    assert_eq!(reg(&nb, "rdx"), 0);
}

#[test]
fn data_region_is_not_executable() {
    let mut nb = notebook();
    submit(&mut nb, ";; def\nsection .data\nf: ret");
    submit(&mut nb, "call f");
    assert!(matches!(nb.live.outcome, Outcome::Signal { .. }));
}

#[test]
fn code_and_data_in_one_cell_and_symbols() {
    let mut nb = notebook();
    let i = submit(
        &mut nb,
        "lea rsi, [rel s]\nmov al, [rsi]\nsection .data\ns: db \"A\"",
    );
    assert_eq!(reg(&nb, "rax") & 0xff, b'A' as u64);
    let c = &nb.cells[i];
    let insns = nb
        .sess
        .arch()
        .disassemble(&c.code, c.addr, &nb.symbols_by_addr());
    assert_eq!(insns[0].text, "lea rsi, [s]");
    assert_eq!(nb.symbolize(nb.symbols["s"]).as_deref(), Some("s"));
}

#[test]
fn data_survives_exit_with_initial_values() {
    let mut nb = notebook();
    submit(&mut nb, ";; def\nsection .data\nv: dq 9");
    submit(&mut nb, "inc qword [rel v]");
    submit(&mut nb, "mov eax, 60\nxor edi, edi\nsyscall");
    submit(&mut nb, "mov rax, [rel v]");
    assert_eq!(
        reg(&nb, "rax"),
        9,
        "fresh process gets the initial data again"
    );
}

// ---- stdin / stdout ----

const READ16: &str = "sub rsp, 64\nxor eax, eax\nxor edi, edi\nmov rsi, rsp\nmov edx, 16\nsyscall\nmov rbx, [rsp]\nadd rsp, 64";

#[test]
fn captures_stdout_and_stderr_per_cell() {
    let mut nb = notebook();
    let i = submit(
        &mut nb,
        "mov eax, 1\nmov edi, 1\nlea rsi, [rel m]\nmov edx, 6\nsyscall\nmov eax, 1\nmov edi, 2\nlea rsi, [rel e]\nmov edx, 4\nsyscall\nsection .data\nm: db \"hello\", 10\ne: db \"oops\"",
    );
    assert_eq!(nb.cells[i].output.stdout, b"hello\n");
    assert_eq!(nb.cells[i].output.stderr, b"oops");
    let j = submit(&mut nb, "nop");
    assert!(
        nb.cells[j].output.is_empty(),
        "output belongs to the cell that wrote it"
    );
}

#[test]
fn stdin_directive_feeds_read() {
    let mut nb = notebook();
    submit(&mut nb, &format!(";; stdin: abc\n{READ16}"));
    assert_eq!(nb.live.outcome, Outcome::Done);
    assert_eq!(reg(&nb, "rax"), 4);
    assert_eq!(
        reg(&nb, "rbx") & 0xffff_ffff,
        u32::from_le_bytes(*b"abc\n") as u64
    );
}

#[test]
fn waiting_read_is_detected_quickly_and_resumed_by_input() {
    let mut nb = notebook();
    let t = std::time::Instant::now();
    let i = submit(&mut nb, READ16);
    assert_eq!(nb.live.outcome, Outcome::WaitingForInput);
    assert!(
        t.elapsed() < std::time::Duration::from_millis(250),
        "{:?}",
        t.elapsed()
    );
    assert_eq!(nb.waiting, Some(i));

    assert_eq!(nb.input("xyz").unwrap(), Some(i));
    assert_eq!(nb.live.outcome, Outcome::Done);
    assert_eq!(reg(&nb, "rax"), 4);
    assert!(nb.cells[i].src.ends_with(";; stdin: xyz"));

    // the recorded input makes a replay reproduce it without waiting
    nb.replay().unwrap();
    assert_eq!(nb.live.outcome, Outcome::Done);
    assert_eq!(reg(&nb, "rax"), 4);
}

#[test]
fn input_without_a_waiting_cell_goes_to_the_next_cell() {
    let mut nb = notebook();
    assert_eq!(nb.input(r"q\tw").unwrap(), None);
    let i = submit(&mut nb, READ16);
    assert!(nb.cells[i].src.starts_with(";; stdin: q\\tw\n"));
    assert_eq!(reg(&nb, "rax"), 4);
    assert!(nb.pending_input.is_empty());
}

#[test]
fn eof_makes_read_return_zero() {
    let mut nb = notebook();
    submit(&mut nb, READ16);
    assert_eq!(nb.live.outcome, Outcome::WaitingForInput);
    nb.eof().unwrap();
    assert_eq!(nb.live.outcome, Outcome::Done);
    assert_eq!(reg(&nb, "rax"), 0);
}

#[test]
fn new_cell_after_waiting_does_not_restart_the_read() {
    let mut nb = notebook();
    submit(&mut nb, READ16);
    assert_eq!(nb.live.outcome, Outcome::WaitingForInput);
    submit(&mut nb, "mov rax, 7");
    assert_eq!(nb.live.outcome, Outcome::Done);
    assert_eq!(reg(&nb, "rax"), 7);
    assert_eq!(nb.waiting, None);
    assert_eq!(
        nb.input("late").unwrap(),
        None,
        "no cell is waiting any more"
    );
}

#[test]
fn large_output_does_not_block() {
    let mut nb = notebook();
    // 64 writes of 4 KiB from the stack = 256 KiB, more than a default pipe holds
    let i = submit(
        &mut nb,
        "sub rsp, 4096\nmov r12, 64\n.w:\nmov eax, 1\nmov edi, 1\nmov rsi, rsp\nmov edx, 4096\nsyscall\ndec r12\njnz .w\nadd rsp, 4096",
    );
    assert_eq!(nb.live.outcome, Outcome::Done);
    assert_eq!(nb.cells[i].output.stdout.len(), 64 * 4096);
}

#[test]
fn ignored_signals_do_not_stop_a_cell() {
    use nix::sys::signal::{Signal, kill};
    let mut nb = notebook();
    submit(&mut nb, READ16);
    assert_eq!(nb.live.outcome, Outcome::WaitingForInput);
    // e.g. the terminal was resized while the read was waiting
    kill(nb.sess.pid(), Signal::SIGWINCH).unwrap();
    nb.input("hi").unwrap();
    assert_eq!(nb.live.outcome, Outcome::Done);
    assert_eq!(reg(&nb, "rax"), 3);
}

#[test]
fn program_has_no_controlling_terminal() {
    let nb = notebook();
    let pid = nb.sess.pid();
    // its own session: terminal signals (SIGWINCH, SIGINT) never reach it
    assert_eq!(nix::unistd::getsid(Some(pid)).unwrap(), pid);
}

#[test]
fn cells_are_call_targets_by_position() {
    let mut nb = notebook();
    submit(&mut nb, ";; def\nmov rax, 7\nret");
    submit(&mut nb, "call cell1");
    assert_eq!(nb.live.outcome, Outcome::Done);
    assert_eq!(reg(&nb, "rax"), 7);
    submit(&mut nb, "lea rbx, [rel cell2]");
    assert_eq!(reg(&nb, "rbx"), nb.cells[1].addr);
    // a cell can name itself
    let i = submit(&mut nb, "lea rcx, [rel cell4]");
    assert_eq!(reg(&nb, "rcx"), nb.cells[i].addr);
}

#[test]
fn jumping_into_a_cell_stops_at_its_end() {
    let mut nb = notebook();
    submit(&mut nb, "mov rbx, 3");
    submit(&mut nb, "mov rbx, 0\njmp cell1\nmov rbx, 9");
    let Outcome::StrayTrap { at } = nb.live.outcome else {
        panic!("{:?}", nb.live.outcome);
    };
    assert_eq!(nb.cell_end(at), Some(0));
    assert_eq!(reg(&nb, "rbx"), 3);
}

#[test]
fn user_label_overrides_cell_name() {
    let mut nb = notebook();
    submit(&mut nb, ";; def\nmov rax, 1\nret");
    submit(&mut nb, ";; def\ncell1: mov rax, 2\nret");
    submit(&mut nb, "call cell1");
    assert_eq!(reg(&nb, "rax"), 2);
}

#[test]
fn cell_names_follow_position_after_delete() {
    let mut nb = notebook();
    submit(&mut nb, ";; def\nmov rax, 1\nret");
    submit(&mut nb, ";; def\nmov rax, 2\nret");
    nb.delete(0).unwrap();
    // the old cell2 is now cell1
    submit(&mut nb, "call cell1");
    assert_eq!(reg(&nb, "rax"), 2);
    assert!(nb.submit("jmp cell9").is_err());
}

// execve is intercepted: decoded and shown, not run, so the notebook survives.
const SH_SHELLCODE: &str = "\
    xor rax, rax\n\
    push rax\n\
    mov rbx, 0x68732f2f6e69622f\n\
    push rbx\n\
    mov rdi, rsp\n\
    push rax\n\
    mov rdx, rsp\n\
    push rdi\n\
    mov rsi, rsp\n\
    add rax, 59\n\
    syscall";

#[test]
fn execve_is_intercepted_and_notebook_survives() {
    let mut nb = notebook();
    let i = submit(&mut nb, SH_SHELLCODE);
    // The cell ran to its end trap rather than being replaced by a shell.
    assert_eq!(
        nb.cells[i].snapshot().map(|s| s.outcome.clone()),
        Some(Outcome::Done)
    );
    let calls = &nb.cells[i].syscalls;
    assert_eq!(calls.len(), 1, "expected one intercepted syscall");
    assert_eq!(calls[0].name, "execve");
    assert!(calls[0].call.contains("/bin//sh"), "{}", calls[0].call);
    // /bin/sh exists and is executable almost everywhere: success == 0.
    assert_eq!(calls[0].ret, 0, "note: {}", calls[0].note);
    // The real test: a following cell still runs (no EIO from a lost process).
    submit(&mut nb, "mov rax, 1234");
    assert_eq!(reg(&nb, "rax"), 1234);
}

#[test]
fn execve_of_a_missing_path_reports_enoent() {
    let mut nb = notebook();
    // Build "/no/such/path\0" on the stack, execve(rsp, NULL, NULL).
    let src = "\
        mov rax, 0x687461702f\n\
        push rax\n\
        mov rax, 0x686375732f6f6e2f\n\
        push rax\n\
        mov rdi, rsp\n\
        xor rsi, rsi\n\
        xor rdx, rdx\n\
        mov rax, 59\n\
        syscall";
    let i = submit(&mut nb, src);
    let calls = &nb.cells[i].syscalls;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].ret, -(libc::ENOENT as i64), "{}", calls[0].call);
}

#[test]
fn ordinary_syscalls_still_run() {
    // A write(1, "hi\n", 3) really reaches the program's stdout pipe.
    let mut nb = notebook();
    let src = "\
        jmp after\n\
        msg: db \"hi\", 10\n\
        after:\n\
        mov rax, 1\n\
        mov rdi, 1\n\
        lea rsi, [rel msg]\n\
        mov rdx, 3\n\
        syscall";
    let i = submit(&mut nb, src);
    assert!(
        nb.cells[i].syscalls.is_empty(),
        "write must not be intercepted"
    );
    assert_eq!(nb.cells[i].output.stdout, b"hi\n");
}
