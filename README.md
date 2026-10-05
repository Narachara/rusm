# rusm

An assembly REPL. Type x86-64 instructions and watch the registers, flags and
memory change after every line. `rusm` works by building a tiny ELF, running it
under `ptrace`, and rewriting and re-running its `.text` section as you go.

It is a Rust port of [yrp604's rappel](https://github.com/yrp604/rappel). The
original C sources are kept under [`legacy/`](legacy/) for reference.

Currently supports **Linux x86-64**. The architecture backend is pluggable
(see [`src/arch/`](src/arch/)), so other targets can be added later.

## Install

You need a Rust toolchain and `nasm` (the only assembler backend so far). On
Debian/Kali/Ubuntu:

```
$ sudo apt install nasm
$ cargo build --release
```

The binary lands at `target/release/rusm`.

Because `rusm` writes to executable memory via `ptrace`, it will not work under
hardened kernels that forbid this (e.g. `PAX_MPROTECT` on grsec).

## Usage

`rusm` has three modes.

**Notebook UI** (the default when run in a terminal). Each cell is a snippet;
the machine state after it runs is shown beside it, and you can edit, delete or
replay cells. Press `F1` for the full key reference.

```
$ rusm                 # fresh session
$ rusm session.asm     # open/save a notebook (cells split by ";; %%")
```

Selected keys: `Enter` run a cell · `Ctrl+J` new line · `Ctrl+R` run block ·
`Tab` move focus between editor / memory / cells · `F2` all registers ·
`F3` memory maps · `F5` replay all · `Ctrl+Q` quit.

**Plain REPL** (`--plain`), a line-based interface with `.`-commands
(`.help`, `.regs`, `.read`, `.write`, `.maps`, `.begin`/`.end`, …):

```
$ rusm --plain
> inc rax
rax=0000000000000001 rbx=0000000000000000 ...
```

**Pipe mode** (when stdin is not a terminal), for one-off snippets:

```
$ echo "inc eax" | rusm
rax=0000000000000001 rbx=0000000000000000 rcx=0000000000000000
rdx=0000000000000000 rsi=0000000000000000 rdi=0000000000000000
rip=0000000000400004 rsp=00007ffc73019c20 rbp=0000000000000000
...
```

## Features

- **Persistent state** — registers and memory carry over between cells.
- **Data and bss** — switch to `section .data`, `.rodata` or `.bss` in a cell
  to declare memory; labels stay visible to later cells. Address it
  RIP-relative, e.g. `lea rsi, [rel msg]`.
- **Labels across cells** — `call strlen`, `jmp cell2`; definition-only cells
  start with `;; def`.
- **Real syscalls** — `write`, `openat`, etc. run for real and `rax` holds the
  result. `execve` is decoded and shown but not run (there is no shell to host).
- **stdin to the program** — `.input TEXT` in the REPL, or `;; stdin: TEXT` /
  `;; eof` directives in a notebook; reads that block are detected and resumed.
- **Disassembly** (`-d`), **all registers** (`-x`), adjustable **timeout** for
  runaway loops, optional **ASLR** (`--aslr`), and saving the generated
  executable (`--save FILE`).

Run `rusm --help` for every flag.

## Development

```
$ cargo test       # unit + integration tests (requires nasm)
$ cargo clippy --all-targets
$ cargo fmt
```

## License

Same terms as the original rappel; see [LICENSE](LICENSE). Original C
implementation © 2016 yrp; Rust port © 2026 Narachara.
