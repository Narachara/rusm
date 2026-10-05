//! ratatui notebook interface.

mod app;
mod editor;
mod ui;

use std::io::stdout;
use std::path::PathBuf;

use anyhow::Result;
use ratatui::crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, KeyboardEnhancementFlags,
    PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::supports_keyboard_enhancement;

use crate::notebook::Notebook;
use app::App;

/// Run the notebook UI until the user quits. `path` is loaded first if given.
pub fn run(mut nb: Notebook, path: Option<PathBuf>) -> Result<()> {
    if let Some(p) = &path
        && p.exists()
    {
        nb.load(p)?;
    }
    let mut app = App::new(nb, path);

    let mut terminal = ratatui::init();
    // Lets terminals that support it report Shift+Enter distinctly.
    let enhanced = supports_keyboard_enhancement().unwrap_or(false);
    if enhanced {
        execute!(
            stdout(),
            PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
        )?;
    }
    execute!(stdout(), EnableBracketedPaste)?;

    let res = (|| -> Result<()> {
        while !app.quit {
            terminal.draw(|f| ui::draw(f, &app))?;
            app.handle(event::read()?);
        }
        Ok(())
    })();

    let _ = execute!(stdout(), DisableBracketedPaste);
    if enhanced {
        let _ = execute!(stdout(), PopKeyboardEnhancementFlags);
    }
    ratatui::restore();
    res
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

    use super::*;
    use crate::arch::{self, ArchKind};
    use crate::asm::{self, Backend};
    use crate::session::{Options, Session};

    fn app() -> App {
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
        App::new(Notebook::new(sess).unwrap(), None)
    }

    fn key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
        app.handle(Event::Key(KeyEvent::new(code, mods)));
    }

    /// Paste `src` and run it with Ctrl+R.
    fn type_cell(app: &mut App, src: &str) {
        app.handle(Event::Paste(src.into()));
        key(app, KeyCode::Char('r'), KeyModifiers::CONTROL);
    }

    /// Type `text` key by key, pressing Enter at each newline.
    fn type_keys(app: &mut App, text: &str) {
        for c in text.chars() {
            match c {
                '\n' => key(app, KeyCode::Enter, KeyModifiers::NONE),
                c => key(app, KeyCode::Char(c), KeyModifiers::NONE),
            }
        }
    }

    fn rax(app: &App) -> u64 {
        app.nb.live.regs.gp[0].value
    }

    fn render(app: &App) -> String {
        let mut t = Terminal::new(TestBackend::new(140, 40)).unwrap();
        t.draw(|f| ui::draw(f, app)).unwrap();
        let buf = t.backend().buffer();
        (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn runs_cells_and_renders_state() {
        let mut app = app();
        type_cell(&mut app, "mov rax, 0x1337\npush rax");
        type_cell(&mut app, "mov rbx, [0]");
        let screen = render(&app);
        if std::env::var("SHOW").is_ok() {
            println!("{screen}");
        }
        assert!(screen.contains("[ 1] ✓"));
        assert!(screen.contains("[ 2] !"));
        assert!(screen.contains("SIGSEGV"));
        assert!(screen.contains("rsp→"));
        assert!(screen.contains("0000000000001337"));
    }

    #[test]
    fn editing_a_cell_replays_notebook() {
        let mut app = app();
        type_cell(&mut app, "mov rax, 1");
        type_cell(&mut app, "add rax, 10");
        // Tab to cells, go to first cell, edit it.
        key(&mut app, KeyCode::Tab, KeyModifiers::NONE);
        key(&mut app, KeyCode::Up, KeyModifiers::NONE);
        key(&mut app, KeyCode::Char('e'), KeyModifiers::NONE);
        key(&mut app, KeyCode::Char('u'), KeyModifiers::CONTROL);
        type_cell(&mut app, "mov rax, 5");
        let rax = app.nb.live.regs.gp[0].value;
        assert_eq!(rax, 15);
        assert_eq!(app.nb.cells.len(), 2);
    }

    #[test]
    fn selecting_cell_shows_its_snapshot() {
        let mut app = app();
        type_cell(&mut app, "mov rax, 1");
        type_cell(&mut app, "mov rax, 2");
        key(&mut app, KeyCode::Tab, KeyModifiers::NONE);
        key(&mut app, KeyCode::Up, KeyModifiers::NONE);
        assert_eq!(app.view().0.regs.gp[0].value, 1);
        if std::env::var("SHOW").is_ok() {
            println!("{}", render(&app));
        }
    }

    #[test]
    fn commands_watch_and_write() {
        let mut app = app();
        type_cell(&mut app, ".write rsp 41424344");
        type_cell(&mut app, ".watch rsp");
        assert_eq!(&app.nb.live.mem.bytes[..4], b"ABCD");
        assert!(app.nb.cells.is_empty());
    }

    fn focus_memory(app: &mut App) {
        while app.focus != app::Focus::Memory {
            key(app, KeyCode::Tab, KeyModifiers::NONE);
        }
    }

    #[test]
    fn memory_follows_register_across_cells() {
        let mut app = app();
        type_cell(&mut app, ".watch rsp");
        type_cell(&mut app, "push 0x41424344");
        assert_eq!(app.nb.live.watch_addr, app.nb.live.regs.sp);
        assert_eq!(&app.nb.live.mem.get(app.nb.live.regs.sp), &Some(0x44));
        let before = app.nb.live.regs.sp;
        type_cell(&mut app, "push rax");
        assert_eq!(app.nb.live.watch_addr, before - 8, "view moved with rsp");
    }

    #[test]
    fn memory_pane_scrolls_and_jumps() {
        let mut app = app();
        focus_memory(&mut app);
        let _ = render(&app); // records pane geometry
        let (rows, per_row) = app.mem_layout.get();
        let start = app.nb.live.watch_addr;
        key(&mut app, KeyCode::Down, KeyModifiers::NONE);
        assert_eq!(app.nb.live.watch_addr, start + per_row as u64);
        key(&mut app, KeyCode::PageDown, KeyModifiers::NONE);
        assert_eq!(app.nb.live.watch_addr, start + (per_row * rows) as u64);

        // goto prompt with a register expression
        key(&mut app, KeyCode::Char('g'), KeyModifiers::NONE);
        app.handle(Event::Paste("ignored in prompt".into()));
        for c in "rsp+0x10".chars() {
            key(&mut app, KeyCode::Char(c), KeyModifiers::NONE);
        }
        key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(app.nb.live.watch_addr, app.nb.live.regs.sp + 0x10);
        assert_eq!(app.nb.watch.describe(), "rsp+0x10");

        // ] from the code region reaches the next mapping, [ comes back
        key(&mut app, KeyCode::Char('p'), KeyModifiers::NONE);
        key(&mut app, KeyCode::Char(']'), KeyModifiers::NONE);
        assert_ne!(app.nb.live.watch_addr & !0xfff, 0x400000);
        key(&mut app, KeyCode::Char('['), KeyModifiers::NONE);
        assert_eq!(app.nb.live.watch_addr, 0x400000);

        // scrolling above the code region shows unmapped bytes
        key(&mut app, KeyCode::Up, KeyModifiers::NONE);
        let screen = render(&app);
        if std::env::var("SHOW").is_ok() {
            println!("{screen}");
        }
        assert!(screen.contains("?? ?? ??"));
        assert!(screen.contains("unmapped"));
    }

    #[test]
    fn fault_in_called_function_shows_that_function() {
        let mut app = app();
        type_cell(
            &mut app,
            ";; def\nstrlen:\n    xor eax, eax\n.loop:\n    cmp byte [rdi + rax], 0\n    je .done\n    inc rax\n    jmp .loop\n.done:\n    ret",
        );
        type_cell(&mut app, "xor edi, edi\ncall strlen");
        let screen = render(&app);
        if std::env::var("SHOW").is_ok() {
            println!("{screen}");
        }
        assert!(screen.contains("◆"));
        assert!(screen.contains("defines strlen"));
        assert!(screen.contains("strlen:"));
        assert!(
            screen.contains("→ cell2+0x7"),
            "return address attributed to the calling cell"
        );
        assert!(
            screen.contains("→ 00400002"),
            "faulting instruction marked inside strlen"
        );
    }

    #[test]
    fn one_line_cells_run_on_enter() {
        let mut app = app();
        type_keys(&mut app, "mov rax, 3\n");
        assert_eq!(app.nb.cells.len(), 1);
        assert_eq!(rax(&app), 3);
    }

    #[test]
    fn function_typed_line_by_line_with_enter() {
        let mut app = app();
        // label opens a block; Enter adds lines; empty line runs it
        type_keys(
            &mut app,
            "string:\nmov rax, 5\n.loop:\ndec rax\njnz .loop\nmov rax, 42\nret\n",
        );
        assert!(app.nb.cells.is_empty(), "still collecting the block");
        assert_eq!(app.editor.lines().len(), 8);
        type_keys(&mut app, "\n");
        assert_eq!(app.nb.cells.len(), 1);
        assert_eq!(
            app.nb.cells[0].src.lines().count(),
            7,
            "blank terminator line dropped"
        );
        type_keys(&mut app, "mov rax, 0\ncall string\n");
        assert_eq!(app.nb.live.outcome, crate::session::Outcome::Done);
        assert_eq!(rax(&app), 42);
    }

    #[test]
    fn def_block_and_local_label_from_later_cell() {
        let mut app = app();
        type_keys(
            &mut app,
            ";; def\nf:\nmov rax, 1\n.inner:\nmov rbx, 2\nret\n\n",
        );
        assert_eq!(app.nb.cells.len(), 1);
        assert_eq!(rax(&app), 0, "def cell not run");
        type_keys(&mut app, "call f.inner\n");
        assert_eq!(app.nb.live.regs.gp[1].value, 2);
        assert_eq!(rax(&app), 0, "entered after mov rax, 1");
    }

    #[test]
    fn ctrl_j_newline_and_ctrl_r_run() {
        let mut app = app();
        type_keys(&mut app, "mov rax, 1");
        key(&mut app, KeyCode::Char('j'), KeyModifiers::CONTROL);
        type_keys(&mut app, "add rax, 1");
        assert!(app.nb.cells.is_empty());
        key(&mut app, KeyCode::Char('r'), KeyModifiers::CONTROL);
        assert_eq!(rax(&app), 2);
    }

    #[test]
    fn dot_label_is_assembly_not_a_command() {
        let mut app = app();
        type_cell(&mut app, ".loop:");
        assert_eq!(app.nb.cells.len(), 1);
        assert!(app.status.is_none(), "{:?}", app.status);
    }

    #[test]
    fn calling_an_empty_label_explains_itself() {
        let mut app = app();
        type_cell(&mut app, "string:");
        type_cell(&mut app, "call string");
        let screen = render(&app);
        assert!(matches!(
            app.nb.live.outcome,
            crate::session::Outcome::StrayTrap { .. }
        ));
        assert!(
            screen.contains("stopped at `string`: there is no code after this"),
            "{screen}"
        );
    }

    #[test]
    fn execve_is_decoded_under_the_cell() {
        let mut app = app();
        type_cell(
            &mut app,
            "mov rax, 59\nmov rbx, 0x0068732f6e69622f\npush rbx\nmov rdi, rsp\nxor rsi, rsi\nxor rdx, rdx\nsyscall",
        );
        let screen = render(&app);
        assert!(screen.contains("execve(\"/bin/sh\""), "{screen}");
        // Process not replaced: a later cell still runs.
        type_cell(&mut app, "mov rax, 0x4242");
        assert_eq!(rax(&app), 0x4242);
    }

    #[test]
    fn jumping_into_a_cell_names_where_it_stopped() {
        let mut app = app();
        type_cell(&mut app, "mov rbx, 3");
        type_cell(&mut app, "jmp cell1");
        let screen = render(&app);
        assert!(screen.contains("reached the end of cell1"), "{screen}");
    }

    #[test]
    fn stdin_and_stdout_in_the_notebook() {
        let mut app = app();
        // echo: read a line, write it back
        type_cell(&mut app, ";; def\nsection .bss\nbuf: resb 64");
        type_cell(
            &mut app,
            "xor eax, eax\nxor edi, edi\nlea rsi, [rel buf]\nmov edx, 64\nsyscall\nmov edx, eax\nmov eax, 1\nmov edi, 1\nsyscall",
        );
        let screen = render(&app);
        assert!(screen.contains("[ 2] ?"), "{screen}");
        assert!(screen.contains("a cell waits for stdin"));

        type_keys(&mut app, ".input hello world\n");
        let screen = render(&app);
        if std::env::var("SHOW").is_ok() {
            println!("{screen}");
        }
        assert!(screen.contains("[ 2] ✓"), "{screen}");
        assert!(screen.contains(";; stdin: hello world"));
        assert!(screen.contains("│ hello world"));
        assert_eq!(app.nb.live.regs.gp[0].value, 12);
    }
}
