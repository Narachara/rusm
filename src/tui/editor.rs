//! Minimal multi-line text editor state. Columns are in chars.

pub struct Editor {
    lines: Vec<String>,
    row: usize,
    col: usize,
}

impl Default for Editor {
    fn default() -> Self {
        Self {
            lines: vec![String::new()],
            row: 0,
            col: 0,
        }
    }
}

fn byte_idx(s: &str, col: usize) -> usize {
    s.char_indices().nth(col).map_or(s.len(), |(i, _)| i)
}

impl Editor {
    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    pub fn cursor(&self) -> (usize, usize) {
        (self.row, self.col)
    }

    pub fn text(&self) -> String {
        self.lines.join("\n")
    }

    /// Replace the contents; cursor goes to the end.
    pub fn set_text(&mut self, text: &str) {
        self.lines = text.split('\n').map(str::to_string).collect();
        self.row = self.lines.len() - 1;
        self.col = self.line_len();
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }

    pub fn on_first_line(&self) -> bool {
        self.row == 0
    }

    pub fn on_last_line(&self) -> bool {
        self.row + 1 == self.lines.len()
    }

    fn line_len(&self) -> usize {
        self.lines[self.row].chars().count()
    }

    pub fn insert_char(&mut self, c: char) {
        let line = &mut self.lines[self.row];
        line.insert(byte_idx(line, self.col), c);
        self.col += 1;
    }

    /// Insert text that may contain newlines (e.g. a paste).
    pub fn insert_str(&mut self, s: &str) {
        for c in s.replace("\r\n", "\n").replace('\r', "\n").chars() {
            match c {
                '\n' => self.newline(),
                '\t' => self.insert_char(' '),
                c if !c.is_control() => self.insert_char(c),
                _ => {}
            }
        }
    }

    pub fn newline(&mut self) {
        let line = &mut self.lines[self.row];
        let rest = line.split_off(byte_idx(line, self.col));
        self.row += 1;
        self.col = 0;
        self.lines.insert(self.row, rest);
    }

    pub fn backspace(&mut self) {
        if self.col > 0 {
            self.col -= 1;
            let line = &mut self.lines[self.row];
            line.remove(byte_idx(line, self.col));
        } else if self.row > 0 {
            let line = self.lines.remove(self.row);
            self.row -= 1;
            self.col = self.line_len();
            self.lines[self.row].push_str(&line);
        }
    }

    pub fn delete(&mut self) {
        if self.col < self.line_len() {
            let line = &mut self.lines[self.row];
            line.remove(byte_idx(line, self.col));
        } else if !self.on_last_line() {
            let next = self.lines.remove(self.row + 1);
            self.lines[self.row].push_str(&next);
        }
    }

    pub fn left(&mut self) {
        if self.col > 0 {
            self.col -= 1;
        } else if self.row > 0 {
            self.row -= 1;
            self.col = self.line_len();
        }
    }

    pub fn right(&mut self) {
        if self.col < self.line_len() {
            self.col += 1;
        } else if !self.on_last_line() {
            self.row += 1;
            self.col = 0;
        }
    }

    pub fn up(&mut self) {
        if self.row > 0 {
            self.row -= 1;
            self.col = self.col.min(self.line_len());
        }
    }

    pub fn down(&mut self) {
        if !self.on_last_line() {
            self.row += 1;
            self.col = self.col.min(self.line_len());
        }
    }

    pub fn home(&mut self) {
        self.col = 0;
    }

    pub fn end(&mut self) {
        self.col = self.line_len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edits_across_lines() {
        let mut e = Editor::default();
        e.insert_str("mov rax, 1\npush rax");
        assert_eq!(e.cursor(), (1, 8));
        e.home();
        e.backspace();
        assert_eq!(e.text(), "mov rax, 1push rax");
        e.newline();
        e.insert_str("äb");
        e.left();
        e.delete();
        assert_eq!(e.text(), "mov rax, 1\näpush rax");
    }
}
