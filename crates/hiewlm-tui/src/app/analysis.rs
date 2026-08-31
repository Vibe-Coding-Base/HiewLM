//! Code understanding: strings a function builds on its stack, and what an
//! instruction is really touching (an imported API, or the string it points at).

use super::*;

impl super::App {
    // -- Stack strings ---------------------------------------------------

    /// Rebuild the strings a function assembles on its stack.
    ///
    /// `mov byte ptr [rbp-0x20], 'h'` repeated forty times leaves nothing for
    /// `strings` to find — which is exactly why obfuscated code does it. Here the
    /// stores are replayed into a model of the stack frame and the readable runs
    /// are recovered.
    pub(super) fn open_stack_strings(&mut self) {
        if !matches!(self.disasm_arch, Arch::X86 | Arch::X86_64) {
            self.set_status("Stack strings need x86/x86-64.");
            return;
        }
        let start = self.function_start_at_cursor();
        let found = self.stack_strings(start, 4000);
        if found.is_empty() {
            self.set_status(format!(
                "No stack-built strings in the function at {}.",
                self.display_addr(start)
            ));
            return;
        }
        let items: Vec<(String, u64)> = found
            .iter()
            .map(|(off, slot, text)| {
                (
                    format!("!{}  [{slot:+#x}]  \"{text}\"", self.display_addr(*off)),
                    *off,
                )
            })
            .collect();
        self.dialog = Some(Dialog::JumpList {
            title: format!(
                "Stack strings in the function at {} ({})",
                self.display_addr(start),
                items.len()
            ),
            items,
            sel: 0,
            filter: String::new(),
        });
        self.set_status("Enter jumps to the instruction that starts the string.");
    }

    /// The recovered function start at or before the cursor, else the cursor.
    pub(super) fn function_start_at_cursor(&self) -> u64 {
        let cur = self.cursor_insn_start();
        self.analyze()
            .functions
            .range(..=cur)
            .next_back()
            .copied()
            .unwrap_or(cur)
    }

    /// Replay a function's stack stores and return `(instruction offset, stack
    /// slot, text)` for every readable run. ASCII and UTF-16LE both fall out of
    /// the same byte model.
    pub(super) fn stack_strings(&self, start: u64, budget: usize) -> Vec<(u64, i64, String)> {
        const MIN: usize = 4;
        // slot -> (byte, offset of the instruction that wrote it)
        let mut frame: BTreeMap<i64, (u8, u64)> = BTreeMap::new();
        let mut off = start;
        let mut left = budget;

        while left > 0 && off < self.buffer.len() {
            let Some(ins) = self.disasm_from(off, 1).into_iter().next() else {
                break;
            };
            left -= 1;
            if let Some((disp, value, size)) = ins.stack_store {
                for i in 0..size as i64 {
                    let byte = (value >> (8 * i as u32)) as u8;
                    frame.insert(disp + i, (byte, ins.offset));
                }
            }
            if ins.flow == Flow::Ret {
                break;
            }
            off = ins.offset + ins.len as u64;
        }

        // Contiguous slots form a run; a gap ends it.
        let mut out = Vec::new();
        let mut run: Vec<(i64, u8, u64)> = Vec::new();
        let flush = |run: &mut Vec<(i64, u8, u64)>, out: &mut Vec<(u64, i64, String)>| {
            if let Some(text) = decode_run(&run.iter().map(|r| r.1).collect::<Vec<_>>(), MIN) {
                let first_insn = run.iter().map(|r| r.2).min().unwrap_or(0);
                out.push((first_insn, run[0].0, text));
            }
            run.clear();
        };
        for (slot, (byte, insn)) in frame {
            match run.last() {
                Some(&(prev, _, _)) if slot == prev + 1 => run.push((slot, byte, insn)),
                Some(_) => {
                    flush(&mut run, &mut out);
                    run.push((slot, byte, insn));
                }
                None => run.push((slot, byte, insn)),
            }
        }
        flush(&mut run, &mut out);
        out.sort_by_key(|(insn, _, _)| *insn);
        out
    }

    // -- Disassembly annotation -----------------------------------------

    /// What an instruction is really touching: the API it calls through the
    /// import table, or the string it points at.
    ///
    /// Reading `call [rip+0x2f10]` tells you nothing; reading
    /// `call [rip+0x2f10]  ; kernel32.dll!VirtualAlloc` tells you what the
    /// function does. Same for `lea rcx, [rip+0x1c4]  ; "http://..."`.
    pub fn annotate(&self, ins: &Insn) -> Option<String> {
        for va in [ins.target, ins.mem_target, ins.imm_target]
            .into_iter()
            .flatten()
        {
            if let Some(name) = self.sym_by_va.get(&va) {
                return Some(name.clone());
            }
            let Some(off) = self.va_to_off(va) else {
                continue;
            };
            if off >= self.buffer.len() {
                continue;
            }
            // An indirect call usually lands on an IAT slot: follow the pointer
            // once and see whether *that* is a known import.
            if matches!(ins.flow, Flow::Call | Flow::Jump) {
                let mut ptr = [0u8; 8];
                let n = 8.min((self.buffer.len() - off) as usize);
                self.view_bytes(off, &mut ptr[..n]);
                let indirect = u64::from_le_bytes(ptr);
                if let Some(name) = self.sym_by_va.get(&indirect) {
                    return Some(format!("{name} (via IAT)"));
                }
            }
            if let Some(text) = self.string_at(off) {
                return Some(format!("\"{text}\""));
            }
        }
        None
    }

    /// A printable string starting exactly at `off` (ASCII or UTF-16LE), read
    /// through the lens so an encoded string still shows up decoded.
    pub(super) fn string_at(&self, off: u64) -> Option<String> {
        const MIN: usize = 4;
        const MAX: usize = 48;
        let n = MAX.min((self.buffer.len() - off) as usize);
        if n < MIN {
            return None;
        }
        let mut buf = vec![0u8; n];
        self.view_bytes(off, &mut buf);

        let printable = |b: u8| (0x20..0x7f).contains(&b);
        let ascii: String = buf
            .iter()
            .copied()
            .take_while(|&b| printable(b))
            .map(|b| b as char)
            .collect();
        if ascii.chars().count() >= MIN {
            return Some(ascii);
        }
        // UTF-16LE: printable byte followed by a zero.
        let wide: String = buf
            .chunks_exact(2)
            .take_while(|c| c[1] == 0 && printable(c[0]))
            .map(|c| c[0] as char)
            .collect();
        (wide.chars().count() >= MIN).then_some(wide)
    }
}
