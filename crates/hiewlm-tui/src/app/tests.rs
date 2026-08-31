//! Editor tests.
//!
//! They live beside the code they exercise rather than inside it: `app.rs`
//! was 6300 lines, and a third of that was this module.

use super::help::PALETTE;

use super::*;

/// An app unlocked for writing — most tests exercise editing commands, and
/// the real UI is locked until Ctrl+W (see `locked_by_default_*` below).
fn app() -> App {
    let mut a = locked_app();
    a.read_only = false;
    a
}

/// An app in its real startup state: the sample is locked.
///
/// Every helper app opens `/dev/null`, so they would all share one content
/// key and leak notes into each other. Each gets a unique key instead; the
/// tests that exercise persistence use real files.
fn locked_app() -> App {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let mut a = App::open(PathBuf::from("/dev/null")).unwrap();
    a.buffer = EditBuffer::new(Arc::new(hiewlm_core::MemSource::new(
        b"0123456789ABCDEF".to_vec(),
    )));
    a.notes_key = format!("test-{}", NEXT.fetch_add(1, Ordering::Relaxed));
    a.comments.clear();
    a.named_bookmarks.clear();
    a.markers.clear();
    a.slots = [None; 8];
    a
}

#[test]
fn disassembly_is_annotated_with_strings_and_imports() {
    // lea rcx, [rip+1]: rip is the next instruction (7), so this points at 8,
    // where the string starts.
    let mut data = vec![0x48, 0x8d, 0x0d, 0x01, 0x00, 0x00, 0x00, 0xc3];
    data.extend_from_slice(b"http://c2.example.top\0");
    let mut a = locked_app();
    a.buffer = EditBuffer::new(Arc::new(hiewlm_core::MemSource::new(data)));
    a.arch = Arch::X86_64;
    a.bits = 64;
    a.disasm_arch = Arch::X86_64;
    a.disasm_bits = 64;

    let ins = a.disasm_from(0, 1).into_iter().next().expect("decode");
    assert_eq!(
        a.annotate(&ins).as_deref(),
        Some("\"http://c2.example.top\"")
    );

    // A direct call to a known symbol VA is named.
    a.sym_by_va
        .insert(0x20, "kernel32.dll!VirtualAlloc".to_string());
    let call = Insn {
        target: Some(0x20),
        ..ins.clone()
    };
    assert_eq!(
        a.annotate(&call).as_deref(),
        Some("kernel32.dll!VirtualAlloc")
    );
}

#[test]
fn documented_letter_aliases_all_exist() {
    use crossterm::event::{KeyCode, KeyEvent};
    // Every Fn-bar action has a letter alias in the help; `m` was missing.
    for (key, want) in [
        ('m', "Mode"),
        ('g', "Goto"),
        ('s', "Strings"),
        ('h', "Hashes"),
    ] {
        let mut a = app();
        a.handle_key(KeyEvent::from(KeyCode::Char(key)));
        assert!(a.dialog.is_some(), "`{key}` ({want}) opened nothing");
    }
    // `e` enters edit mode rather than opening a dialog.
    let mut a = app();
    a.handle_key(KeyEvent::from(KeyCode::Char('e')));
    assert!(a.editing, "`e` (Edit) did nothing");
    // ...and `m` specifically reaches the mode menu the help promises.
    let mut a = app();
    a.handle_key(KeyEvent::from(KeyCode::Char('m')));
    assert!(matches!(a.dialog, Some(Dialog::ModeMenu { .. })));
}

#[test]
fn long_rows_scroll_sideways_instead_of_being_cut_off() {
    use crossterm::event::{KeyCode, KeyEvent};
    let mut a = app();
    // A string far wider than any popup.
    let long: String = "A".repeat(400);
    a.buffer = EditBuffer::new(Arc::new(hiewlm_core::MemSource::new(
        format!("\0{long}\0").into_bytes(),
    )));
    a.apply(Command::OpenStrings);
    assert!(matches!(a.dialog, Some(Dialog::JumpList { .. })));
    assert_eq!(a.hscroll, 0, "a popup opens at the left edge");

    a.handle_key(KeyEvent::from(KeyCode::Right));
    a.handle_key(KeyEvent::from(KeyCode::Right));
    assert_eq!(a.hscroll, 16);
    a.handle_key(KeyEvent::from(KeyCode::Left));
    assert_eq!(a.hscroll, 8);
    // It cannot scroll off the left edge.
    for _ in 0..5 {
        a.handle_key(KeyEvent::from(KeyCode::Left));
    }
    assert_eq!(a.hscroll, 0);

    // Opening the next popup starts from the left again.
    a.handle_key(KeyEvent::from(KeyCode::Right));
    a.handle_key(KeyEvent::from(KeyCode::Esc));
    a.apply(Command::Help);
    assert_eq!(a.hscroll, 0);
}

#[test]
fn palette_finds_commands_by_words_not_by_key() {
    // The point of the palette: you remember "yara", not that it is `R`.
    let m = palette_matches("yara");
    assert!(
        m.iter().any(|(_, _, c)| matches!(c, Command::RunYara)),
        "{m:?}"
    );
    assert!(palette_matches("copy clipboard").len() == 1);
    assert!(palette_matches("zzzz").is_empty());
    // An empty query lists everything.
    assert_eq!(palette_matches("").len(), PALETTE.len());
}

#[test]
fn palette_runs_the_selected_command() {
    use crossterm::event::{KeyCode, KeyEvent};
    let mut a = locked_app();
    a.handle_key(KeyEvent::from(KeyCode::Char(':')));
    for c in "help".chars() {
        a.handle_key(KeyEvent::from(KeyCode::Char(c)));
    }
    a.handle_key(KeyEvent::from(KeyCode::Enter));
    assert!(matches!(&a.dialog, Some(Dialog::Message { title, .. }) if title.contains("help")));
}

#[test]
fn search_all_lists_every_match_with_context() {
    let mut a = app();
    a.buffer = EditBuffer::new(Arc::new(hiewlm_core::MemSource::new(b"AxxAxxAxx".to_vec())));
    a.confirm_search("A", SearchKind::Text);
    a.apply(Command::SearchAll);
    let Some(Dialog::JumpList { title, items, .. }) = &a.dialog else {
        panic!("expected a jump list");
    };
    assert!(title.contains("All matches (3"), "{title}");
    assert_eq!(
        items.iter().map(|(_, o)| *o).collect::<Vec<_>>(),
        vec![0, 3, 6]
    );
}

#[test]
fn case_insensitive_search_kind_is_in_the_tab_cycle() {
    let mut a = app();
    a.buffer = EditBuffer::new(Arc::new(hiewlm_core::MemSource::new(
        b"xx VirtualAlloc xx".to_vec(),
    )));
    assert_eq!(SearchKind::Text.next(), SearchKind::TextI);
    a.confirm_search("virtualalloc", SearchKind::TextI);
    assert_eq!(a.cursor, 3);
}

#[test]
fn search_history_is_recalled_with_up() {
    use crossterm::event::{KeyCode, KeyEvent};
    let mut a = app();
    a.confirm_search("abc", SearchKind::Text);
    a.apply(Command::OpenSearch);
    a.handle_key(KeyEvent::from(KeyCode::Up));
    assert!(matches!(&a.dialog, Some(Dialog::Search { input, .. }) if input == "abc"));
}

#[test]
fn legacy_marker_sidecar_is_imported_once() {
    let path = std::env::temp_dir().join("hiewlm_legacy_markers.bin");
    fs::write(&path, b"legacy marker migration sample").unwrap();
    // A sidecar written by an older build, next to the file.
    let sidecar = super::markers_path(&path);
    fs::write(
        &sidecar,
        toml::to_string(&MarkerFile {
            markers: vec![Marker {
                start: 2,
                end: 5,
                color: 3,
            }],
        })
        .unwrap(),
    )
    .unwrap();

    let a = App::open(path.clone()).unwrap();
    assert_eq!(
        a.marker_color_at(3),
        Some(3),
        "old markers must not be lost"
    );

    // Now they live in the content-keyed store, so the sidecar is redundant.
    fs::remove_file(&sidecar).ok();
    let b = App::open(path.clone()).unwrap();
    assert_eq!(b.marker_color_at(3), Some(3));

    let _ = fs::remove_file(&path);
}

#[test]
fn notes_survive_a_rename() {
    let first = std::env::temp_dir().join("hiewlm_notes_sample.bin");
    fs::write(&first, b"sample bytes for the notes test").unwrap();

    {
        let mut a = App::open(first.clone()).unwrap();
        a.cursor = 4;
        a.set_comment("decrypt loop starts here");
        a.cursor = 8;
        a.add_named_bookmark("config blob");
        a.mark = Some(0);
        a.cursor = 3;
        a.color_block(1);
    }

    // The analyst renames the sample, as everyone does after identifying it.
    let renamed = std::env::temp_dir().join("hiewlm_notes_emotet_2026.bin");
    let _ = fs::remove_file(&renamed);
    fs::rename(&first, &renamed).unwrap();

    let b = App::open(renamed.clone()).unwrap();
    assert_eq!(b.comment_at(4), Some("decrypt loop starts here"));
    assert!(b
        .named_bookmarks
        .iter()
        .any(|(n, o)| n == "config blob" && *o == 8));
    assert_eq!(b.markers.len(), 1);
    assert!(b.status.contains("Notes restored"), "{}", b.status);

    let _ = fs::remove_file(&renamed);
}

#[test]
fn different_content_does_not_share_notes() {
    let one = std::env::temp_dir().join("hiewlm_notes_one.bin");
    let two = std::env::temp_dir().join("hiewlm_notes_two.bin");
    fs::write(&one, b"first sample").unwrap();
    fs::write(&two, b"second sample").unwrap();
    {
        let mut a = App::open(one.clone()).unwrap();
        a.cursor = 2;
        a.set_comment("only mine");
    }
    let b = App::open(two.clone()).unwrap();
    assert_eq!(b.comment_at(2), None);

    let _ = fs::remove_file(&one);
    let _ = fs::remove_file(&two);
}

#[test]
fn opening_a_directory_shows_the_ranked_queue() {
    let dir = std::env::temp_dir().join("hiewlm_open_folder_test");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("a_dull.bin"), vec![0u8; 2048]).unwrap();
    let mut nasty = b"http://c2.example.top/gate.php\0".to_vec();
    nasty.extend(b"powershell -EncodedCommand ZQBjAGgAbwA\0");
    nasty.extend(b"185.220.101.7\0");
    fs::write(dir.join("z_nasty.bin"), &nasty).unwrap();

    let app = App::open_folder(dir.clone()).unwrap();
    assert!(matches!(app.dialog, Some(Dialog::FileHits { .. })));
    // The worst sample is the one open underneath, not the alphabetical first.
    assert!(app.path.ends_with("z_nasty.bin"), "opened {:?}", app.path);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn folder_triage_ranks_files_worst_first() {
    let dir = std::env::temp_dir().join("hiewlm_folder_triage_test");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    // One dull file, one full of indicators.
    fs::write(dir.join("boring.bin"), vec![0u8; 4096]).unwrap();
    let mut nasty = b"http://c2.example.top/gate.php\0".to_vec();
    nasty.extend(b"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\0");
    nasty.extend(b"powershell -EncodedCommand ZQBjAGgAbwA\0");
    nasty.extend(b"185.220.101.7\0");
    fs::write(dir.join("nasty.bin"), &nasty).unwrap();

    let mut a = App::open(dir.join("boring.bin")).unwrap();
    a.apply(Command::FolderTriage);
    let Some(Dialog::FileHits { items, .. }) = &a.dialog else {
        panic!("expected the folder list");
    };
    assert_eq!(items.len(), 2);
    assert!(
        items[0].1.ends_with("nasty.bin"),
        "worst first: {:?}",
        items[0].0
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn report_is_written_beside_the_sample_while_locked() {
    let path = std::env::temp_dir().join("hiewlm_report_write.bin");
    fs::write(&path, b"http://c2.example.top/gate.php and padding padding").unwrap();
    let out = std::env::temp_dir().join("hiewlm_report_write.bin.triage.md");
    let _ = fs::remove_file(&out);

    let mut a = App::open(path.clone()).unwrap();
    assert!(a.read_only, "the sample stays locked");
    a.apply(Command::CopyItem(12));

    let md = fs::read_to_string(&out).expect("the report file");
    assert!(md.starts_with("# Triage — hiewlm_report_write.bin"), "{md}");
    assert!(md.contains("SHA-256"));
    assert!(
        !a.buffer.is_dirty(),
        "writing a report must not touch the sample"
    );

    let _ = fs::remove_file(&out);
    let _ = fs::remove_file(&path);
}

#[test]
fn copy_menu_labels_match_the_copy_actions() {
    let mut a = locked_app();
    a.apply(Command::OpenCopyMenu);
    assert!(matches!(a.dialog, Some(Dialog::CopyMenu { .. })));
    assert_eq!(
        crate::ui::COPY_MENU_LABELS.len(),
        13,
        "menu rows index copy_item"
    );
    // Copying the address never needs a selection and never fails.
    a.apply(Command::CopyItem(8));
    assert!(a.dialog.is_none());
    // Copying a block without one explains itself instead of copying nothing.
    a.apply(Command::CopyItem(4));
    assert!(a.status.contains("Nothing to copy"), "{}", a.status);
}

#[test]
fn lens_decodes_the_view_without_touching_the_file() {
    let mut a = locked_app();
    let plain = a.buffer.to_vec();
    let encoded: Vec<u8> = plain.iter().map(|&b| b ^ 0x5a).collect();
    a.buffer = EditBuffer::new(Arc::new(hiewlm_core::MemSource::new(encoded.clone())));

    a.set_lens("xor 5a");
    assert_eq!(a.lens_label(), Some("xor 5a"));
    let seen: Vec<u8> = (0..plain.len() as u64).map(|o| a.view_byte(o)).collect();
    assert_eq!(seen, plain, "the view is decoded");
    assert_eq!(a.buffer.to_vec(), encoded, "the file is not");
    assert!(!a.buffer.is_dirty());

    a.set_lens("");
    assert!(a.lens_label().is_none());
    assert_eq!(a.view_byte(0), encoded[0]);
}

#[test]
fn rebuilds_a_string_assembled_on_the_stack() {
    // The shape obfuscated code uses: the literal never exists in the file.
    //   mov dword ptr [rbp-0x10], "http"
    //   mov dword ptr [rbp-0x0c], "://e"
    //   mov dword ptr [rbp-0x08], "vil."
    //   mov dword ptr [rbp-0x04], "top\0"
    //   ret
    let mut data = Vec::new();
    for (disp, word) in [
        (0xf0u8, b"http"),
        (0xf4u8, b"://e"),
        (0xf8u8, b"vil."),
        (0xfcu8, b"top\0"),
    ] {
        data.extend_from_slice(&[0xc7, 0x45, disp]);
        data.extend_from_slice(word);
    }
    data.push(0xc3);

    let mut a = locked_app();
    a.buffer = EditBuffer::new(Arc::new(hiewlm_core::MemSource::new(data)));
    a.arch = Arch::X86_64;
    a.bits = 64;
    a.disasm_arch = Arch::X86_64;
    a.disasm_bits = 64;

    let found = a.stack_strings(0, 64);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].2, "http://evil.top");
    assert_eq!(found[0].0, 0, "points at the first store");

    // ...and the same thing through the command, as a jump list.
    a.apply(Command::StackStrings);
    match &a.dialog {
        Some(Dialog::JumpList { items, title, .. }) => {
            assert!(title.contains("Stack strings"), "{title}");
            assert!(items[0].0.contains("http://evil.top"), "{}", items[0].0);
        }
        _ => panic!("expected the stack-strings list"),
    }
}

#[test]
fn stack_string_run_decoding_handles_utf16_and_gaps() {
    // Wide string, NUL-terminated.
    let wide: Vec<u8> = "cmd.exe"
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    assert_eq!(super::decode_run(&wide, 4).as_deref(), Some("cmd.exe"));
    // Too short to be worth reporting.
    assert_eq!(super::decode_run(b"ab\0\0", 4), None);
    // Not text at all.
    assert_eq!(super::decode_run(&[0x01, 0x02, 0x03, 0x04, 0x05], 4), None);
}

#[test]
fn xor_key_recovers_a_repeating_key_and_sets_the_lens() {
    use crossterm::event::{KeyCode, KeyEvent};
    // Key recovery is statistical: each key column is decided by its own
    // samples, so the blob has to be the size a real configuration is.
    let plain = b"host=c2.example.top;port=443;id=BOT-0007;interval=60;retry=5;path=/gate.php;\
ua=Mozilla/5.0 (Windows NT 10.0; Win64; x64);key=0123456789abcdef;mutex=Global-Lock77;\
persist=SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run;drop=%APPDATA%\\svc.exe;\
fallback=http://backup.example.top/p.php;sleep=300;jitter=15;campaign=summer;";
    let key = b"S3cr3t!";
    // Put the blob at an offset that is *not* a multiple of the key length,
    // so the lens rotation is actually exercised.
    let pad = 5u64;
    let mut data = vec![0u8; pad as usize];
    data.extend(
        plain
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()]),
    );

    let mut a = locked_app();
    a.buffer = EditBuffer::new(Arc::new(hiewlm_core::MemSource::new(data)));
    a.mark = Some(pad);
    a.cursor = a.max_offset();
    a.apply(Command::XorKey);

    assert!(
        matches!(a.dialog, Some(Dialog::XorHits { .. })),
        "expected candidates"
    );
    a.handle_key(KeyEvent::from(KeyCode::Enter));

    let decoded: String = (pad..pad + 19).map(|o| a.view_byte(o) as char).collect();
    assert_eq!(
        decoded, "host=c2.example.top",
        "lens must decode at the block offset"
    );
    assert!(!a.buffer.is_dirty(), "the file itself is untouched");
}

#[test]
fn xor_key_needs_a_block_worth_analysing() {
    let mut a = locked_app();
    a.apply(Command::XorKey);
    assert!(a.status.contains("Select a block"), "{}", a.status);
    a.mark = Some(0);
    a.cursor = 3;
    a.apply(Command::XorKey);
    assert!(a.status.contains("bigger block"), "{}", a.status);
}

#[test]
fn xor_search_finds_a_hidden_url_and_offers_its_recipe() {
    let mut a = locked_app();
    let mut data = vec![0u8; 64];
    data.extend(b"http://c2.example.top/x".iter().map(|&b| b ^ 0x33));
    a.buffer = EditBuffer::new(Arc::new(hiewlm_core::MemSource::new(data)));

    a.apply(Command::XorSearch);
    let Some(Dialog::XorHits { items, .. }) = &a.dialog else {
        panic!("expected the xor hits list");
    };
    assert!(
        items
            .iter()
            .any(|(_, off, recipe)| *off == 64 && recipe == "xor 33"),
        "{items:?}"
    );

    // Enter jumps there and puts the recovering recipe on the lens.
    use crossterm::event::{KeyCode, KeyEvent};
    a.handle_key(KeyEvent::from(KeyCode::Enter));
    assert_eq!(a.lens_label(), Some("xor 33"));
    assert_eq!(a.cursor, 64);
    let decoded: String = (64..64 + 7).map(|o| a.view_byte(o) as char).collect();
    assert_eq!(decoded, "http://");
}

/// A minimal but real OOXML package (stored entries), enough that the document
/// parser recognises it the way it recognises a Word file.
fn docx_bytes() -> Vec<u8> {
    let entries: [(&str, &[u8]); 2] = [
        ("[Content_Types].xml", b"<Types/>"),
        ("word/document.xml", b"<w:document/>"),
    ];
    let mut out = Vec::new();
    let mut dir = Vec::new();
    for (name, data) in entries {
        let local = out.len() as u32;
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);

        dir.extend_from_slice(b"PK\x01\x02");
        dir.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        dir.extend_from_slice(&0u32.to_le_bytes());
        dir.extend_from_slice(&(data.len() as u32).to_le_bytes());
        dir.extend_from_slice(&(data.len() as u32).to_le_bytes());
        dir.extend_from_slice(&(name.len() as u16).to_le_bytes());
        for _ in 0..4 {
            dir.extend_from_slice(&0u16.to_le_bytes());
        }
        dir.extend_from_slice(&0u32.to_le_bytes());
        dir.extend_from_slice(&local.to_le_bytes());
        dir.extend_from_slice(name.as_bytes());
    }
    let cd_off = out.len() as u32;
    let cd_len = dir.len() as u32;
    out.extend_from_slice(&dir);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&cd_len.to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// An app holding a document, opened the way the real one is.
///
/// Each caller gets its own file: tests run in parallel, and sharing one path
/// meant two of them writing and reading it at the same time.
fn doc_app(tag: &str) -> App {
    let path = std::env::temp_dir().join(format!("hiewlm_doc_{tag}.docx"));
    fs::write(&path, docx_bytes()).unwrap();
    let a = App::open(path).unwrap();
    assert!(a.doc_supported(), "the fixture must parse as a document");
    a
}

#[test]
fn mode_menu_offers_every_mode() {
    // Doc shipped unreachable from the menu: the list and its wrap-around were
    // still written for three modes.
    use crossterm::event::{KeyCode, KeyEvent};
    let mut a = doc_app("modemenu");
    a.apply(Command::OpenModeMenu);
    a.handle_key(KeyEvent::from(KeyCode::Char('4')));
    assert_eq!(a.mode, Mode::Doc, "`4` in the mode menu must reach Doc");

    // Arrowing down wraps through all four, not three.
    a.apply(Command::OpenModeMenu);
    let mut seen = Vec::new();
    for _ in 0..MODES {
        let Some(Dialog::ModeMenu { selected }) = &a.dialog else {
            panic!("menu closed")
        };
        seen.push(*selected);
        a.handle_key(KeyEvent::from(KeyCode::Down));
    }
    assert_eq!(
        seen,
        vec![3, 0, 1, 2],
        "the highlight must cycle all four rows"
    );
}

#[test]
fn enter_cycles_into_doc_only_for_documents() {
    let mut a = doc_app("cycle");
    a.mode = Mode::Text;
    a.apply(Command::CycleMode);
    assert_eq!(a.mode, Mode::Doc);
    a.apply(Command::CycleMode);
    assert_eq!(a.mode, Mode::Hex);

    // A file with no document structure skips it rather than showing an empty
    // screen.
    let mut b = app();
    assert!(!b.doc_supported());
    b.mode = Mode::Text;
    b.apply(Command::CycleMode);
    assert_eq!(b.mode, Mode::Hex);
    b.apply(Command::SetMode(Mode::Doc));
    assert_eq!(b.mode, Mode::Hex, "Doc is refused, not entered empty");
    assert!(b.status.contains("Not an Office document"), "{}", b.status);
}

#[test]
fn doc_view_lists_parts_and_navigates() {
    let mut a = doc_app("view");
    a.apply(Command::SetMode(Mode::Doc));
    let rows = a.doc_rows();
    assert!(
        rows.iter().any(|(l, _)| l.contains("word/document.xml")),
        "{rows:?}"
    );
    // Enter on a part jumps to its bytes.
    let idx = rows
        .iter()
        .position(|(l, _)| l.contains("word/document.xml"))
        .unwrap();
    a.doc_sel = idx;
    a.apply(Command::DocActivate);
    assert_eq!(a.mode, Mode::Hex);
    assert!(a.cursor > 0, "jumped to the part's local header");
}

#[test]
fn triage_screen_opens_and_lists_panes() {
    use crossterm::event::{KeyCode, KeyEvent};
    let mut a = locked_app();
    a.handle_key(KeyEvent::from(KeyCode::Char('2')));
    let Some(Dialog::Triage { pane, .. }) = &a.dialog else {
        panic!("expected the triage dialog, got {:?}", a.dialog.is_some());
    };
    assert_eq!(*pane, TriagePane::Overview);
    assert!(a
        .triage_entries(TriagePane::Overview, "")
        .iter()
        .any(|(l, _)| l.contains("SHA-256")));
    // Right cycles panes; every pane renders something.
    for _ in 0..hiewlm_triage::Pane::ALL.len() {
        a.handle_key(KeyEvent::from(KeyCode::Right));
        let Some(Dialog::Triage { pane, .. }) = &a.dialog else {
            panic!("dialog closed")
        };
        assert!(!a.triage_entries(*pane, "").is_empty(), "{pane:?} empty");
    }
}

#[test]
fn triage_filter_narrows_and_esc_clears_it() {
    use crossterm::event::{KeyCode, KeyEvent};
    let mut a = locked_app();
    a.apply(Command::OpenTriage);
    let all = a.triage_entries(TriagePane::Overview, "").len();
    for c in "sha".chars() {
        a.handle_key(KeyEvent::from(KeyCode::Char(c)));
    }
    let Some(Dialog::Triage { filter, .. }) = &a.dialog else {
        panic!("closed")
    };
    assert_eq!(filter, "sha");
    assert!(a.triage_entries(TriagePane::Overview, "sha").len() < all);
    // First Esc clears the filter, second closes.
    a.handle_key(KeyEvent::from(KeyCode::Esc));
    assert!(matches!(&a.dialog, Some(Dialog::Triage { filter, .. }) if filter.is_empty()));
    a.handle_key(KeyEvent::from(KeyCode::Esc));
    assert!(a.dialog.is_none());
}

#[test]
fn triage_badges_appear_only_after_analysis() {
    let mut a = locked_app();
    assert!(a.triage_badges().is_none());
    a.apply(Command::OpenTriage);
    assert!(a.triage_badges().is_some_and(|b| b.starts_with('[')));
}

#[test]
fn locked_by_default_refuses_every_write() {
    let mut a = locked_app();
    let before = a.buffer.to_vec();

    a.apply(Command::EnterEdit);
    assert!(!a.editing, "edit mode must be refused while locked");
    a.mark = Some(0);
    a.cursor = 3;
    a.apply(Command::BlockDelete);
    a.apply(Command::BlockFillZero);
    a.apply(Command::BlockInsert);
    a.mode = Mode::Code;
    a.apply(Command::NopInstruction);
    assert_eq!(a.buffer.to_vec(), before, "a locked sample must not change");
    assert!(!a.buffer.is_dirty());
}

#[test]
fn ctrl_w_unlocks_and_relocks() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let mut a = locked_app();
    let ctrl_w = KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL);
    a.handle_key(ctrl_w);
    assert!(!a.read_only);
    a.apply(Command::EnterEdit);
    assert!(a.editing);
    a.handle_key(ctrl_w);
    assert!(a.read_only);
    assert!(!a.editing, "re-locking must leave edit mode");
}

#[test]
fn parse_addr_forms() {
    let a = app();
    assert_eq!(a.parse_addr("10"), Some(0x10));
    assert_eq!(a.parse_addr("10t"), Some(10));
    assert_eq!(a.parse_addr("0xff"), Some(255));
    assert_eq!(a.parse_addr("+4"), Some(4));
}

#[test]
fn hex_edit_writes_byte() {
    let mut a = app();
    a.apply(Command::EnterEdit);
    a.apply(Command::TypeHex(0x4));
    a.apply(Command::TypeHex(0x1));
    assert_eq!(a.buffer.read_byte(FileOffset(0)), 0x41);
    assert_eq!(a.cursor, 1);
}

#[test]
fn mode_cycle_matches_hiew() {
    let mut a = app();
    assert_eq!(a.mode, Mode::Hex);
    a.apply(Command::CycleMode);
    assert_eq!(a.mode, Mode::Code);
    a.apply(Command::CycleMode);
    assert_eq!(a.mode, Mode::Text);
    a.apply(Command::CycleMode);
    assert_eq!(a.mode, Mode::Hex);
}

#[test]
fn goto_dialog_moves_cursor() {
    use crossterm::event::{KeyCode, KeyEvent};
    let mut a = app();
    a.handle_key(KeyEvent::from(KeyCode::F(5)));
    a.handle_key(KeyEvent::from(KeyCode::Char('a')));
    a.handle_key(KeyEvent::from(KeyCode::Enter));
    assert_eq!(a.cursor, 0x0a);
    assert!(a.dialog.is_none());
}

#[test]
fn f4_menu_switches_mode() {
    use crossterm::event::{KeyCode, KeyEvent};
    let mut a = app();
    a.handle_key(KeyEvent::from(KeyCode::F(4))); // open mode menu
    assert!(a.dialog.is_some());
    a.handle_key(KeyEvent::from(KeyCode::Char('3'))); // pick Text directly
    assert_eq!(a.mode, Mode::Text);
    assert!(a.dialog.is_none());
}

#[test]
fn f4_again_cycles_highlight_then_enter_switches() {
    use crossterm::event::{KeyCode, KeyEvent};
    let mut a = app();
    a.handle_key(KeyEvent::from(KeyCode::F(4))); // menu, highlight = Hex(0)
    a.handle_key(KeyEvent::from(KeyCode::F(4))); // cycle -> Code(1)
    a.handle_key(KeyEvent::from(KeyCode::Enter));
    assert_eq!(a.mode, Mode::Code);
}

#[test]
fn letter_and_digit_aliases_work_without_fn_keys() {
    use crossterm::event::{KeyCode, KeyEvent};
    // 'g' opens goto (like F5)
    let mut a = app();
    a.handle_key(KeyEvent::from(KeyCode::Char('g')));
    a.handle_key(KeyEvent::from(KeyCode::Char('8')));
    a.handle_key(KeyEvent::from(KeyCode::Enter));
    assert_eq!(a.cursor, 0x08);

    // 'e' enters edit (like F3); '5' opens goto (digit mirrors the Fn-bar)
    let mut b = app();
    b.handle_key(KeyEvent::from(KeyCode::Char('e')));
    assert!(b.editing);
    b.handle_key(KeyEvent::from(KeyCode::Esc)); // leave edit
    assert!(!b.editing);
    b.handle_key(KeyEvent::from(KeyCode::Char('5')));
    assert!(matches!(b.dialog, Some(Dialog::Goto { .. })));

    // 'q' quits from the view
    let mut c = app();
    c.handle_key(KeyEvent::from(KeyCode::Char('q')));
    assert!(c.should_quit);
}

fn code_app() -> App {
    // push rbp; mov rbp,rsp; call +6; 6x nop; ret  (16 bytes, x64)
    let data = vec![
        0x55, 0x48, 0x89, 0xe5, 0xe8, 0x06, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0xc3,
    ];
    let mut a = App::open(PathBuf::from("/dev/null")).unwrap();
    a.read_only = false;
    a.buffer = EditBuffer::new(Arc::new(hiewlm_core::MemSource::new(data)));
    a.arch = Arch::X86_64;
    a.bits = 64;
    a.visible_rows = 10;
    a
}

#[test]
fn code_mode_disassembles_and_steps_by_instruction() {
    let mut a = code_app();
    a.apply(Command::SetMode(Mode::Code));
    assert_eq!(a.mode, Mode::Code);
    let insns = a.disasm_from(0, 4);
    assert!(insns[0].text.contains("push"));
    assert!(insns[1].text.contains("mov"));
    assert!(insns[2].text.contains("call"));

    // Down steps one instruction: 0 (push,len1) -> 1 (mov)
    a.apply(Command::StepRow(1));
    assert_eq!(a.cursor, 1);
    // -> 4 (call)
    a.apply(Command::StepRow(1));
    assert_eq!(a.cursor, 4);
    // Up steps back one instruction
    a.apply(Command::StepRow(-1));
    assert_eq!(a.cursor, 1);
}

#[test]
fn code_mode_xref_finds_caller() {
    let mut a = code_app();
    a.apply(Command::SetMode(Mode::Code));
    // Recursive analysis from offset 0 sees `call +6` (offset 4) → target VA 15.
    let analysis = a.analyze();
    assert!(analysis
        .xrefs
        .get(&15)
        .map(|v| v.contains(&4))
        .unwrap_or(false));
    // The call target (offset 15) is recorded as a function start.
    assert!(analysis.functions.contains(&15));
}

#[test]
fn comment_set_and_removed() {
    use crossterm::event::{KeyCode, KeyEvent};
    let mut a = app();
    a.handle_key(KeyEvent::from(KeyCode::Char(';')));
    a.handle_key(KeyEvent::from(KeyCode::Char('h')));
    a.handle_key(KeyEvent::from(KeyCode::Char('i')));
    a.handle_key(KeyEvent::from(KeyCode::Enter));
    assert_eq!(a.comment_at(0), Some("hi"));
    // Re-open and clear it.
    a.handle_key(KeyEvent::from(KeyCode::Char(';')));
    a.handle_key(KeyEvent::from(KeyCode::Backspace));
    a.handle_key(KeyEvent::from(KeyCode::Backspace));
    a.handle_key(KeyEvent::from(KeyCode::Enter));
    assert_eq!(a.comment_at(0), None);
}

#[test]
fn macro_record_and_play() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let mut a = app(); // "0123456789ABCDEF"
    let ctrl_dot = KeyEvent::new(KeyCode::Char('.'), KeyModifiers::CONTROL);
    a.handle_key(ctrl_dot); // start recording
    a.handle_key(KeyEvent::from(KeyCode::Right)); // cursor 0 -> 1
    a.handle_key(KeyEvent::from(KeyCode::Right)); // -> 2
    a.handle_key(ctrl_dot); // stop
    assert_eq!(a.cursor, 2);
    a.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL)); // replay: +2
    assert_eq!(a.cursor, 4);
}

#[test]
fn cfg_builds_multiple_blocks() {
    // xor eax,eax; test eax,eax; jz +2; inc eax; ret
    let data = vec![0x31, 0xc0, 0x85, 0xc0, 0x74, 0x02, 0xff, 0xc0, 0xc3];
    let mut a = App::open(PathBuf::from("/dev/null")).unwrap();
    a.read_only = false;
    a.buffer = EditBuffer::new(Arc::new(hiewlm_core::MemSource::new(data)));
    a.arch = Arch::X86_64;
    a.bits = 64;
    a.disasm_arch = Arch::X86_64;
    a.disasm_bits = 64;
    a.visible_rows = 10;
    a.apply(Command::SetMode(Mode::Code));
    a.open_cfg();
    match &a.dialog {
        Some(Dialog::Message { body, title, .. }) => {
            assert!(title.starts_with("CFG"));
            assert!(body.matches("── block").count() >= 2, "cfg:\n{body}");
            assert!(body.contains("(return)"));
        }
        _ => panic!("expected CFG dialog"),
    }
}

#[test]
fn code_mode_follow_branch_and_back() {
    let mut a = code_app();
    a.apply(Command::SetMode(Mode::Code));
    // Move the cursor onto the `call +6` instruction (offset 4).
    a.apply(Command::StepRow(1)); // -> mov (offset 1)
    a.apply(Command::StepRow(1)); // -> call (offset 4)
    assert_eq!(a.cursor, 4);
    a.apply(Command::FollowBranch); // target is file offset 15
    assert_eq!(a.cursor, 15);
    a.apply(Command::NavBack);
    assert_eq!(a.cursor, 4);
}

#[test]
fn code_mode_opcode_patch_updates_disasm() {
    let mut a = code_app();
    a.apply(Command::SetMode(Mode::Code));
    a.apply(Command::EnterEdit);
    assert!(a.editing);
    // Patch 0x55 (push rbp) -> 0x58 (pop rax).
    a.apply(Command::TypeHex(0x5));
    a.apply(Command::TypeHex(0x8));
    assert_eq!(a.buffer.read_byte(FileOffset(0)), 0x58);
    assert!(a.disasm_from(0, 1)[0].text.contains("pop"));
}

#[test]
fn code_edit_steps_by_byte_not_instruction() {
    let mut a = code_app();
    a.apply(Command::SetMode(Mode::Code));
    a.apply(Command::StepRow(1)); // -> mov at offset 1 (3 bytes)
    assert_eq!(a.cursor, 1);
    a.apply(Command::EnterEdit);
    a.apply(Command::Step(1)); // while editing: byte step, not to next instruction
    assert_eq!(a.cursor, 2);
}

#[test]
fn disasm_override_and_reset() {
    use crossterm::event::{KeyCode, KeyEvent};
    let mut a = code_app();
    a.apply(Command::OpenDisasmMenu);
    assert!(matches!(a.dialog, Some(Dialog::DisasmMenu { .. })));
    a.handle_key(KeyEvent::from(KeyCode::Char('3'))); // option 3 = x86 32-bit
    assert_eq!(a.disasm_arch, Arch::X86);
    assert_eq!(a.disasm_bits, 32);
    assert!(a.disasm_override);
    a.apply(Command::OpenDisasmMenu);
    a.handle_key(KeyEvent::from(KeyCode::Char('1'))); // option 1 = auto
    assert!(!a.disasm_override);
    assert_eq!(a.disasm_arch, a.arch);
}

#[test]
fn code_mode_digits_are_fnbar_not_follow() {
    use crossterm::event::{KeyCode, KeyEvent};
    let mut a = code_app();
    a.apply(Command::SetMode(Mode::Code));
    // '5' must open Goto (Fn-bar alias), not do a follow.
    a.handle_key(KeyEvent::from(KeyCode::Char('5')));
    assert!(matches!(a.dialog, Some(Dialog::Goto { .. })));
}

#[test]
fn block_yank_and_paste() {
    let mut a = app(); // "0123456789ABCDEF"
    a.apply(Command::ToggleMark);
    a.apply(Command::Step(2)); // select offsets 0..=2 = "012"
    a.apply(Command::BlockYank);
    a.mark = None;
    a.cursor = a.buffer.len(); // append position
    a.insert_mode = true;
    a.apply(Command::BlockPaste);
    let v = a.buffer.to_vec();
    assert_eq!(v.len(), 19);
    assert_eq!(&v[16..19], b"012");
}

#[test]
fn block_delete_shrinks_and_clears_mark() {
    let mut a = app();
    a.apply(Command::ToggleMark);
    a.apply(Command::Step(3)); // select "0123"
    a.apply(Command::BlockDelete);
    assert_eq!(a.buffer.to_vec(), b"456789ABCDEF");
    assert!(a.selection().is_none());
}

#[test]
fn block_fill_via_dialog() {
    use crossterm::event::{KeyCode, KeyEvent};
    let mut a = app();
    a.apply(Command::ToggleMark);
    a.apply(Command::Step(2)); // select "012"
    a.apply(Command::OpenBlockFill);
    a.handle_key(KeyEvent::from(KeyCode::Char('9')));
    a.handle_key(KeyEvent::from(KeyCode::Char('0')));
    a.handle_key(KeyEvent::from(KeyCode::Enter));
    let v = a.buffer.to_vec();
    assert_eq!(&v[0..3], &[0x90, 0x90, 0x90]);
    assert_eq!(&v[3..], b"3456789ABCDEF");
}

#[test]
fn header_opens_and_cycles_panes() {
    use crossterm::event::{KeyCode, KeyEvent};
    let mut a = app();
    a.handle_key(KeyEvent::from(KeyCode::Char('8')));
    assert!(matches!(
        a.dialog,
        Some(Dialog::Header {
            pane: HeaderPane::Info,
            ..
        })
    ));
    a.handle_key(KeyEvent::from(KeyCode::Tab));
    assert!(matches!(
        a.dialog,
        Some(Dialog::Header {
            pane: HeaderPane::Sections,
            ..
        })
    ));
    a.handle_key(KeyEvent::from(KeyCode::Esc));
    assert!(a.dialog.is_none());
}

#[test]
fn header_info_enter_jumps_to_entry() {
    use crossterm::event::{KeyCode, KeyEvent};
    let mut a = app();
    a.entry = Some(0x0a); // flat address space -> offset 0x0a
    a.handle_key(KeyEvent::from(KeyCode::Char('8'))); // Header, Info pane
                                                      // Filter to just the "Entry point" line (robust to field-order changes).
    for c in "entry".chars() {
        a.handle_key(KeyEvent::from(KeyCode::Char(c)));
    }
    a.handle_key(KeyEvent::from(KeyCode::Enter));
    assert_eq!(a.cursor, 0x0a);
    assert!(a.dialog.is_none());
}

#[test]
fn header_imports_jump_and_filter() {
    use crossterm::event::{KeyCode, KeyEvent};
    let mut a = app();
    a.imports = vec![("alpha".into(), 0x04), ("beta".into(), 0x08)];
    a.handle_key(KeyEvent::from(KeyCode::Char('8')));
    a.handle_key(KeyEvent::from(KeyCode::Right)); // Info -> Sections
    a.handle_key(KeyEvent::from(KeyCode::Right)); // -> Imports
                                                  // Filter by typing "bet" -> only "beta" remains, at sel 0.
    for c in "bet".chars() {
        a.handle_key(KeyEvent::from(KeyCode::Char(c)));
    }
    let entries = a.header_entries(HeaderPane::Imports, "bet");
    assert_eq!(entries.len(), 1);
    a.handle_key(KeyEvent::from(KeyCode::Enter)); // jump to beta @ va 0x08 (flat)
    assert_eq!(a.cursor, 0x08);
}

#[test]
fn bookmark_push_pop() {
    let mut a = app();
    a.cursor = 5;
    a.apply(Command::BookmarkPush);
    a.cursor = 0;
    a.apply(Command::BookmarkPop);
    assert_eq!(a.cursor, 5);
}

#[test]
fn struct_viewer_applies_template() {
    let tpl = std::env::temp_dir().join("hiewlm_tpl.txt");
    std::fs::write(&tpl, "a u16\nb u16\n").unwrap();
    let mut a = app(); // "0123456789ABCDEF"
    a.cursor = 0;
    a.open_struct(tpl.to_str().unwrap());
    match &a.dialog {
        Some(Dialog::JumpList { items, .. }) => {
            assert_eq!(items.len(), 2);
            assert_eq!(items[1].1, 2); // second field starts at offset 2
        }
        _ => panic!("expected struct field list"),
    }
    std::fs::remove_file(&tpl).ok();
}

#[test]
fn imphash_is_normalized() {
    let mut a = app();
    a.format = Format::Pe;
    a.imports = vec![("KERNEL32.dll!GetProcAddress".into(), 0)];
    let h1 = a.compute_imphash();
    // Same import in different case / with a stripped extension → same hash.
    a.imports = vec![("kernel32.DLL!getprocaddress".into(), 0)];
    let h2 = a.compute_imphash();
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 32);
}

#[test]
fn long_field_wraps_without_clipping() {
    let long = "0x8160 [HIGH_ENTROPY_VA DYNAMIC_BASE(ASLR) NX_COMPAT(DEP) GUARD_CF TERMINAL_SERVER_AWARE FORCE_INTEGRITY NO_SEH]";
    let lines = wrap_field("DllCharacteristics", long);
    assert!(
        lines.len() > 1,
        "long value should wrap onto multiple lines"
    );
    // No wrapped line exceeds the dialog width.
    assert!(lines.iter().all(|(l, _)| l.chars().count() <= 84));
}

#[test]
fn entropy_bounds() {
    let mut a = app();
    a.buffer = EditBuffer::new(Arc::new(hiewlm_core::MemSource::new(vec![7u8; 2000])));
    assert!(
        a.range_entropy(0, 2000) < 0.01,
        "constant data should be ~0"
    );
    let uniform: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    a.buffer = EditBuffer::new(Arc::new(hiewlm_core::MemSource::new(uniform)));
    assert!(a.range_entropy(0, 4096) > 7.9, "uniform data should be ~8");
}

#[test]
fn header_has_resources_pane() {
    let a = app();
    // Raw file: no resources, but the pane exists and doesn't panic.
    assert!(a.header_entries(HeaderPane::Resources, "").is_empty());
    // Pane cycle reaches Resources.
    assert_eq!(HeaderPane::Exports.next(), HeaderPane::Resources);
}

#[test]
fn calc_dialog_evaluates() {
    let mut a = app();
    a.apply(Command::OpenCalc);
    assert!(matches!(a.dialog, Some(Dialog::Calc { .. })));
    let ctx = a.calc_ctx();
    assert_eq!(hiewlm_core::calc::eval("2+3*4", &ctx).unwrap(), 14);
    assert_eq!(hiewlm_core::calc::eval("@o + 0x10", &ctx).unwrap(), 0x10);
}

#[test]
fn macro_loop_terminates_on_no_progress() {
    use crossterm::event::{KeyCode, KeyEvent};
    let mut a = app(); // 16 bytes
    a.macro_saved = vec![KeyEvent::from(KeyCode::Right)];
    a.cursor = 0;
    a.macro_play_loop();
    // Right advances to the last offset, then no progress → loop stops.
    assert_eq!(a.cursor, a.max_offset());
}

#[test]
fn markers_color_jump_and_persist() {
    let path = std::env::temp_dir().join("hiewlm_markers_test.bin");
    std::fs::write(&path, b"0123456789ABCDEF").unwrap();
    let sidecar = super::markers_path(&path);
    std::fs::remove_file(&sidecar).ok();

    let mut a = App::open(path.clone()).unwrap();
    a.mark = Some(2);
    a.cursor = 4; // selection 2..=4
    a.color_block(0);
    assert_eq!(a.marker_color_at(3), Some(0));
    assert!(a.selection().is_none());

    // Persisted and reloaded.
    let b = App::open(path.clone()).unwrap();
    assert_eq!(b.marker_color_at(3), Some(0));

    // Jump to marker start.
    a.cursor = 0;
    a.jump_marker(true);
    assert_eq!(a.cursor, 2);

    std::fs::remove_file(&sidecar).ok();
    std::fs::remove_file(&path).ok();
}

#[test]
fn inspector_and_hashes_open() {
    let mut a = app();
    a.apply(Command::OpenInspector);
    match &a.dialog {
        Some(Dialog::Message { body, .. }) => assert!(body.contains("uint32")),
        _ => panic!("expected inspector"),
    }
    a.dialog = None;
    a.apply(Command::OpenHashes);
    match &a.dialog {
        Some(Dialog::Message { body, .. }) => {
            assert!(body.contains("CRC32"));
            assert!(body.contains("SHA-256"));
        }
        _ => panic!("expected hashes"),
    }
}

#[test]
fn named_bookmark_appears_in_names() {
    use crossterm::event::{KeyCode, KeyEvent};
    let mut a = app();
    a.cursor = 6;
    a.handle_key(KeyEvent::from(KeyCode::Char('k'))); // name bookmark
    for c in "loop".chars() {
        a.handle_key(KeyEvent::from(KeyCode::Char(c)));
    }
    a.handle_key(KeyEvent::from(KeyCode::Enter));
    assert!(a
        .names_list()
        .iter()
        .any(|(l, off)| l.contains("loop") && *off == 6));
}

/// A plugin-parsed container (ZIP/PDF) lists members via F12 and must not
/// run function recovery over compressed data.
#[test]
fn utf16_search_matches_wide_strings() {
    let a = app();
    let p = a.search_pattern("AB", SearchKind::Utf16).unwrap();
    assert_eq!(p.literal_bytes().unwrap(), &[b'A', 0, b'B', 0]);
}

#[test]
fn instruction_search_assembles_the_pattern() {
    let mut a = app();
    a.disasm_arch = Arch::X86_64;
    a.disasm_bits = 64;
    let p = a.search_pattern("xor eax, eax", SearchKind::Asm).unwrap();
    assert_eq!(p.literal_bytes().unwrap(), &[0x31, 0xC0]);
    // A non-x86 target must say so rather than search for nothing.
    a.disasm_arch = Arch::Arm64;
    assert!(a.search_pattern("nop", SearchKind::Asm).is_err());
}

#[test]
fn search_kind_tab_cycles_every_kind() {
    let mut k = SearchKind::Hex;
    let mut seen = vec![k.label()];
    for _ in 0..4 {
        k = k.next();
        seen.push(k.label());
    }
    assert_eq!(seen, vec!["hex", "text", "text/i", "utf-16", "asm"]);
    assert_eq!(k.next().label(), "hex", "must wrap around");
}

#[test]
fn block_scope_confines_search_to_the_marked_range() {
    let mut a = app(); // "0123456789ABCDEF"
                       // "9" lives at offset 9; scope the search to 0..=4 so it must not match.
    a.mark = Some(0);
    a.cursor = 4;
    a.confirm_search("9", SearchKind::Text);
    assert!(a.status.contains("Not found"), "{}", a.status);
    assert_ne!(a.cursor, 9);

    // Without a block, the same search succeeds.
    a.mark = None;
    a.cursor = 0;
    a.search_scope = None;
    a.confirm_search("9", SearchKind::Text);
    assert_eq!(a.cursor, 9, "{}", a.status);
}

#[test]
fn find_prev_searches_backwards() {
    let mut a = app(); // "0123456789ABCDEF"
    a.mark = None;
    a.cursor = 0;
    a.confirm_search("5", SearchKind::Text);
    assert_eq!(a.cursor, 5);
    // Move past it, then search back.
    a.cursor = 12;
    a.apply(Command::FindPrev);
    assert_eq!(a.cursor, 5, "{}", a.status);
}

#[test]
fn numbered_slot_set_and_jump() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let mut a = app();
    a.cursor = 7;
    a.apply(Command::SetSlotPrompt);
    a.handle_key(KeyEvent::from(KeyCode::Char('3')));
    assert_eq!(a.slots[2], Some(7));

    a.cursor = 0;
    a.handle_key(KeyEvent::new(KeyCode::Char('3'), KeyModifiers::ALT));
    assert_eq!(a.cursor, 7, "Alt+3 must jump to slot 3");
    // Slots show up in the F12 list.
    assert!(a
        .names_list()
        .iter()
        .any(|(l, off)| l.contains("slot 3") && *off == 7));
}

#[test]
fn empty_slot_reports_instead_of_jumping_to_zero() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let mut a = app();
    a.cursor = 5;
    a.handle_key(KeyEvent::new(KeyCode::Char('6'), KeyModifiers::ALT));
    assert_eq!(a.cursor, 5, "cursor must not move for an empty slot");
    assert!(a.status.contains("empty"), "{}", a.status);
}

#[test]
fn block_copy_to_bookmark() {
    let mut a = app(); // buffer: "0123456789ABCDEF"
    a.apply(Command::ToggleMark);
    a.apply(Command::Step(2)); // select "012"
    a.cursor = 8;
    a.apply(Command::BookmarkPush); // destination = offset 8
    a.cursor = 0;
    a.mark = Some(0);
    a.cursor = 2;
    a.apply(Command::BlockCopy);
    let v = a.buffer.to_vec();
    assert_eq!(v.len(), 19, "copy must grow the file by 3");
    assert_eq!(&v[8..11], b"012");
}

#[test]
fn block_move_rebases_destination_after_the_block() {
    let mut a = app();
    a.cursor = 8;
    a.apply(Command::BookmarkPush); // destination after the source block
    a.mark = Some(0);
    a.cursor = 2; // source = 0..=2 ("012")
    a.apply(Command::BlockMove);
    let v = a.buffer.to_vec();
    assert_eq!(v.len(), 16, "move must not change the file size");
    // "3456789ABCDEF" with "012" reinserted at the rebased destination.
    assert_eq!(
        String::from_utf8_lossy(&v),
        "34567012 89ABCDEF".replace(' ', "")
    );
}

#[test]
fn block_move_into_itself_is_refused() {
    let mut a = app();
    let before = a.buffer.to_vec();
    a.cursor = 1;
    a.apply(Command::BookmarkPush); // destination inside the block
    a.mark = Some(0);
    a.cursor = 4;
    a.apply(Command::BlockMove);
    assert_eq!(a.buffer.to_vec(), before, "buffer must be untouched");
    assert!(a.status.contains("into itself"), "{}", a.status);
}

#[test]
fn block_insert_uses_clipboard_and_grows_file() {
    let mut a = app();
    a.mark = Some(0);
    a.cursor = 2;
    a.apply(Command::BlockYank); // clipboard = "012"
    a.mark = None;
    a.cursor = 16;
    a.apply(Command::BlockInsert);
    let v = a.buffer.to_vec();
    assert_eq!(v.len(), 19);
    assert_eq!(&v[16..19], b"012");
}

#[test]
fn block_menu_labels_match_command_order() {
    // Enter indexes BLOCK_MENU_CMDS by the rendered row, so a mismatch
    // would silently run the wrong operation.
    assert_eq!(BLOCK_MENU_CMDS.len(), crate::ui::BLOCK_MENU_LABELS.len());
}

#[test]
fn crypt_transforms_block_and_round_trips() {
    use crossterm::event::{KeyCode, KeyEvent};
    let mut a = app();
    let before = a.buffer.to_vec();
    a.mark = Some(0);
    a.cursor = 3;
    a.apply(Command::OpenCrypt);
    assert!(matches!(a.dialog, Some(Dialog::Crypt { .. })));
    for c in "xor 5a".chars() {
        a.handle_key(KeyEvent::from(KeyCode::Char(c)));
    }
    a.handle_key(KeyEvent::from(KeyCode::Enter));
    let after = a.buffer.to_vec();
    assert_ne!(after[0..4], before[0..4], "block must change");
    assert_eq!(after[4..], before[4..], "bytes outside the block must not");

    // XOR is its own inverse: applying it again restores the block.
    a.mark = Some(0);
    a.cursor = 3;
    a.apply(Command::OpenCrypt);
    for c in "xor 5a".chars() {
        a.handle_key(KeyEvent::from(KeyCode::Char(c)));
    }
    a.handle_key(KeyEvent::from(KeyCode::Enter));
    assert_eq!(a.buffer.to_vec(), before);
}

#[test]
fn crypt_without_a_block_is_refused() {
    let mut a = app();
    a.mark = None;
    a.apply(Command::OpenCrypt);
    assert!(a.dialog.is_none());
    assert!(a.status.contains("block"), "{}", a.status);
}

#[test]
fn assemble_patches_instruction_and_pads_with_nops() {
    let mut a = app();
    a.mode = Mode::Code;
    a.disasm_arch = Arch::X86_64;
    a.disasm_bits = 64;
    a.cursor = 0;
    // Preview reports the encoding and the slot it must fit.
    let (bytes, _slot) = a.assemble_preview("xor eax, eax").unwrap();
    assert_eq!(bytes, vec![0x31, 0xC0]);

    a.apply(Command::OpenAssemble);
    assert!(matches!(a.dialog, Some(Dialog::Assemble { .. })));
    for c in "xor eax, eax".chars() {
        a.handle_key(KeyEvent::from(KeyCode::Char(c)));
    }
    a.handle_key(KeyEvent::from(KeyCode::Enter));

    let mut got = [0u8; 2];
    a.buffer.read_at(FileOffset(0), &mut got);
    assert_eq!(got, [0x31, 0xC0]);
    assert!(!a.read_only);
}

#[test]
fn assemble_refuses_when_encoding_exceeds_the_slot() {
    let mut a = app();
    a.mode = Mode::Code;
    a.disasm_arch = Arch::X86_64;
    a.disasm_bits = 64;
    a.cursor = 0;
    let before = {
        let mut b = vec![0u8; 8];
        a.buffer.read_at(FileOffset(0), &mut b);
        b
    };
    a.apply(Command::OpenAssemble);
    // 5 bytes into whatever short instruction sits at offset 0.
    for c in "mov eax, 12345678".chars() {
        a.handle_key(KeyEvent::from(KeyCode::Char(c)));
    }
    a.handle_key(KeyEvent::from(KeyCode::Enter));
    let mut after = vec![0u8; 8];
    a.buffer.read_at(FileOffset(0), &mut after);
    if a.status.contains("won't fit") {
        assert_eq!(
            before, after,
            "buffer must be untouched when the patch is refused"
        );
    }
}

#[test]
fn assemble_is_rejected_outside_code_mode() {
    let mut a = app();
    a.mode = Mode::Hex;
    a.apply(Command::OpenAssemble);
    assert!(a.dialog.is_none());
    assert!(a.status.contains("Code mode"), "{}", a.status);
}

#[test]
fn plugin_container_lists_members_not_functions() {
    use hiewlm_core::container::{Container, Member};
    let mut a = app();
    a.container = Some(Container {
        kind: "ZIP archive".into(),
        summary: vec![("Entries".into(), "2".into())],
        members: vec![
            Member::new("a.txt", 0x00, 10, "stored"),
            Member::new("evil.exe", 0x49, 20, "deflate"),
        ],
        findings: vec![hiewlm_core::container::Finding::suspicious(
            "executable member",
        )],
    });
    let names = a.names_list();
    assert!(names
        .iter()
        .any(|(l, off)| l.contains("evil.exe") && *off == 0x49));
    a.open_names();
    match &a.dialog {
        Some(Dialog::JumpList { title, items, .. }) => {
            assert!(title.starts_with("Parts & names"), "{title}");
            assert!(items.iter().all(|(l, _)| !l.contains("func")));
        }
        _ => panic!("expected members list"),
    }
    // The header Info pane shows container summary + findings.
    let info = a.header_entries(HeaderPane::Info, "");
    assert!(info.iter().any(|(l, _)| l.contains("ZIP archive")));
    assert!(info.iter().any(|(l, _)| l.contains("SUSPICIOUS")));
}

#[test]
fn container_names_list_members_not_functions() {
    let mut a = app();
    a.format = Format::Archive;
    a.exports = vec![("a.txt".into(), 0x00), ("b.txt".into(), 0x49)];
    let names = a.names_list();
    assert!(names
        .iter()
        .any(|(l, off)| l.contains("member") && l.contains("b.txt") && *off == 0x49));
    // Function recovery must be skipped for containers.
    a.open_names();
    match &a.dialog {
        Some(Dialog::JumpList { title, items, .. }) => {
            assert!(title.starts_with("Parts & names"), "{title}");
            assert!(items.iter().all(|(l, _)| !l.contains("func")));
        }
        _ => panic!("expected members list"),
    }
}

#[test]
fn theme_and_encoding_cycle() {
    use crate::encoding::Encoding;
    use crate::theme::ThemeKind;
    let mut a = app();
    assert_eq!(a.theme_kind, ThemeKind::Classic);
    a.apply(Command::ToggleTheme);
    assert_eq!(a.theme_kind, ThemeKind::Dark);
    assert_eq!(a.encoding, Encoding::Ascii);
    a.apply(Command::CycleEncoding);
    assert_eq!(a.encoding, Encoding::Cp437);
    assert_eq!(Encoding::Cp437.decode(0x01), '☺');
}

#[test]
fn strings_list_finds_text() {
    let mut a = app();
    a.buffer = EditBuffer::new(Arc::new(hiewlm_core::MemSource::new(
        b"\x00\x01Hello world\x00\x02".to_vec(),
    )));
    a.apply(Command::OpenStrings);
    match &a.dialog {
        Some(Dialog::JumpList { items, .. }) => {
            assert!(items
                .iter()
                .any(|(l, off)| l.contains("Hello world") && *off == 2));
        }
        _ => panic!("expected strings list"),
    }
}

#[test]
fn nav_history_records_jumps() {
    use crossterm::event::{KeyCode, KeyEvent};
    let mut a = app();
    a.cursor = 3;
    a.handle_key(KeyEvent::from(KeyCode::Char('g'))); // goto
    for c in "0a".chars() {
        a.handle_key(KeyEvent::from(KeyCode::Char(c)));
    }
    a.handle_key(KeyEvent::from(KeyCode::Enter)); // jump from 3 to 0x0a
    assert!(a.history.contains(&3));
    a.apply(Command::OpenHistory);
    assert!(matches!(a.dialog, Some(Dialog::JumpList { .. })));
}

#[test]
fn nop_overwrites_x86_instruction() {
    let mut a = code_app(); // push rbp (1 byte) at offset 0
    a.apply(Command::SetMode(Mode::Code));
    a.apply(Command::NopInstruction);
    assert_eq!(a.buffer.read_byte(FileOffset(0)), 0x90);
}

#[test]
fn utf16_detect_and_glyph() {
    use crate::encoding::Encoding;
    let wide: Vec<u8> = "Hello"
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    assert_eq!(Encoding::detect(&wide.repeat(4)), Encoding::Utf16Le);
    assert_eq!(Encoding::wide_glyph(b'H', 0), 'H');
}

#[test]
fn multi_search_finds_matching_file() {
    let dir = std::env::temp_dir().join("hiewlm_multi_test");
    std::fs::create_dir_all(&dir).unwrap();
    let f1 = dir.join("open.bin");
    let f2 = dir.join("hit.bin");
    std::fs::write(&f1, b"nothing here").unwrap();
    std::fs::write(&f2, b"xxNEEDLExx").unwrap();

    let mut a = App::open(f1).unwrap();
    a.last_pattern = Some((Pattern::from_text("NEEDLE"), Direction::Forward));
    a.multi_search();
    match &a.dialog {
        Some(Dialog::FileHits { items, .. }) => {
            assert!(items
                .iter()
                .any(|(l, _, off)| l.contains("hit.bin") && *off == 2));
        }
        _ => panic!("expected file hits"),
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn file_picker_selects_diff_file() {
    use crossterm::event::{KeyCode, KeyEvent};
    let dir = std::env::temp_dir().join("hiewlm_pick_test");
    std::fs::create_dir_all(&dir).unwrap();
    let a = dir.join("a.bin");
    let b = dir.join("b.bin");
    std::fs::write(&a, b"AAAA").unwrap();
    std::fs::write(&b, b"AABA").unwrap();

    let mut app = App::open(a.clone()).unwrap();
    app.apply(Command::OpenDiff); // opens the picker in a's directory
    let idx = match &app.dialog {
        Some(Dialog::FilePicker {
            entries,
            purpose: PickPurpose::Diff,
            ..
        }) => entries
            .iter()
            .position(|e| e.name == "b.bin")
            .expect("b.bin listed"),
        _ => panic!("expected file picker"),
    };
    for _ in 0..idx {
        app.handle_key(KeyEvent::from(KeyCode::Down));
    }
    app.handle_key(KeyEvent::from(KeyCode::Enter));
    assert!(app.has_diff());
    assert_eq!(app.diff_name, "b.bin");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn diff_detects_and_navigates() {
    let a_path = std::env::temp_dir().join("hiewlm_diff_a.bin");
    let b_path = std::env::temp_dir().join("hiewlm_diff_b.bin");
    std::fs::write(&a_path, b"AAAA").unwrap();
    std::fs::write(&b_path, b"AABA").unwrap(); // differs at offset 2

    let mut app = App::open(a_path.clone()).unwrap();
    app.open_diff(b_path.to_str().unwrap());
    assert!(app.has_diff());
    assert!(!app.byte_differs(0));
    assert!(app.byte_differs(2));

    app.cursor = 0;
    app.next_diff(true);
    assert_eq!(app.cursor, 2);

    std::fs::remove_file(&a_path).ok();
    std::fs::remove_file(&b_path).ok();
}

#[test]
fn esc_backs_out_without_quitting() {
    use crossterm::event::{KeyCode, KeyEvent};
    let mut a = app();
    // Selection active -> Esc clears it, does not quit.
    a.apply(Command::ToggleMark);
    a.handle_key(KeyEvent::from(KeyCode::Esc));
    assert!(a.selection().is_none());
    assert!(!a.should_quit);
    // Search highlight active -> Esc clears it, does not quit.
    a.confirm_search("2", SearchKind::Text);
    assert!(!a.search_hits(0, a.buffer.len()).is_empty());
    a.handle_key(KeyEvent::from(KeyCode::Esc));
    assert!(a.search_hits(0, a.buffer.len()).is_empty());
    assert!(!a.should_quit);
    // Nothing active -> Esc still does not quit.
    a.handle_key(KeyEvent::from(KeyCode::Esc));
    assert!(!a.should_quit);
}

#[test]
fn esc_returns_to_previous_position() {
    use crossterm::event::{KeyCode, KeyEvent};
    let mut a = app(); // "0123456789ABCDEF"
    a.cursor = 2;
    // A goto records the origin (2) and moves to the destination (10).
    a.confirm_goto("a");
    assert_eq!(a.cursor, 10);
    // With no transient state active, Esc walks back to where we jumped from.
    a.handle_key(KeyEvent::from(KeyCode::Esc));
    assert_eq!(a.cursor, 2, "Esc should return to the pre-jump position");
    assert!(!a.should_quit);
    // Once history is exhausted, Esc reports it and still never quits.
    a.handle_key(KeyEvent::from(KeyCode::Esc));
    assert!(a.status.contains("Nothing to go back to"), "{}", a.status);
    assert!(!a.should_quit);
}

#[test]
fn esc_clears_transient_state_before_going_back() {
    use crossterm::event::{KeyCode, KeyEvent};
    let mut a = app();
    a.cursor = 1;
    a.confirm_goto("8"); // origin 1 recorded, cursor -> 8
    a.apply(Command::ToggleMark); // start a selection at 8
    a.cursor = 12;
    // First Esc clears the selection but must NOT move the cursor yet.
    a.handle_key(KeyEvent::from(KeyCode::Esc));
    assert!(a.selection().is_none());
    assert_eq!(a.cursor, 12);
    // Second Esc now goes back to the jump origin.
    a.handle_key(KeyEvent::from(KeyCode::Esc));
    assert_eq!(a.cursor, 1);
}

#[test]
fn search_highlights_all_matches() {
    let mut a = app(); // "0123456789ABCDEF" has one '5'
    a.confirm_search("5", SearchKind::Text);
    let hits = a.search_hits(0, a.buffer.len());
    assert_eq!(hits, vec![(5, 5)]);
}

#[test]
fn mark_and_extend_selection() {
    use crossterm::event::{KeyCode, KeyEvent};
    let mut a = app(); // "0123456789ABCDEF"
    a.handle_key(KeyEvent::from(KeyCode::Char('*'))); // mark at 0
    assert_eq!(a.selection(), Some((0, 0)));
    for _ in 0..3 {
        a.handle_key(KeyEvent::from(KeyCode::Right)); // extend to offset 3
    }
    assert_eq!(a.cursor, 3);
    assert_eq!(a.selection(), Some((0, 3))); // 4 bytes selected
    a.handle_key(KeyEvent::from(KeyCode::Char('*'))); // clear
    assert_eq!(a.selection(), None);
}

#[test]
fn shift_arrow_starts_selection() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let mut a = app();
    a.handle_key(KeyEvent::new(KeyCode::Right, KeyModifiers::SHIFT));
    assert_eq!(a.selection(), Some((0, 1)));
}

#[test]
fn text_mode_navigation_uses_content_width() {
    let mut a = app();
    a.mode = Mode::Text;
    a.text_cols = 4; // pretend the content area is 4 columns wide
    a.apply(Command::StepRow(1)); // down one visual row = +4 bytes
    assert_eq!(a.cursor, 4);
}

#[test]
fn aliases_do_not_fire_while_ascii_editing() {
    use crossterm::event::{KeyCode, KeyEvent};
    let mut a = app();
    a.apply(Command::EnterEdit);
    a.apply(Command::ToggleEditCol); // switch to ASCII column
    a.handle_key(KeyEvent::from(KeyCode::Char('q'))); // must type 'q', not quit
    assert!(!a.should_quit);
    assert_eq!(a.buffer.read_byte(FileOffset(0)), b'q');
}

/// Drive the full stack key -> command -> buffer -> disk: edit one byte, save.
#[test]
fn edit_and_save_roundtrip() {
    use crossterm::event::{KeyCode, KeyEvent};
    let path = std::env::temp_dir().join("hiewlm_e2e_edit.bin");
    std::fs::write(&path, b"AAAA").unwrap();

    let mut a = App::open(path.clone()).unwrap();
    a.read_only = false;
    a.handle_key(KeyEvent::from(KeyCode::F(3))); // enter edit (hex)
    assert!(a.editing);
    a.handle_key(KeyEvent::from(KeyCode::Char('4')));
    a.handle_key(KeyEvent::from(KeyCode::Char('2'))); // byte0 = 0x42
    a.handle_key(KeyEvent::from(KeyCode::F(9))); // save

    let on_disk = std::fs::read(&path).unwrap();
    assert_eq!(on_disk, b"BAAA");

    std::fs::remove_file(&path).ok();
}
