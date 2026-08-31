# M4 — "Triage-first": kế hoạch & bảng theo dõi tiến độ

> **Đây là nguồn sự thật duy nhất về tiến độ M4.**
> Quy tắc làm việc: mỗi lần hoàn tất một mục, đánh dấu `[x]` **ngay trong commit đó**.
> Khi mở lại phiên làm việc mới: đọc file này trước, tìm mục `[ ]` đầu tiên, làm tiếp từ đó.
> Mục đang làm dở đánh dấu `[~]` kèm ghi chú ở cột "Ghi chú".

Mục tiêu: tối đa hoá tốc độ **phân loại & phân tích mã độc ban đầu**.
Bối cảnh và lý do từng mục: xem review M4 trong lịch sử thảo luận và `00-overall-design.md`.

---

## M4.0 — Sửa lỗi & bất nhất (nền tảng an toàn)

| # | Mục | Trạng thái | Ghi chú |
|---|---|---|---|
| 0.1 | Khoá read-only THẬT (`--rw`, `Ctrl+W`, `ensure_writable()` chặn mọi lệnh ghi) | [x] | `read_only` hiện chỉ là nhãn; paste/delete không set cờ |
| 0.2 | Bỏ `N`=NOP (nguy hiểm cạnh `n`); NOP → `Alt+F2` + block menu | [x] | |
| 0.3 | Sửa binding chết `Alt+Shift+n`; `N` = FindPrev | [x] | keymap.rs:98 không bao giờ khớp |
| 0.4 | JumpList: filter gõ trực tiếp + PgUp/PgDn/Home/End | [x] | 20k strings mà chỉ có ↑↓ |
| 0.5 | README: sửa mô tả phím packer (`p` là BlockPaste) | [x] | |
| 0.6 | Strings: báo khi bị cắt (64MB / 20k mục) | [x] | tiêu đề hiện `[TRUNCATED]` |
| 0.7 | Lỗi phát sinh: block menu chỉ điều hướng được 4/8 mục (`% 4`) | [x] | nav theo `BLOCK_MENU_CMDS.len()`; labels chuyển sang `ui::BLOCK_MENU_LABELS` |

## M4.1 — Triage dashboard + CLI JSON

| # | Mục | Trạng thái | Ghi chú |
|---|---|---|---|
| 1.1 | Crate `hiewlm-triage`: dựng `TriageReport` (pure, dùng chung TUI+CLI) | [x] | |
| 1.2 | TUI: phím `2` / `F2` / `T` mở dashboard nhiều pane | [x] | `2` đang trống, khớp Fn-bar |
| 1.3 | CLI `hiewlmc triage <file> [--json] [--fail-on-suspicious]` | [x] | |

## M4.2 — Strings v2 + trích xuất IOC

| # | Mục | Trạng thái | Ghi chú |
|---|---|---|---|
| 2.1 | `core::strings`: ASCII + UTF-16LE, min length, dedupe, phân loại IOC | [x] | URL/domain/IP/registry/path/mutex/GUID/PDB/base64 |
| 2.2 | TUI `s`: engine mới + filter + lọc theo nhóm | [x] | |
| 2.3 | CLI `strings --utf16 --ioc --min N` | [x] | |

## M4.3 — Chấm điểm import + bất thường PE

| # | Mục | Trạng thái | Ghi chú |
|---|---|---|---|
| 3.1 | `core::apiscore`: phân nhóm hành vi API (inject/anti-debug/net/crypto/persist…) | [x] | |
| 3.2 | `fmt`: overlay, TLS callbacks, debug/PDB, security dir (Authenticode), anomalies | [x] | |
| 3.3 | TUI: Imports pane tô màu theo rủi ro + pane Anomalies trong dashboard | [x] | |

## M4.4 — Hash cho clustering + clipboard

| # | Mục | Trạng thái | Ghi chú |
|---|---|---|---|
| 4.1 | SHA-1, ssdeep (spamsum thuần Rust), rich hash, authentihash | [x] | hash từng section: bỏ — entropy từng section đã đủ cho triage |
| 4.2 | Clipboard qua OSC 52 (không cần dependency, chạy được qua SSH) + menu copy `Alt+C` | [x] | hash / hex / C array / python bytes |

## M4.5 — YARA

| # | Mục | Trạng thái | Ghi chú |
|---|---|---|---|
| 5.1 | Tích hợp `yara-x` (thuần Rust) sau feature flag | [x] | phải nâng ratatui 0.29→0.30 vì ratatui ghim `unicode-width =0.2.0` còn yara-x cần ≥0.2.2 |
| 5.2 | TUI `Y`: quét, list match, Enter nhảy, tô sáng | [x] | |
| 5.3 | CLI `hiewlmc yara <file> <rules>` | [x] | |

## M4.6 — XOR lens + xorsearch + chú giải disasm

| # | Mục | Trạng thái | Ghi chú |
|---|---|---|---|
| 6.1 | `core::xorsearch`: brute 1-byte XOR/ADD/ROL + suy key từ known-plaintext | [x] | dùng chữ ký delta bất biến theo khoá: 20s → 0.2s |
| 6.2 | TUI `L`: lens xem-qua-phép-biến-đổi, KHÔNG sửa buffer | [x] | |
| 6.3 | Code mode: chú giải tên API tại call/jmp + preview chuỗi tại toán hạng data | [x] | |

## M4.7 — Mở file / panel thư mục (chất FAR)

| # | Mục | Trạng thái | Ghi chú |
|---|---|---|---|
| 7.1 | `O` mở file khác không cần thoát (`PickPurpose::Open`) | [x] | |
| 7.2 | Nhận tham số là thư mục → danh sách mẫu kèm điểm nghi ngờ | [x] | `hiewlm <dir>` mở hàng đợi; phím `F` bật lại bất cứ lúc nào |
| 7.3 | CLI `hiewlmc triage <dir>` | [x] | xếp hạng worst-first + `--json` |

## M4.8 — UI/UX bổ trợ (gộp các mục P2 của review)

| # | Mục | Trạng thái | Ghi chú |
|---|---|---|---|
| 8.1 | Fn-bar theo ngữ cảnh (Hex/Code/Text khác nhau) | [x] | |
| 8.2 | Command palette `:` (fuzzy, giải bài toán cạn phím) | [x] | |
| 8.3 | Entropy map (pane trong dashboard, jump được) | [x] | |
| 8.4 | Search: case-insensitive, lịch sử pattern, "list all matches" | [x] | |
| 8.5 | Badge rủi ro trên status line | [x] | |

## M4.9 — Hoàn thiện

| # | Mục | Trạng thái | Ghi chú |
|---|---|---|---|
| 9.1 | Cập nhật HELP_TEXT trong app.rs | [x] | |
| 9.2 | Cập nhật README + design doc | [x] | |
| 9.3 | `cargo test` + `cargo clippy` sạch | [x] | 18 test binary xanh; clippy chỉ còn `unwrap_used` trong test (đã cấu hình là warn từ trước) |


---

## Đã hoàn tất toàn bộ M4 (2026-08-30)

Những việc *cố ý* để lại, không phải bỏ quên:

| Hạng mục | Lý do |
|---|---|
| TLSH (bên cạnh ssdeep) | ssdeep đã đủ để gom cụm ở bước phân loại đầu; TLSH thêm phụ thuộc mà không đổi quyết định |
| Hash từng section | entropy từng section đã cho cùng tín hiệu trong pane Sections |
| Đọc bộ nhớ tiến trình trên Windows | cần `unsafe` + crate `windows`, xung đột với `unsafe_code = deny` toàn workspace — phải là quyết định riêng, có audit, sau feature flag |
| HEM shim (nạp DLL native) | vi phạm mô hình an ninh (§22), giữ nguyên trạng thái "deferred" |
| Chuột | cố ý không hỗ trợ — đúng tinh thần HIEW/FAR |

### Mục trong bản review nhưng KHÔNG nằm trong bảng M4.0–M4.9 — Tony đã quyết (2026-08-31)

| Đề xuất trong review | Quyết định | Đã làm |
|---|---|---|
| Gỡ `X` (replace toàn thư mục) khỏi TUI | **Gỡ khỏi TUI, giữ ở CLI** | `X`, `Dialog::Replace`, `multi_file_replace` đã gỡ khỏi TUI; năng lực chuyển sang `hiewlmc replace <dir> --recursive` (bắt buộc cờ, nếu không sẽ từ chối; đệ quy, có `.bak`, giới hạn 5000 file / 64MB mỗi file) |
| Dồn `y`/`p`/`d` vào menu `b` | **Giữ nguyên** | lý do cũ (cạn phím + nguy cơ gõ nhầm) không còn: còn trống `f j l r u` + 10 chữ hoa, có palette `:`, và khoá ghi đã chặn tai nạn |
| Bỏ Rhai hoặc WASM plugin | **Giữ cả hai, không đầu tư thêm** | không đổi |

Phát sinh khi rà lại: phím `m` (mode menu) được ghi trong help/README từ lâu nhưng
**chưa bao giờ được map** — đã sửa, kèm test canh mọi alias chữ được ghi trong help.

---

# M5 — "Không mất công phân tích, không mù nền tảng khác"

Cùng quy tắc theo dõi như M4: đánh `[x]` ngay trong commit hoàn tất mục đó.

| # | Mục | Trạng thái | Ghi chú |
|---|---|---|---|
| 5.1 | Ghi chú bền vững khoá theo nội dung: comment/bookmark/slot/marker lưu theo SHA-256, không theo tên file | [x] | store `$XDG_DATA_HOME/hiewlm/notes/<key>.toml`; tự nhập sidecar `.hiewlm.markers` cũ; file >64MB dùng khoá `part:` (size + 2 đầu) để không phải hash lại mỗi lần mở |
| 5.2 | Bất thường ELF + Mach-O ngang tầm PE | [x] | ELF: segment RWX, mất section header, stack +x, giãn bộ nhớ, entry ngoài LOAD, overlay, loader lạ. Mach-O: RWX/`__TEXT` ghi được, không có LC_CODE_SIGNATURE, cryptid, LC_UNIXTHREAD, dylib/rpath ở đường ghi được, overlay sau chữ ký; đi vào slice đầu của fat binary và re-base offset. Cột perms của Sections giờ lấy từ segment bao ngoài |
| 5.3 | Suy khoá XOR lặp nhiều byte trên block đã chọn | [x] | `Alt+K` trong TUI + `hiewlmc xorkey`. Chấm điểm bằng log-likelihood theo mô hình plaintext (không chỉ "in được") + phạt MDL cho độ dài khoá; khoá recipe được xoay theo offset block để lens khớp |
| 5.4 | Dựng lại stack string (chuỗi ghép bằng `mov`) trong Code mode | [x] | `Alt+S`; `hiewlm-asm` thêm trường `stack_store`; dựng lại cả ASCII lẫn UTF-16 |
| 5.5 | Xuất báo cáo Markdown (CLI `--format markdown`, TUI copy/ghi file) | [x] | `Y` → `m` chép, `w` ghi `<file>.triage.md` cạnh mẫu (ghi được cả khi mẫu đang khoá) |
| 5.6 | Cập nhật help/README/design doc + test + clippy | [x] | 18 test binary xanh, clippy sạch |


---

# M6 — Đóng gói chuẩn, luật phong phú, và định dạng Office

Cùng quy tắc: đánh `[x]` ngay trong commit hoàn tất mục đó.

| # | Mục | Trạng thái | Ghi chú |
|---|---|---|---|
| 6.1 | Tên artifact build theo `os-arch` (`macos-arm64`), bỏ `host` | [x] | suy triple từ `cargo -vV`, khớp nhãn của bản cross-compile |
| 6.2 | Feature-gate dependency nặng (wasmtime, rhai) như đã làm với yara | [x] | `hiewlmc` 15 MB → **8.8 MB**; `--features full` = 29.8 MB. Lệnh vẫn hiện trong `--help`, chạy thì báo cách bật |
| 6.3 | Tách signature/rule ra file dữ liệu riêng + làm giàu (API, packer, LOLBin, IOC) | [x] | `crates/hiewlm-core/data/*.txt`: **359** API (từ ~140), **84** luật packer/protector/installer/runtime, **283** mục từ vựng IOC. Nhúng `include_str!`, override bằng `<config>/hiewlm/rules/*.txt`; xem bằng `hiewlmc rules` |
| 6.4 | Module parse Office (OLE/CFB + OOXML) + mode mới trên TUI | [x] | crate `hiewlm-office`: OLE2/CFB, OOXML (có inflate), RTF, giải nén VBA (MS-OVBA). Mode `Doc` trong TUI (4 pane, Enter nhảy tới offset), `hiewlmc office`, và findings được đưa vào triage |
| 6.5 | Tách `app.rs` (6065 dòng) thành module | [ ] | vấn đề bảo trì thật sự, lớn hơn chuyện dung lượng |
| 6.6 | Popup cuộn được cả ngang lẫn dọc (hiện text dài bị cắt cụt) | [x] | `←→` trong list/message popup, `Shift+←→` trong pane view (vì `←→` đã dùng để đổi pane), `<`/`>` trong Doc mode; mở popup mới thì về lề trái |
| 6.7 | Cập nhật docs + test + clippy | [ ] | |

## Ghi chú về câu hỏi "tách thành .dll"

Số liệu thực đo (2026-08-31): `hiewlm` 24.0 MB *có* YARA, **9.9 MB không có**; `hiewlmc`
29.8 MB / 16 MB. Không có con số "hàng trăm MB" nào cả. Workspace **đã** là 9 crate thư
viện rời — đó chính là cách tổ chức chuẩn của Rust.

Xuất `.dll`/`.dylib` rồi nạp lúc chạy sẽ **vi phạm trụ cột an ninh §22.1** (cấm
`dlopen`/`LoadLibrary`, có test `no_exec` canh) và **không giảm** một byte nào — cùng
lượng mã, chỉ chuyển từ file này sang file khác, lại thêm rủi ro DLL hijacking khi phân
tích mã độc. Thứ giảm dung lượng thật là feature-gate (mục 6.2).
