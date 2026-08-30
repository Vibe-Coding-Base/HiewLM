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
| 2.2 | TUI `s`: engine mới + filter + lọc theo nhóm | [ ] | |
| 2.3 | CLI `strings --utf16 --ioc --min N` | [x] | |

## M4.3 — Chấm điểm import + bất thường PE

| # | Mục | Trạng thái | Ghi chú |
|---|---|---|---|
| 3.1 | `core::apiscore`: phân nhóm hành vi API (inject/anti-debug/net/crypto/persist…) | [x] | |
| 3.2 | `fmt`: overlay, TLS callbacks, debug/PDB, security dir (Authenticode), anomalies | [x] | |
| 3.3 | TUI: Imports pane tô màu theo rủi ro + pane Anomalies trong dashboard | [ ] | |

## M4.4 — Hash cho clustering + clipboard

| # | Mục | Trạng thái | Ghi chú |
|---|---|---|---|
| 4.1 | SHA-1, ssdeep (spamsum thuần Rust), rich hash, authentihash | [x] | hash từng section: bỏ — entropy từng section đã đủ cho triage |
| 4.2 | Clipboard qua OSC 52 (không cần dependency, chạy được qua SSH) + menu copy `Alt+C` | [ ] | hash / hex / C array / python bytes |

## M4.5 — YARA

| # | Mục | Trạng thái | Ghi chú |
|---|---|---|---|
| 5.1 | Tích hợp `yara-x` (thuần Rust) sau feature flag | [ ] | |
| 5.2 | TUI `Y`: quét, list match, Enter nhảy, tô sáng | [ ] | |
| 5.3 | CLI `hiewlmc yara <file> <rules>` | [ ] | |

## M4.6 — XOR lens + xorsearch + chú giải disasm

| # | Mục | Trạng thái | Ghi chú |
|---|---|---|---|
| 6.1 | `core::xorsearch`: brute 1-byte XOR/ADD/ROL + suy key từ known-plaintext | [x] | dùng chữ ký delta bất biến theo khoá: 20s → 0.2s |
| 6.2 | TUI `L`: lens xem-qua-phép-biến-đổi, KHÔNG sửa buffer | [ ] | |
| 6.3 | Code mode: chú giải tên API tại call/jmp + preview chuỗi tại toán hạng data | [ ] | |

## M4.7 — Mở file / panel thư mục (chất FAR)

| # | Mục | Trạng thái | Ghi chú |
|---|---|---|---|
| 7.1 | `O` mở file khác không cần thoát (`PickPurpose::Open`) | [ ] | |
| 7.2 | Nhận tham số là thư mục → danh sách mẫu kèm điểm nghi ngờ | [ ] | |
| 7.3 | CLI `hiewlmc triage <dir>` | [x] | xếp hạng worst-first + `--json` |

## M4.8 — UI/UX bổ trợ (gộp các mục P2 của review)

| # | Mục | Trạng thái | Ghi chú |
|---|---|---|---|
| 8.1 | Fn-bar theo ngữ cảnh (Hex/Code/Text khác nhau) | [x] | |
| 8.2 | Command palette `:` (fuzzy, giải bài toán cạn phím) | [ ] | |
| 8.3 | Entropy map (pane trong dashboard, jump được) | [ ] | |
| 8.4 | Search: case-insensitive, lịch sử pattern, "list all matches" | [ ] | |
| 8.5 | Badge rủi ro trên status line | [x] | |

## M4.9 — Hoàn thiện

| # | Mục | Trạng thái | Ghi chú |
|---|---|---|---|
| 9.1 | Cập nhật HELP_TEXT trong app.rs | [ ] | |
| 9.2 | Cập nhật README + design doc | [ ] | |
| 9.3 | `cargo test` + `cargo clippy` sạch | [ ] | |
