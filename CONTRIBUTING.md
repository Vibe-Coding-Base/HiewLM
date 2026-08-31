# Contributing

Thanks for looking. hiewLM is a tool for people who analyse hostile files, and
that shapes what a good contribution looks like.

## The quick paths

**Adding a detection rule needs no Rust.** Packer signatures, API behaviours,
string indicators and document markers are text files in
`crates/hiewlm-core/data/`. One line, one pull request. See
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md#adding-things) for the formats.

**Reporting a false positive is as valuable as adding a rule.** Include the file
type and what hiewLM said; a rule that fires on ordinary software costs more than
a missing rule does.

## Before you open a pull request

```sh
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt --all
```

CI runs the same on Linux, macOS and Windows, plus a build with the optional
features and the `no_exec` security guard.

## What the review will ask

- **Does it keep the target file passive?** No code path may load or execute
  content from the file being analysed. The `no_exec` test enforces the letter of
  this; the spirit matters too — do not fetch a URL a document mentions, do not
  run a macro, do not shell out.
- **Is the parser bounded?** Hostile input is the normal case here. Cycles, sizes
  past EOF, absurd counts and decompression ratios all need a limit and a test.
- **Does a new signal earn its noise?** A finding that fires on ordinary software
  makes the tool less useful, not more. If a signal is common in benign files,
  mark it weak so it informs without shouting.
- **Does the test say what actually holds?** Where a technique is statistical,
  assert the guarantee that survives rather than tuning the fixture until it
  passes.
- **Does it stay HIEW-shaped?** The keymap follows HIEW. Deviating is allowed;
  doing it silently is not.

## Commit messages

Explain what changed and why the change is right, not just what file moved. If
you fixed a false positive, say what tripped it — that is the part a future
maintainer needs.

## License

By contributing you agree that your work is licensed under MIT or Apache-2.0, at
the user's option, matching the rest of the project.
