//! Sandboxed WASM plugin host (wasmtime). A plugin is a `.wasm`/`.wat` module
//! that exports `run()` and reaches the file only through the host imports below
//! — no filesystem, network, or syscalls. Execution is fuel-bounded.
//!
//! Host ABI (module `"host"`):
//! - `len() -> i64`                      length of the buffer
//! - `read(off: i64) -> i32`             byte at off, or -1 out of range
//! - `write(off: i64, val: i32)`         set a byte (marks the buffer modified)
//! - `find(ptr: i32, len: i32) -> i64`   find bytes (from wasm memory), or -1
//! - `log(ptr: i32, len: i32)`           append a UTF-8 message from wasm memory
//!
//! The plugin must export its linear memory as `"memory"` for `find`/`log`.

use anyhow::{Context, Result};
use wasmtime::{Caller, Config, Engine, Linker, Module, Store};

/// Result of running a plugin.
#[derive(Debug)]
pub struct Outcome {
    pub data: Vec<u8>,
    pub log: Vec<String>,
    pub modified: bool,
}

struct HostState {
    data: Vec<u8>,
    log: Vec<String>,
    modified: bool,
}

fn wasm_mem(caller: &mut Caller<'_, HostState>, ptr: i32, len: i32) -> Option<Vec<u8>> {
    let mem = caller.get_export("memory")?.into_memory()?;
    let mut buf = vec![0u8; len.max(0) as usize];
    mem.read(&*caller, ptr as usize, &mut buf).ok()?;
    Some(buf)
}

/// Run `module` (wasm binary or `.wat` text) against `data`, returning the
/// possibly-modified bytes and any log lines. Fuel-bounded to stay safe on
/// hostile modules.
pub fn run(module: &[u8], data: Vec<u8>) -> Result<Outcome> {
    let mut config = Config::new();
    config.consume_fuel(true);
    let engine = Engine::new(&config).context("wasmtime engine")?;
    let module = Module::new(&engine, module).context("compile plugin module")?;

    let mut store = Store::new(&engine, HostState { data, log: Vec::new(), modified: false });
    store.set_fuel(2_000_000_000).ok();

    let mut linker: Linker<HostState> = Linker::new(&engine);
    linker.func_wrap("host", "len", |caller: Caller<'_, HostState>| caller.data().data.len() as i64)?;
    linker.func_wrap("host", "read", |caller: Caller<'_, HostState>, off: i64| {
        caller.data().data.get(off as usize).map(|&b| b as i32).unwrap_or(-1)
    })?;
    linker.func_wrap("host", "write", |mut caller: Caller<'_, HostState>, off: i64, val: i32| {
        let st = caller.data_mut();
        if let Some(x) = st.data.get_mut(off as usize) {
            *x = val as u8;
            st.modified = true;
        }
    })?;
    linker.func_wrap("host", "find", |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| -> i64 {
        let Some(needle) = wasm_mem(&mut caller, ptr, len) else { return -1 };
        let data = &caller.data().data;
        if needle.is_empty() || data.len() < needle.len() {
            return -1;
        }
        (0..=data.len() - needle.len())
            .find(|&i| &data[i..i + needle.len()] == needle.as_slice())
            .map(|i| i as i64)
            .unwrap_or(-1)
    })?;
    linker.func_wrap("host", "log", |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| {
        if let Some(bytes) = wasm_mem(&mut caller, ptr, len) {
            caller.data_mut().log.push(String::from_utf8_lossy(&bytes).into_owned());
        }
    })?;

    let instance = linker.instantiate(&mut store, &module).context("instantiate plugin")?;
    let run = instance
        .get_typed_func::<(), ()>(&mut store, "run")
        .context("plugin must export `run()`")?;
    run.call(&mut store, ()).context("plugin trapped")?;

    let st = store.into_data();
    Ok(Outcome { data: st.data, log: st.log, modified: st.modified })
}

#[cfg(test)]
mod tests {
    use super::*;

    // A plugin that logs, finds "BB", and overwrites the byte there with 'C'.
    const PLUGIN: &str = r#"
        (module
          (import "host" "len"   (func $len (result i64)))
          (import "host" "read"  (func $read (param i64) (result i32)))
          (import "host" "write" (func $write (param i64 i32)))
          (import "host" "find"  (func $find (param i32 i32) (result i64)))
          (import "host" "log"   (func $log (param i32 i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "BB")       ;; needle at ptr 0, len 2
          (data (i32.const 8) "hello")    ;; message at ptr 8, len 5
          (func (export "run")
            (local $at i64)
            (call $log (i32.const 8) (i32.const 5))
            (local.set $at (call $find (i32.const 0) (i32.const 2)))
            (if (i64.ge_s (local.get $at) (i64.const 0))
              (then (call $write (local.get $at) (i32.const 67))))  ;; 'C'
          )
        )
    "#;

    #[test]
    fn plugin_reads_writes_and_logs() {
        let out = run(PLUGIN.as_bytes(), b"AABBCC".to_vec()).unwrap();
        assert!(out.modified);
        assert_eq!(out.data, b"AACBCC"); // 'B' at offset 2 → 'C'
        assert_eq!(out.log, vec!["hello".to_string()]);
    }

    #[test]
    fn missing_run_export_errors() {
        assert!(run(b"(module)", b"x".to_vec()).is_err());
    }
}
