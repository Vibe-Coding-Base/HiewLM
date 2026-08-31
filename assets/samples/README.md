# Sample binaries

Small, harmless programs used to exercise the format parsers by hand. They are
committed because "open a real Mach-O and check the header view" is a two-second
test that needs no toolchain.

| File | What it is |
|---|---|
| `hello.c` | The source, so the binaries can be rebuilt or checked |
| `hello_x64` | Mach-O, x86-64 |
| `hello_arm64` | Mach-O, arm64 |

Rebuild with:

```sh
cc -arch x86_64 -o hello_x64 hello.c
cc -arch arm64  -o hello_arm64 hello.c
```

There are no malware samples in this repository, and there never will be.
