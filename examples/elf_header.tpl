# ELF64 header — apply with `t` at file offset 0 of a 64-bit ELF.
#
# Syntax: <name> <type> [enum { v=NAME ... }] [= expected]
#   types: u8/u16/u32/u64, i8..i64, f32/f64 (optional le/be suffix),
#          char[N], bytes[N], TYPE[N] arrays.  N is a literal or the
#          name of an earlier integer field.
#   `meta endian be|le` sets the file-level byte order (le by default).

magic       u32 = 0x464C457F        # "\x7FELF" read little-endian
class       u8  enum { 1=ELF32 2=ELF64 }
data        u8  enum { 1=little 2=big }
version     u8  = 1
osabi       u8  enum { 0=SysV 3=Linux 9=FreeBSD }
abiversion  u8
pad         bytes[7]
type        u16 enum { 1=REL 2=EXEC 3=DYN 4=CORE }
machine     u16 enum { 3=x86 40=ARM 62=x86-64 183=AArch64 243=RISC-V }
e_version   u32
entry       u64
phoff       u64
shoff       u64
flags       u32
ehsize      u16
phentsize   u16
phnum       u16
shentsize   u16
shnum       u16
shstrndx    u16
