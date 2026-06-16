# [PHASE 0 OUTPUT]
# Binary Security Analysis — Disassembly & Initial Pattern Detection

```
Binary    : /home/rave/opt/proj/jop/modules/vuln-code/stack_bof
BuildID   : b987780847f7b641a6082dfa27e3a110ae562418
Format    : /home/rave/opt/proj/jop/modules/vuln-code/stack_bof: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically li
Type      : ELF
Architecture : x86-64 (64-bit)
Stripped  : False
Compiler  : detected via .comment / annobin
```

---

## SECURITY PROPERTIES

```
Mitigation       State     Detail
────────────────────────────────────────────────────────────────────────
PIE              OFF       Fixed base 0x400000
Stack Canary     ABSENT    Overflow is silent — no abort()
NX / DEP         ENABLED   Non-executable stack
RELRO            NONE      No GOT protection
ASLR             Level 2   Affects libs/stack only (no PIE)
```

---

## SECTIONS

```
Section              Address        Size (bytes)  Flags
────────────────────────────────────────────────────────────────────────
.note.gnu.build-id   0x400318                 36  A
.init                0x40033c                 27  AX
.plt                 0x400360                 80  AX
.text                0x4003b0                363  AX
.fini                0x40051c                 13  AX
.interp              0x401000                 28  A
.gnu.hash            0x401020                 28  A
.dynsym              0x401040                168  A
.dynstr              0x4010e8                 91  A
.gnu.version         0x401144                 14  A
.gnu.version_r       0x401158                 48  A
.rela.dyn            0x401188                 48  A
.rela.plt            0x4011b8                 96  AI
.rodata              0x401218                122  A
.eh_frame_hdr        0x401294                 60  A
.eh_frame            0x4012d0                204  A
.note.gnu.property   0x4013a0                 64  A
.note.ABI-tag        0x4013e0                 32  A
.init_array          0x402df8                  8  WA
.fini_array          0x402e00                  8  WA
.dynamic             0x402e08                464  WA
.got                 0x402fd8                 16  WA
.got.plt             0x402fe8                 56  WA
.data                0x403020                  4  WA
.bss                 0x403024                  4  WA
.comment             0x0                      46  MS
.annobin.notes       0x0                     335  MS
.gnu.build.attributes 0x405028                324  0
.symtab              0x0                     936  30
.strtab              0x0                     497  0
.shstrtab            0x0                     315  0
```

---

## FUNCTIONS IDENTIFIED: 16

### `_init` @ 0x0040033c  (size: 0 bytes)

- **Stack frame size**: 8 bytes
- **Registers used**: `rax`, `rsp`
- **Calls**: none

### `puts@plt-0x10` @ 0x????????  (size: 0 bytes)

- **Stack frame size**: 0 bytes
- **Registers used**: `rax`
- **Calls**: none

### `puts@plt` @ 0x????????  (size: 0 bytes)

- **Stack frame size**: 0 bytes
- **Registers used**: `n/a`
- **Calls**: none

### `system@plt` @ 0x????????  (size: 0 bytes)

- **Stack frame size**: 0 bytes
- **Registers used**: `n/a`
- **Calls**: none

### `printf@plt` @ 0x????????  (size: 0 bytes)

- **Stack frame size**: 0 bytes
- **Registers used**: `n/a`
- **Calls**: none

### `gets@plt` @ 0x????????  (size: 0 bytes)

- **Stack frame size**: 0 bytes
- **Registers used**: `n/a`
- **Calls**: none

### `_start` @ 0x004003b0  (size: 38 bytes)

- **Stack frame size**: 0 bytes
- **Registers used**: `ebp`, `ecx`, `r9`, `rax`, `rdi`, `rdx`, `rsi`, `rsp`
- **Calls**: none

### `_dl_relocate_static_pie` @ 0x004003e0  (size: 5 bytes)

- **Stack frame size**: 0 bytes
- **Registers used**: `rax`
- **Calls**: none

### `deregister_tm_clones` @ 0x004003f0  (size: 0 bytes)

- **Stack frame size**: 0 bytes
- **Registers used**: `eax`, `edi`, `rax`
- **Calls**: none

### `register_tm_clones` @ 0x00400420  (size: 0 bytes)

- **Stack frame size**: 0 bytes
- **Registers used**: `eax`, `edi`, `esi`, `rax`, `rsi`
- **Calls**: none

### `__do_global_dtors_aux` @ 0x00400460  (size: 0 bytes)

- **Stack frame size**: 0 bytes
- **Registers used**: `rax`, `rbp`, `rsp`
- **Calls**: none

### `frame_dummy` @ 0x00400490  (size: 0 bytes)

- **Stack frame size**: 0 bytes
- **Registers used**: `n/a`
- **Calls**: none

### `secret` @ 0x00400496  (size: 27 bytes)

- **Stack frame size**: 0 bytes
- **Registers used**: `edi`, `rbp`, `rsp`
- **Calls**: none

### `vuln` @ 0x004004b1  (size: 60 bytes)

- **Stack frame size**: 64 bytes
- **Registers used**: `eax`, `edi`, `rax`, `rbp`, `rdi`, `rsi`, `rsp`
- **Calls**: none

### `main` @ 0x004004ed  (size: 46 bytes)

- **Stack frame size**: 0 bytes
- **Registers used**: `eax`, `edi`, `esi`, `rbp`, `rsp`
- **Calls**: none

### `_fini` @ 0x0040051c  (size: 0 bytes)

- **Stack frame size**: 8 bytes
- **Registers used**: `rsp`
- **Calls**: none

---

## SUSPICIOUS PATTERNS DETECTED

1. `0x00402fe8` — **.got.plt** in `[binary-wide]`  [MEDIUM] WRITABLE_GOT
   > Partial RELRO: .got.plt at 0x402fe8 is writable at runtime; arbitrary write → GOT overwrite → code exec

---

## DYNAMIC IMPORT RISK MATRIX

```
Import         Risk       Notes
────────────────────────────────────────────────────────────────────────
gets           CRITICAL   gets() performs unbounded stdin read; no length param; 
printf         HIGH       printf(user_str) — if first arg is user-controlled, arb
system         HIGH       system() passes argument to /bin/sh -c; user input = RC
```
