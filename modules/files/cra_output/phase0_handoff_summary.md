# HAND-OFF SUMMARY
# stack_bof — Executive Brief for Phases 1–4
────────────────────────────────────────────────────────────────────────

## Binary Identity

```
File         : /home/rave/opt/proj/jop/modules/vuln-code/stack_bof
BuildID      : b987780847f7b641a6082dfa27e3a110ae562418
Architecture : x86-64 (64-bit)
PIE          : OFF — fixed base 0x400000
Symbols      : present (not stripped)
```

## Security State

```
Mitigation         State      Impact
────────────────────────────────────────────────────────────────────────
PIE                OFF        Addresses fixed
Stack Canary       ABSENT     Overflow undetected
NX / DEP           ENABLED    Non-executable stack
RELRO              NONE       GOT writable runtime
```

## TOP 3 CRITICAL VULNERABILITIES

### 1. [MEDIUM] WRITABLE_GOT  —  `.got.plt` @ `0x00402fe8`

```
Function : [binary-wide]()
CWE      : CWE-119
Buf size : 56 bytes
Channel  : any
```

> Partial RELRO: .got.plt at 0x402fe8 is writable at runtime; arbitrary write → GOT overwrite → code exec

## KEY ADDRESSES (all static — PIE=OFF)

```
Symbol                         Address        Notes
────────────────────────────────────────────────────────────────────────
  deregister_tm_clones         0x004003f0
  register_tm_clones           0x00400420
  __do_global_dtors_aux        0x00400460
  frame_dummy                  0x00400490
  vuln                         0x004004b1
  _fini                        0x0040051c
  secret                       0x00400496
  _dl_relocate_static_pie      0x004003e0
  _start                       0x004003b0
  main                         0x004004ed
  _init                        0x0040033c
  gets@plt                     (PLT stub — see disassembly)
  printf@plt                   (PLT stub — see disassembly)
  system@plt                   (PLT stub — see disassembly)
```

## RECOMMENDED EXPLOITATION ORDER

```
Path                   Difficulty   Prerequisites                  Payload
────────────────────────────────────────────────────────────────────────
GOT overwrite          MEDIUM       Arbitrary write + ROP          Write to .got.plt
```

## PHASE 0 ROOT CAUSE FIX

```bash
# If Phase 0 returned zero findings:
# Auto-detected input mode: arg
./phase0_vuln_detection.sh -b stack_bof -i arg
# Static analysis always runs regardless of fuzzer results.
```

## QUICK VALIDATION

```bash
```
