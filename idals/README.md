# idals

idals is an IDA Pro-powered command-line tool for binary inspection.

## requirements

- IDA Pro installation
- a usable idapro runtime setup (for example via IDADIR)

## installation

From PyPI:

```bash
pip install idals
```

With uvx.sh:

```bash
curl -LsSf uvx.sh/idals/install.sh | sh
```

Windows:

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://uvx.sh/idals/install.ps1 | iex"
```

Install a pinned version:

```bash
curl -LsSf uvx.sh/idals/0.1.0.dev0/install.sh | sh
```

## usage

```bash
idals --help
idals <file>
idals <file> <address>
```

## examples

Binary overview:

```
$ idals malware.exe
--- Overview: malware.exe ------------------------------------------------
File: malware.exe
Architecture: metapc (32-bit)
Image base: 0x400000
Entry point: start@0x401820
Functions: 14 total, 9 named
MD5: ...
SHA256: ...
--- Entry points --------------------------------------------------------
0x401820  start@0x401820 (OEP)
--- Imports -------------------------------------------------------------
[KERNEL32]
CloseHandle@0x402000
CreateFileA@0x402014
...
--- Tips ---------------------------------------------------------------
• This binary imports CloseHandle@0x402000 - view cross references to it.
```

Function view with xrefs:

```
$ idals malware.exe _main --after=4
    ; XREF: 0x4018FE (in start@0x401820)
      0x401440 mov     eax, [esp+argc]  ; <-- target
      0x401444 sub     esp, 44h
      0x401447 cmp     eax, 2
      0x40144A push    ebx
```

Data/import view with xrefs before the item:

```
$ idals malware.exe CreateFileA --after=1
               ; XREF: 0x4014AC (in _main@0x401440)
               ; XREF: 0x4014F0 (in _main@0x401440)
      0x402014 extrn CreateFileA:dword  ; <-- target
```

Symbol suggestions use `name@0xADDRESS`:

```
$ idals malware.exe CreateFlie
Error: Symbol "CreateFlie" not found.
Did you mean:
  CreateFileA@0x402014
  CreateFileMappingA@0x402010
```
