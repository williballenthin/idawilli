# Crysis/Dharma Ransomware Analysis

**Sample:** `009c2377b67997b0da1579f4bbc822c1.exe`
**SHA256:** `f58c502a1f26f8e754caa1adb73df3714e54b256383becaedc4166aacad15a57`
**Family:** Crysis/Dharma Ransomware
**Type:** PE32 executable (GUI) Intel 80386

---

## Executive Summary

This sample is **Crysis ransomware**, identified by the embedded PDB path `C:\crysis\Release\PDB\payload.pdb`. The malware uses extensive string obfuscation (RC4 encryption) and dynamic API resolution to evade static analysis. It encrypts files using AES-256 CBC, adds persistence via registry and startup folders, and deletes shadow copies.

---

## Static Strings (Unobfuscated)

These strings are visible in the binary without decryption:

```
GetProcAddress
LoadLibraryA
WaitForSingleObject
InitializeCriticalSectionAndSpinCount
LeaveCriticalSection
GetLastError
EnterCriticalSection
ReleaseMutex
CloseHandle
KERNEL32.dll
C:\crysis\Release\PDB\payload.pdb
0123456789ABCDEF
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
```

---

## Dynamically Resolved APIs (Obfuscated at Rest)

Based on Crysis family analysis, the following APIs are resolved at runtime:

### kernel32.dll
- `GetModuleFileNameW`, `GetModuleHandleW`, `GetProcAddress`, `LoadLibraryW`
- `VirtualAlloc`, `VirtualFree`
- `CreateFileW`, `WriteFile`, `ReadFile`, `CloseHandle`
- `GetFileSize`, `SetFilePointer`, `DeleteFileW`
- `FindFirstFileW`, `FindNextFileW`, `FindClose`
- `GetLogicalDrives`, `GetDriveTypeW`
- `CreateDirectoryW`, `RemoveDirectoryW`
- `GetSystemDirectoryW`, `GetWindowsDirectoryW`, `GetTempPathW`
- `GetComputerNameW`, `GetUserNameW`
- `CreateThread`, `WaitForSingleObject`, `Sleep`, `ExitProcess`
- `GetTickCount`, `GetSystemTimeAsFileTime`, `QueryPerformanceCounter`

### advapi32.dll
- `RegOpenKeyExW`, `RegQueryValueExW`, `RegSetValueExW`, `RegCloseKey`
- `CryptAcquireContextW`, `CryptGenRandom`, `CryptReleaseContext`
- `CryptImportKey`, `CryptDestroyKey`, `CryptEncrypt`, `CryptDecrypt`

### user32.dll
- `GetDesktopWindow`, `SystemParametersInfoW`, `wsprintfW`

### shell32.dll
- `SHGetFolderPathW`, `ShellExecuteW`, `SHGetSpecialFolderPathW`

### crypt32.dll
- `CryptBinaryToStringW`, `CryptStringToBinaryW`

---

## Key Function Map

| Address | Purpose |
|---------|---------|
| `0x40A9D0` | Entry point - initializes decryption |
| `0x4019D0` | RC4 string decryption wrapper |
| `0x4058A0` | RC4 Key Scheduling Algorithm (KSA) |
| `0x405970` | RC4 PRGA (Pseudo-Random Generation Algorithm) |
| `0x4065E0` | Dynamic API resolver (LoadLibraryA/GetProcAddress) |
| `0x4054B0` | Encryption key generation (32 bytes) |
| `0x403AE0` | AES T-table encryption (file encryption) |
| `0x402880` | Main file encryption function |
| `0x409780` | Drive enumeration (A:-Z:) |
| `0x4094E0` | Directory traversal |
| `0x4098E0` | Encryption worker thread |
| `0x409B80` | Ransom note creation |
| `0x40A610` | Persistence (startup folder) |
| `0x407350` | Registry persistence |
| `0x408580` | File extension filtering |

---

## Encryption Details

- **Algorithm:** AES-256 CBC
- **Key/IV Generation:** Unique per-file using timestamp, SHA1, and RC4
- **Partial Encryption:** Files >1MB are partially encrypted (3 chunks of 0x40000 bytes)
- **AES T-tables located at:** `0x40B3B8`, `0x40B7B8`, `0x40BBB8`, `0x40BFB8`

---

## Persistence Mechanisms

### Registry Run Keys
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

### Startup Folders
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
- `%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup`

### Mutex Names (Crysis Family)
- `Global\syncronize_FQBL57A`
- `Global\syncronize_FQBL57U`

---

## Targeted File Extensions

```
.1cd .3ds .3g2 .3gp .7z .accdb .ai .avi .backup .bak .bin .bmp
.cdr .cer .cfg .class .config .cpp .cr2 .crt .cs .css .csv .db
.dbf .dib .djvu .doc .docm .docx .dwg .eps .fdb .flv .gif .h
.htm .html .ibd .ico .iso .jpe .jpeg .jpg .js .key .lnk .max
.mdb .mdf .mkv .mov .mp3 .mp4 .mpeg .mpg .nef .nrg .ods .odt
.ogg .orf .pdf .pem .pfx .php .png .ppt .pptm .pptx .psd .py
.rar .raw .rtf .sql .svg .tar .tif .tiff .txt .vb .vbs .vcf
.vmdk .vmx .wav .wma .wmv .wpd .wps .xls .xlsm .xlsx .xml .zip
```

---

## Encrypted File Extension Pattern

Files are renamed with the pattern:
```
originalname.extension.id-{VICTIM_ID}.[attacker_email].crysis
```
Other variants use `.dharma`, `.wallet`, etc.

---

## Detection Opportunities

### Host-Based Detection

| Indicator Type | Value |
|----------------|-------|
| **PDB Path** | `C:\crysis\Release\PDB\payload.pdb` |
| **SHA256** | `f58c502a1f26f8e754caa1adb73df3714e54b256383becaedc4166aacad15a57` |
| **Minimal Imports** | Only 9 KERNEL32 imports (evasion indicator) |
| **File Pattern** | `*.id-*.[email].*` |

### Behavioral Detection (EDR/SIEM)

1. **Mass file modifications** across directories with extension changes
2. **Registry modifications** to Run keys
3. **Startup folder** modifications
4. **Shadow copy deletion**: `vssadmin delete shadows /all /quiet`
5. **High CPU** from multi-threaded encryption
6. **Drive enumeration** (GetLogicalDrives pattern)

### Network Detection

- Exposed RDP servers are primary attack vector
- Check for brute-force login attempts on port 3389

---

## YARA Rule

```yara
rule Crysis_Ransomware {
    meta:
        description = "Detects Crysis/CrySiS/Dharma ransomware"
        author = "Analysis"
        date = "2024"
        hash = "f58c502a1f26f8e754caa1adb73df3714e54b256383becaedc4166aacad15a57"

    strings:
        $pdb = "crysis" ascii nocase
        $pdb2 = "payload.pdb" ascii
        $b64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ascii
        $hex_alphabet = "0123456789ABCDEF" ascii
        $api1 = "GetProcAddress" ascii
        $api2 = "LoadLibraryA" ascii

        // RC4 KSA pattern (S-box initialization)
        $rc4_init = { 89 ?? 00 01 00 00 }

        // AES T-table XOR pattern
        $aes_ttable = { 8B ?? ?? ?? 40 00 33 }

    condition:
        uint16(0) == 0x5A4D and
        (
            ($pdb and $pdb2) or
            (all of ($api*) and $b64_alphabet and $hex_alphabet) or
            ($rc4_init and $aes_ttable and 2 of ($api*))
        )
}
```

---

## Recommendations

### Prevention
1. **Disable RDP** or restrict to VPN-only access
2. **Enable NLA** (Network Level Authentication) for RDP
3. **Use strong passwords** and account lockout policies
4. **Block execution** from temp/download directories
5. **Maintain offline backups**

### Detection
1. Monitor for mass file renames with victim-ID patterns
2. Alert on shadow copy deletion commands
3. Monitor registry Run key modifications
4. Track startup folder changes

### Response
1. **Isolate** infected hosts immediately
2. **Preserve** encrypted files (decryptors sometimes released)
3. **Check** for lateral movement via RDP
4. **Restore** from offline backups

---

## References

- [Acronis - Dharma Ransomware Analysis](https://www.acronis.com/en/blog/posts/dharma-ransomware/)
- [Fortinet - CrySIS/Dharma Variants](https://www.fortinet.com/blog/threat-research/ransomware-roundup-playing-whack-a-mole-with-new-crysis-dharma-variants)
- [Malwarebytes - CrySIS Threat Spotlight](https://www.malwarebytes.com/blog/news/2019/05/threat-spotlight-crysis-aka-dharma-ransomware-causing-a-crisis-for-businesses)
- [Panda Security - Crysis/Dharma Report (PDF)](https://www.pandasecurity.com/en/mediacenter/src/uploads/2017/11/Ransomware_Crysis-Dharma-en.pdf)
