# lumina_history

Annotate functions with what Lumina knows about them, as a function comment.

Illustrative output (PMA Lab01-01.exe; the `primary` record here was built from local metadata with a hand-edited name):

```
; Lumina: 1 record as of 2026-10-15 13:08Z
;   pattern: md5:ef678deed8c795720da8eada4ce9b0f3 (607 bytes)
;   local:   sub_4011E0  score=1520
;   primary: find_files_recursive  seen=7  score=1520  size=607
;     prototype: int __cdecl(LPCSTR lpFileName, int)
;     frame +0x10: hFindFile HANDLE 4 bytes
;     frame +0x14: FindFileData struct _WIN32_FIND_DATAA 320 bytes
;     frame +0x158: lpFileName LPCSTR 4 bytes
;     unnamed frame members: 1
;     operand representations: 52
;     differs from local:
;       name: sub_4011E0 -> find_files_recursive
; int __cdecl sub_4011E0(LPCSTR lpFileName, int)
sub_4011E0      proc near
```

## usage

Headless (idalib + Domain API):

```
python lumina_history.py <input-or-idb> [--ea 0x4011E0 ...] [--dry-run] [--clear] [--offline-demo]
```

In IDA: `File > Script file...` annotates all functions
(set `LUMINA_HISTORY_EA=1` in the environment to only annotate the function under the cursor).

- `--dry-run` prints the comments instead of saving them.
- `--clear` removes rendered blocks (other comment text is kept).
- `--offline-demo` does not contact Lumina; it renders the locally computed metadata
  as a record labeled `SIMULATED`, which is useful for working on the format.

Function comments are part of the metadata IDA pushes to Lumina, so run `--clear`
before pushing. The script hides its own block when computing the local metadata.

## what's in a record

| item | source |
|------|--------|
| pattern ID (calcrel MD5 + size) | `ida_lumina.calc_function_metadata` |
| local score | `ida_lumina.score_metadata` |
| "applied from Lumina" | `ida_funcs.FUNC_LUMINA` / Domain API `FunctionFlags.LUMINA` |
| pre-Lumina backup present | `ida_lumina.has_backup_metadata` |
| per-server name, size, popularity (`seen=`) | `lumina_client_t.pull_md(eas, PULL_MD_SEEN_FILE)` on primary and secondary servers (`get_server_connection2(LFEAT_*)`) |
| prototype, function/instruction/extra comments, frame members, user stack points, operand representations | `ida_lumina.diff_metadata` of an empty `func_info_t` against the record |
| local → server differences | `ida_lumina.diff_metadata(local, remote)` |

`PULL_MD_SEEN_FILE` is passed so that looking doesn't bump the server's popularity counter.

## no name history available through the Python SDK

Lumina's *history* (previous names, who pushed them, when, from which input file/IDB)
exists in the protocol (`PKT_GET_FUNC_HISTORIES`, used by the GUI action `LuminaMetadataHistory`,
and `PKT_SHOW_HISTORY`, used by `lc hist show`), and `ida_lumina` exports the related `BOPF_*` field flags
(username, license name/email/ID, input hash/path, IDB path, calcrel hash, function EA).
But as of IDA 9.4 the Python bindings only expose `pull_md`, `push_md`, `get_pop` and `del_history`
on `lumina_client_t`, and the Domain API has no Lumina module.
`pull_md` returns the current best record per function.

So the record shows what the server holds now, compared with the local state. It isn't a timeline.
History fields would need a binding for `get_func_histories` (or similar) in `ida_lumina`.
Whether the public `lumina.hex-rays.com` serves history queries at all (vs. only private Lumina servers) is not verified.
