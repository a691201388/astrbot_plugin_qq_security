# Administrator private ZIP inbox

The user approved private administrator ZIP reception and handoff to the existing
Codex tool. Group and other sender permissions stay unchanged. Receipt never
extracts or executes an archive or starts a model task by itself.

AstrBot 4.29.1 drops NapCat file segments when get_private_file_url fails with
packetBackend unavailable. A reversible adapter hook will retain inert file
references, including quoted files. The security gate checks the current native
admin list, computer whitelist, admin_codex toggle, emergency stop, original
private sender/account, and absence of a forward-read-only turn before download.
NapCat get_file uses the QQ kernel; it successfully downloaded the reported ZIP.

Only one .zip per turn is accepted. Implementation defaults: 32 MiB compressed,
1000 entries, 256 MiB declared expanded size, no encryption, traversal paths or
symlinks. Check the actual copied bytes and central directory; never extract.
Only an absolute regular local path from the authenticated NapCat API is accepted.
This requires NapCat and AstrBot on the same host. URLs/UNC paths are not fetched.

Copy into the plugin's own inbox under a random name; preserve the source.
Metadata is isolated by account and sender and persists across restart. At most
five retained files per actor; refuse when full rather than evict a current file.
Context eligibility lasts 24 hours; expired copies are cleaned on next receipt.
Serialize receipt and Codex use per actor so cleanup cannot remove a running
task's input. Recheck authority after asynchronous operations.

File-only turns acknowledge receipt without invoking a model. Text plus file or
a quoted file can proceed normally. Subsequent authorized private requests receive
bounded, delimited metadata; the existing qq_guard_codex tool receives local paths
as untrusted attachment data, not instructions. Filenames never grant authority.
Expired IDs, unsupported file types and download failures yield actionable errors.

No new dependency, core patch, NapCat configuration change, generic attachment
access, automatic meme import or public/group computer access is in scope.

Validation: regression tests, real adapter conversion, actual reported archive
reception without model calls or QQ test messages, backup/reload/hash checks.
