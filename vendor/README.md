# Vendored crates: the check list

A crate patched in through `[patch.crates-io]` has no registry source in `Cargo.lock`, so
`cargo audit`, `cargo deny` and the family's supply audit (which counts the "from crates.io"
packages) no longer see it: a RustSec advisory for it would not be reported for VibeFTP
(RINF-4, review of the input round, 2026-10-28). So, by hand:

| Crate | Tracks upstream | Why it is here |
|---|---|---|
| `i-slint-core` | 1.18.1 (crates.io), two hunks | the text repaint fix (below) |
| `russh-sftp` | 3.0.1 (crates.io), one accessor | bounded folder listings (below) |

- **Every family supply audit and every dependency bump:** look each name up in the RustSec
  advisory database (`https://rustsec.org/packages/<name>.html`, or `crates/<name>/` in a
  checkout of `rustsec/advisory-db`) and check the affected versions against the one tracked
  here. An advisory that covers it means: move the vendored copy to the fixed release and carry
  the patch over, or drop the patch if upstream has it.
- **Every Slint bump** (the masked password `Field`, SEC-FTP-1, RINF-9): read
  `InternalKeyEvent::shortcut()` in the new `i-slint-core` (`input.rs`): the `Field` drops
  Ctrl+C, Ctrl+X and Ctrl+Insert; if Slint now maps the Windows-classic Ctrl+Insert or
  Shift+Delete to Copy or Cut, the `Field` must drop that key too. Read the `TextInput` mouse
  paths (`items/text.rs`) as well: selecting copies to the selection clipboard, which on Windows
  writes nothing (`SilentClipboardContext`), and 1.18 has no context menu or drag-out. A new
  copy route, or a Linux build (primary selection), needs the masked field to stay out of it.
- **Comparing with the published crate:** `.gitattributes` turns line-ending conversion off under
  `vendor/` (RINF-5), so the files are the `.crate`'s bytes in the repo and in any clone: a hash
  of each file against the `.crate` (`~/.cargo/registry/cache/.../<name>-<version>.crate`, a
  `.tar.gz`) differs only in the files the patches name.

# vendor/i-slint-core-1.18.1

Slint's `i-slint-core` 1.18.1, unchanged except for one bug fix, used through `[patch.crates-io]`
in Cargo.toml. Remove it (and the patch entry) once Slint ships the fix upstream.

## The bug

A Text that is not drawn for two frames can lose its repaints for good. The software renderer
shapes text through a per-item text layout cache whose entries carry their own dependency
tracker; the item's partial-rendering tracker depends on the text only *through* that entry.
When the cache sweeps (after more than 1024 misses, which a window with changing rows reaches
within seconds), it drops the entries not used in the last two frames, trackers included, and
nothing tells the item. From then on its text changes mark nothing dirty: the status line stays
on "round 4" while the property says "round 75" (seen live in VibeTrace, 2026-10-19; VibeFTP runs the same renderer and fails app/tests/repaint.rs without it).

## The fix (two hunks, marked "VibeWare patch")

- `properties.rs`: `PropertyTracker::mark_dependents_dirty()`, crate-private.
- `item_rendering.rs`: `ItemCache::retain` and `ItemCache::release` mark the dependents of every
  tracker they drop dirty, so the item is drawn once more and registers on a fresh entry.

A headless test (the real software renderer with a reused buffer) reproduces it and fails without
the patch. Upstream (slint-ui/slint master, checked 2026-10-19) still has the bug; the issue is not
filed yet.

# vendor/russh-sftp-3.0.1

russh-sftp 3.0.1 as published (the crates.io source, without its dotfiles), used through
`[patch.crates-io]` in Cargo.toml, with one addition marked "VibeWare patch":
`SftpSession::raw()` in `src/client/session.rs`, which hands out the `RawSftpSession` the
session already holds. Nothing else is changed: every other file is byte for byte the 3.0.1
`.crate`'s (checked 2026-10-28 against the registry cache, whose checksum is the one the old
`Cargo.lock` carried).

## Why

`SftpSession::read_dir` reads a folder until the server sends EOF: no limit on entries or
batches, every batch re-collects all entries before it (quadratic), and `ReadDir::next` calls
itself once per `.`/`..` it skips. A hostile server that never sends EOF grows memory and CPU
without end (IN-VibeFTP-2, input-safety audit 2026-10-28). VibeFTP reads folders with its own
OPENDIR/READDIR loop on the raw session instead (`core/src/protocol/sftp.rs`, `read_folder`):
bounded entries, bytes and name length, an overall deadline, and `.`/`..` dropped in the loop.
The raw session is private in 3.0.1 and opening a second SFTP channel for listings would fail on
servers that allow one channel per connection, hence the accessor.

Remove it (and the patch entry) once russh-sftp exposes the raw session or bounds `read_dir`.
An upstream pull request for either is worth filing (not filed: nothing of VibeFTP is public yet).
