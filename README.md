# VibeFTP

An FTP, FTPS and SFTP client for Windows that stays small and out of your way.

Two panes, this computer and the server, with a transfer queue between them. Saved sites keep
their passwords in Windows Credential Manager, never in a file. Server host keys and certificates
are pinned the first time you trust them, so a changed one stops the connection and asks you
again. Open a remote file in your own editor and VibeFTP sends your saves back. It is written in
Rust with a native Slint interface, with no browser engine inside, and uses about 9 MB of memory
when idle.

## What is in this repository

| Folder | What it is |
|--------|-----------|
| `core/` | The engine: FTP, FTPS and SFTP, connection pools, transfers, edit copies, sites and pins. No interface. |
| `app/` | The Windows app: the Slint interface (`ui/`, the VibeWare design system in `ui/vibeware/`), the updater and the installer (`installer/`). |
| `tools/release/` | The release tool: makes the release key and signs each installer and its update manifest. Never shipped. |
| `vendor/` | Two crates with one small patch each: Slint's `i-slint-core` 1.18.1 (a repaint fix) and `russh-sftp` 3.0.1 (one accessor). `vendor/README.md` says what changed and why. |

## What it connects to

Only the servers you connect to, GitHub to look for updates (a few seconds after each start,
which you can turn off in the menu, or when you ask) and getvibeware.com when you press About's
"Check this install". Updates are signed with the VibeWare release key, and the app checks the
signature before anything is installed. To check the installer's code signature during an update,
Windows itself may fetch certificates from Windows Update and Certum (who issued the certificate).

## Download

Get the installer from [Releases](https://github.com/tedkj/vibeftp/releases). It installs for your
user only, without admin rights. The installer, VibeFTP.exe and its uninstaller are code signed by
"Open Source Developer Ted Kenneth Johansen" (right-click › Properties › Digital Signatures). The
certificate is new, so Windows SmartScreen may still warn before it runs. You can also compare the
installer's SHA-256 with the one in `SHA256SUMS.txt` on the release page:

```powershell
Get-FileHash .\VibeFTP_0.2.2-preview_x64-setup.exe
```

The app looks for full releases only, so a preview doesn't update itself to the next preview: get
that one from Releases.

## Building from source

You need a current Rust toolchain on Windows (the MSVC target) and NASM, which assembles the
crypto code (aws-lc).

```sh
cargo build --release -p vibeftp-app --bin vibeftp-native
```

The app is then at `target\release\vibeftp-native.exe`. `cargo run -p vibeftp-app --bin kitchen`
shows the design system's kitchen sink.

### Building the installer

`app\installer\build.ps1` builds the app and its installer,
`target\release\bundle\VibeFTP_<version>_x64-setup.exe`. It needs the official NSIS 3.13:
download `nsis-3.13.zip` from SourceForge (SHA-256
`ba63dffc4410ee89193e1cb5a41989991bd77c61068da17e3156d136b7b0b3d8`) and unpack it to
`_tools\nsis-3.13` in the folder that holds this repository. The script checks that whole folder
against a pinned hash before it runs anything from it. It also needs the official NASM 3.02:
`nasm.exe` and `LICENSE` from nasm.us's Windows x64 build, in `_tools\nasm-3.02` beside NSIS's
folder. That folder is pinned the same way, and the script puts it first on PATH for the build.
`app\installer\notices.ps1` writes `THIRD-PARTY-NOTICES.txt` for each build (every crate the app
links, with its licence text), and the installer puts it and `LICENSE` next to the app.

## License

[AGPL-3.0](LICENSE). Use it, change it, share it. If you hand out a changed version, or run one as
a service for other people, you share your changes under the same license. Slint is used under
its GPLv3 option.

Made in Norway by Ted K. Johansen.
