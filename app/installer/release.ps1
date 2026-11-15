# A release: the installer (build.ps1), its signature and latest.json, in target\release\bundle.
# Upload VibeFTP_<version>_x64-setup.exe and latest.json to the GitHub release tagged with the
# version's release tag (`vibeftp-release tag <version>`: v0.2-preview for 0.2.0-preview, v0.3 for
# 0.3.0, v0.3.1 for 0.3.1); the manifest URL the app checks is .../releases/latest/download/latest.json.
# The key: %USERPROFILE%\.vibeware\release.key (made once with `vibeftp-release keygen`). Its
# password: $env:VIBEWARE_SIGN_PASSWORD, or asked on the console when that is unset.
# Code signing is on by default (X15SIG-2): build.ps1 -Sign (Authenticode on the exe, the
# uninstaller and the installer, sign.ps1 with the Certum certificate), so the update signature
# below covers the signed installer. The updater starts no installer Windows doesn't say is signed
# by PUBLISHER, so an unsigned release could never install itself.
# -NoSign builds unsigned, for a dry run only: it says so loudly, and never upload what it makes.
# -TestSign is refused: a release is never test-signed (build.ps1 -TestSign makes a test build).
param([string]$Notes = "", [string]$Repo = "tedkj/vibeftp", [switch]$NoSign, [switch]$TestSign)
$ErrorActionPreference = "Stop"
if ($TestSign) { throw "-TestSign: a release is never test-signed; build a test-signed installer with build.ps1 -TestSign" }
if ($NoSign) {
    Write-Warning "-NoSign: NOT CODE SIGNED. This release is unsigned: installed copies refuse to update to it. Do not upload it."
}
$root = Resolve-Path "$PSScriptRoot\..\.."
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"

& "$PSScriptRoot\build.ps1" -Sign:(-not $NoSign)
if ($LASTEXITCODE -ne 0) { throw "build failed" }
$version = (Select-String -Path "$root\app\Cargo.toml" -Pattern '^version = "(.+)"' | Select-Object -First 1).Matches[0].Groups[1].Value
$file = "VibeFTP_${version}_x64-setup.exe"

# --locked: the signing tool is built from Cargo.lock as committed, like the exe (IA2).
Push-Location $root
try {
    # The release tag by the tool's one rule (release_tag), which `sign` checks the URL against.
    $tag = cargo run -q --release --locked -p vibeftp-release -- tag $version
    if ($LASTEXITCODE -ne 0 -or -not $tag) { throw "no release tag for $version" }
    cargo run -q --release --locked -p vibeftp-release -- sign "target\release\bundle\$file" --version $version --url "https://github.com/$Repo/releases/download/$tag/$file" --notes $Notes
    if ($LASTEXITCODE -ne 0) { throw "signing failed" }
    # Check what will be uploaded as a client will, with the key the app compiles in (not the
    # signing key's own half): a stale signature or a key mismatch stops the release here.
    $pubkey = (Select-String -Path "$root\app\src\updater.rs" -Pattern '^pub const PUBLIC_KEY: &str = "(.+)";' | Select-Object -First 1).Matches[0].Groups[1].Value
    cargo run -q --release --locked -p vibeftp-release -- verify "target\release\bundle\$file" --pubkey $pubkey
    if ($LASTEXITCODE -ne 0) { throw "the signed release does not verify; do not upload it" }
    if ($NoSign) { Write-Warning "-NoSign: NOT CODE SIGNED. Do not upload this release." }
    "Release tag: $tag"
} finally { Pop-Location }
