# Signs one file for a release (code signing is not set up yet: previews ship unsigned).
# build.ps1 -Sign runs it on the bundled exe; makensis runs it (app.nsi's !uninstfinalize and
# !finalize) on the uninstaller before it is packed and on the finished installer.
#   sign.ps1 -Config <sign.json> -File <file> [-Keep <path>]
# -Keep: a copy of the signed file there (the uninstaller, for build.ps1's check).
# Exit 0 once the file carries a signature, 1 (with the reason on stderr) when it does not.
#
# The config lives outside every repo (%USERPROFILE%\.vibeware\sign.json) and holds paths, no secret:
#   signtool   signtool.exe (Windows SDK 10.0.22621.755 or newer)
#   dlib       Azure.CodeSigning.Dlib.dll (Microsoft Artifact Signing client tools)
#   metadata   the metadata.json that names the Artifact Signing account and certificate profile
#   timestamp  the RFC 3161 timestamp server; left out: http://timestamp.acs.microsoft.com
#   testPfx    tests only, in place of dlib and metadata: a throwaway self-signed PFX without a
#              password; only with it may timestamp be "" (no timestamp, no network)
# Digests are SHA-256 (file and timestamp). Windows PowerShell 5.1.
param(
    [Parameter(Mandatory = $true)][string]$Config,
    [Parameter(Mandatory = $true)][string]$File,
    [string]$Keep = ""
)
$ErrorActionPreference = "Stop"
# Always its own Windows PowerShell process (build.ps1 and makensis start it by its full path).
# Started from PowerShell 7 by anything but PowerShell 7 itself (makensis under a pwsh build.ps1),
# it inherits pwsh's PSModulePath, whose modules it can't load (no signature or JSON cmdlets):
# the built-in ones only.
$env:PSModulePath = "$PSHOME\Modules"

function Fail([string]$why) {
    [Console]::Error.WriteLine("sign.ps1: $why")
    exit 1
}

function Field($cfg, [string]$name) {
    $p = $cfg.PSObject.Properties[$name]
    if ($p) { return $p.Value }
    return $null
}

function ExistingFile($cfg, [string]$name) {
    $v = Field $cfg $name
    if (-not ($v -is [string]) -or $v -eq "") { Fail "$Config has no `"$name`"" }
    if (-not (Test-Path -LiteralPath $v -PathType Leaf)) { Fail "$Config's `"$name`" is not a file: $v" }
    return $v
}

try {
    if (-not (Test-Path -LiteralPath $Config -PathType Leaf)) { Fail "no signing config at $Config" }
    if (-not (Test-Path -LiteralPath $File -PathType Leaf)) { Fail "no file to sign at $File" }
    $cfg = Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json

    $signtool = ExistingFile $cfg "signtool"
    $test = $null -ne (Field $cfg "testPfx")
    if ($test -and ($null -ne (Field $cfg "dlib") -or $null -ne (Field $cfg "metadata"))) {
        Fail "$Config has testPfx and dlib/metadata: one or the other"
    }
    $timestamp = Field $cfg "timestamp"
    if ($null -eq $timestamp) { $timestamp = "http://timestamp.acs.microsoft.com" }
    if (-not ($timestamp -is [string])) { Fail "$Config's `"timestamp`" is not a string" }
    if ($timestamp -eq "") {
        # An Artifact Signing certificate lives 72 hours: a signature without a timestamp dies with it.
        if (-not $test) { Fail "$Config has no timestamp server, which only a test certificate may skip" }
    } elseif ($timestamp -notmatch '^https?://[^\s"]+$') {
        Fail "$Config's `"timestamp`" is not an http(s) URL: $timestamp"
    }

    $a = @("sign", "/fd", "SHA256")
    if ($timestamp -ne "") { $a += @("/tr", $timestamp, "/td", "SHA256") }
    if ($test) {
        $a += @("/f", (ExistingFile $cfg "testPfx"))
    } else {
        $a += @("/dlib", (ExistingFile $cfg "dlib"), "/dmdf", (ExistingFile $cfg "metadata"))
    }
    & $signtool @a $File
    if ($LASTEXITCODE -ne 0) { Fail "signtool failed ($LASTEXITCODE) on $File" }

    $s = Get-AuthenticodeSignature -LiteralPath $File
    if (-not $s.SignerCertificate) { Fail "$File carries no signature after signtool ($($s.Status))" }
    if ($timestamp -ne "" -and -not $s.TimeStamperCertificate) { Fail "$File's signature has no timestamp" }
    if ($Keep -ne "") { Copy-Item -LiteralPath $File -Destination $Keep -Force }
} catch {
    Fail "$_"
}
exit 0
