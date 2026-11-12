# THIRD-PARTY-NOTICES.txt: the licence of every crate VibeFTP ships, with the licence texts the
# crates themselves carry. build.ps1 runs it after the release build, so the list matches
# Cargo.lock; the installer puts the file next to VibeFTP.exe.
#   notices.ps1 -Out <file> [-Report]
# What ships: the resolve graph from vibeftp-app over normal dependencies (no dev or build
# dependencies) for x86_64-pc-windows-msvc, VibeFTP's own crates left out (LICENSE covers them).
# The texts: each crate's top-level LICENSE*, LICENCE*, COPYING*, NOTICE*, COPYRIGHT* and
# UNLICENSE* files, and the file `license-file` names; identical texts are printed once, with
# every crate that carries them. A crate with none gets its REUSE LICENSES\<id> file, or else the
# standard SPDX text of its licence (licenses\ beside this script) with its authors as the
# copyright line.
param([Parameter(Mandatory)][string]$Out, [switch]$Report)
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\..\.."
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"

Push-Location $root
try {
    # What a release build links: cargo tree resolves features as the build does (cargo
    # metadata's graph is the union of every feature anyone asks for, dev dependencies' too).
    # Proc macros run in the compiler and never ship, and neither does what only they use.
    $tree = cargo tree --offline --locked -e normal,no-proc-macro --target x86_64-pc-windows-msvc -p vibeftp-app --prefix none -f "{p}"
    if ($LASTEXITCODE -ne 0) { throw "cargo tree failed" }
    $json = cargo metadata --offline --locked --format-version 1 --filter-platform x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) { throw "cargo metadata failed" }
} finally { Pop-Location }
$m = $json | ConvertFrom-Json -AsHashtable
$linked = @{}
foreach ($line in $tree) { if ($line -match '^(\S+) v(\S+)') { $linked["$($Matches[1]) $($Matches[2])"] = $true } }
$own = @($m.workspace_members)
$shipped = @($m.packages | Where-Object { $linked.ContainsKey("$($_.name) $($_.version)") -and $own -notcontains $_.id } | Sort-Object { $_.name }, { $_.version })
if ($shipped.Count -lt 100) { throw "only $($shipped.Count) crates found: cargo tree's output changed?" }

$namePattern = '^(LICEN[CS]E|COPYING|NOTICE|COPYRIGHT|UNLICENSE)([-_.].*)?$'
$groups = [ordered]@{}   # text -> list of "name version (licence)"
$missing = @()
$needed = @()
foreach ($p in $shipped) {
    $dir = Split-Path -Parent $p.manifest_path
    $files = @(Get-ChildItem -LiteralPath $dir -File | Where-Object { $_.Name -match $namePattern })
    if ($p.license_file) {
        $lf = Join-Path $dir $p.license_file
        if ((Test-Path -LiteralPath $lf -PathType Leaf) -and -not ($files | Where-Object { $_.FullName -eq (Resolve-Path -LiteralPath $lf).Path })) { $files += Get-Item -LiteralPath $lf }
    }
    $licence = if ($p.license) { $p.license } else { "see its licence file" }
    $label = "$($p.name) $($p.version) ($licence)"
    $texts = @()
    foreach ($f in ($files | Sort-Object Name)) {
        $texts += ([IO.File]::ReadAllText($f.FullName) -replace "`r`n", "`n").Trim()
    }
    # The licence VibeFTP takes it under: of "A OR B", MIT when offered, else the first; every
    # part of an AND. (Slint: GPL-3.0-only.)
    $chosen = @()
    if ($p.license) {
        $options = @($p.license -split '\s+OR\s+|/' | ForEach-Object { $_.Trim().Trim('(', ')').Trim() } | Where-Object { $_ })
        $pick = if ($options -contains "MIT") { "MIT" } else { $options[0] }
        $chosen = @($pick -split '\s+AND\s+' | ForEach-Object { ($_.Trim().Trim('(', ')') -split '\s+WITH\s+')[0].Trim() })
    }
    if (-not $texts.Count) {
        # REUSE layout: LICENSES\<id>.txt or .md.
        foreach ($id in $chosen) {
            $f = @("$id.txt", "$id.md") | ForEach-Object { Join-Path $dir "LICENSES\$_" } | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
            if ($f) { $texts += ([IO.File]::ReadAllText($f) -replace "`r`n", "`n").Trim() }
        }
    }
    if (-not $texts.Count) {
        $missing += $p
        $authors = if ($p.authors) { ($p.authors | ForEach-Object { $_ -replace '\s*<[^>]*>', '' }) -join ', ' } else { "the $($p.name) authors" }
        foreach ($id in $chosen) {
            $std = Join-Path $PSScriptRoot "licenses\$id.txt"
            if (-not (Test-Path -LiteralPath $std)) { $needed += "licenses\$id.txt"; continue }
            $t = ([IO.File]::ReadAllText($std) -replace "`r`n", "`n").Trim()
            $texts += if ($t.Contains("<year> <copyright holders>")) { $t.Replace("<year> <copyright holders>", $authors) } else { "Copyright (c) $authors`n`n$t" }
        }
    }
    foreach ($t in $texts) {
        if (-not $groups.Contains($t)) { $groups[$t] = [System.Collections.Generic.List[string]]::new() }
        if (-not $groups[$t].Contains($label)) { $groups[$t].Add($label) }
    }
}

if ($needed.Count) { throw "standard licence texts missing:`n  " + (($needed | Sort-Object -Unique) -join "`n  ") }
if ($Report) {
    "shipped crates: $($shipped.Count); distinct texts: $($groups.Count); with no text of their own: $($missing.Count)"
    $missing | ForEach-Object { "  {0} {1}: {2}" -f $_.name, $_.version, $_.license }
}

$rule = "-" * 78
$sb = [Text.StringBuilder]::new()
[void]$sb.Append("VibeFTP includes the third-party software listed below. VibeFTP itself is licensed under the`nGNU Affero General Public License v3.0 (LICENSE). Slint is used under its GPL-3.0 option.`n")
[void]$sb.Append("`nThe Rust standard library is linked in (MIT OR Apache-2.0, the Rust Project Developers),`nand so is the Microsoft C runtime (static CRT, under the Visual Studio license terms).`n")
[void]$sb.Append("`n$rule`nCrates ($($shipped.Count))`n$rule`n")
foreach ($p in $shipped) { [void]$sb.Append("$($p.name) $($p.version): $(if ($p.license) { $p.license } else { 'see its licence file' })`n") }
foreach ($t in $groups.Keys) {
    [void]$sb.Append("`n$rule`n$($groups[$t] -join "`n")`n$rule`n`n$t`n")
}
New-Item -ItemType Directory -Force (Split-Path -Parent $Out) | Out-Null
[IO.File]::WriteAllText($Out, ($sb.ToString() -replace "`n", "`r`n"), [Text.UTF8Encoding]::new($false))
if ($Report) { "wrote $Out ($((Get-Item $Out).Length) bytes)" }
