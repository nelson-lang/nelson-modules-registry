# Signs registry.json with the Ed25519 private key passed as an argument.
# Windows PowerShell port of sign_registry.sh. Produces registry.json.sig
# (signature) and registry.json.sha256 (checksum). Requires openssl in PATH
# (Git for Windows ships one under usr\bin).
#
#   powershell -ExecutionPolicy Bypass -File scripts\sign_registry.ps1 <cle_privee.pem>
#
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string] $Key
)
$ErrorActionPreference = 'Stop'

function Get-Hex([byte[]] $bytes) {
  # lowercase hexadecimal, no spaces or newline
  -join ($bytes | ForEach-Object { $_.ToString('x2') })
}

function Resolve-OpenSSL {
  # 1) openssl already on PATH
  $cmd = Get-Command openssl -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  # 2) derive it from the Git installation (Git ships openssl)
  $candidates = New-Object System.Collections.Generic.List[string]
  $git = Get-Command git -ErrorAction SilentlyContinue
  if ($git) {
    # <GitRoot>\cmd\git.exe or <GitRoot>\bin\git.exe -> <GitRoot>
    $gitRoot = Split-Path -Parent (Split-Path -Parent $git.Source)
    $candidates.Add((Join-Path $gitRoot 'mingw64\bin\openssl.exe'))
    $candidates.Add((Join-Path $gitRoot 'usr\bin\openssl.exe'))
  }
  # 3) common install locations
  foreach ($root in @(
      'C:\WindowsTools\Git', "$env:ProgramFiles\Git",
      "${env:ProgramFiles(x86)}\Git", "$env:LOCALAPPDATA\Programs\Git")) {
    if ($root) {
      $candidates.Add((Join-Path $root 'mingw64\bin\openssl.exe'))
      $candidates.Add((Join-Path $root 'usr\bin\openssl.exe'))
    }
  }
  foreach ($c in $candidates) {
    if ($c -and (Test-Path -LiteralPath $c)) { return $c }
  }
  throw "openssl not found. Install it or add its folder to PATH (e.g. Git's mingw64\bin), then retry."
}

# Resolve the repository root (the parent of this scripts\ folder) so the script
# works regardless of the current directory.
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $scriptDir
$registry = Join-Path $root 'registry.json'
if (-not (Test-Path -LiteralPath $registry)) {
  throw "registry.json not found next to scripts\ ($registry)"
}
if (-not (Test-Path -LiteralPath $Key)) {
  throw "private key not found: $Key"
}

$openssl = Resolve-OpenSSL
$tmpDer = Join-Path ([System.IO.Path]::GetTempPath()) ("nmm_pub_" + [guid]::NewGuid().ToString('N') + '.der')
$tmpSig = Join-Path ([System.IO.Path]::GetTempPath()) ("nmm_sig_" + [guid]::NewGuid().ToString('N') + '.bin')
try {
  # 32-byte raw Ed25519 public key = last 32 bytes of the DER SubjectPublicKeyInfo
  & $openssl pkey -in $Key -pubout -outform DER -out $tmpDer
  if ($LASTEXITCODE -ne 0) { throw 'openssl pkey (public key export) failed' }
  $der = [System.IO.File]::ReadAllBytes($tmpDer)
  if ($der.Length -lt 32) { throw 'unexpected public key length' }
  $pub = Get-Hex ($der[($der.Length - 32)..($der.Length - 1)])

  # pure Ed25519 signature over the exact bytes of registry.json (128 hex chars)
  & $openssl pkeyutl -sign -rawin -inkey $Key -in $registry -out $tmpSig
  if ($LASTEXITCODE -ne 0) { throw 'openssl pkeyutl (sign) failed' }
  $sig = Get-Hex ([System.IO.File]::ReadAllBytes($tmpSig))

  # sha256 of the exact registry bytes
  $bytes = [System.IO.File]::ReadAllBytes($registry)
  $sha256 = [System.Security.Cryptography.SHA256]::Create()
  try { $sum = Get-Hex ($sha256.ComputeHash($bytes)) } finally { $sha256.Dispose() }
}
finally {
  Remove-Item -LiteralPath $tmpDer, $tmpSig -Force -ErrorAction SilentlyContinue
}

$sigJson = @"
{
  "format": "nmm-registry-signature",
  "version": 1,
  "algorithm": "ed25519",
  "file": "registry.json",
  "sha256": "$sum",
  "signatures": [
    { "public_key": "$pub", "signature": "$sig" }
  ]
}
"@

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText((Join-Path $root 'registry.json.sig'), $sigJson + "`n", $utf8NoBom)
[System.IO.File]::WriteAllText((Join-Path $root 'registry.json.sha256'), "$sum  registry.json`n", $utf8NoBom)
Write-Host 'signed: registry.json.sig and registry.json.sha256 written.'
