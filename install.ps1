$ErrorActionPreference = "Stop"

$Repo = "andrejksi/emiv2"
$Version = if ($env:EMI_VERSION) { $env:EMI_VERSION } else { "latest" }
$InstallDir = if ($env:EMI_INSTALL_DIR) { $env:EMI_INSTALL_DIR } else { Join-Path $HOME ".local\bin" }
$Archive = "emi-x86_64-pc-windows-msvc.zip"

$BaseUrl = if ($Version -eq "latest") {
    "https://github.com/$Repo/releases/latest/download"
} else {
    "https://github.com/$Repo/releases/download/$Version"
}

$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("emi-install-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $TmpDir | Out-Null

try {
    $ZipPath = Join-Path $TmpDir $Archive
    Write-Host "Downloading $Archive ($Version)..."
    Invoke-WebRequest -Uri "$BaseUrl/$Archive" -OutFile $ZipPath

    try {
        $SumsPath = Join-Path $TmpDir "SHA256SUMS.txt"
        Invoke-WebRequest -Uri "$BaseUrl/SHA256SUMS.txt" -OutFile $SumsPath
        $Line = Get-Content $SumsPath | Where-Object { $_ -match "\s+\*?$([regex]::Escape($Archive))$" } | Select-Object -First 1
        if ($Line) {
            $Expected = ($Line -split "\s+")[0].ToLowerInvariant()
            $Actual = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($Actual -ne $Expected) {
                throw "Checksum mismatch for $Archive (expected $Expected, got $Actual)"
            }
        }
    } catch {
        if ($_.Exception.Message -like "Checksum mismatch*") { throw }
    }

    Expand-Archive -Path $ZipPath -DestinationPath $TmpDir -Force
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item -Path (Join-Path $TmpDir "emi.exe") -Destination (Join-Path $InstallDir "emi.exe") -Force
    Write-Host "Installed emi to $(Join-Path $InstallDir 'emi.exe')"
    if (-not (($env:PATH -split ";") -contains $InstallDir)) {
        Write-Host "Add to PATH: `$env:PATH = `"$InstallDir;`$env:PATH`""
    }
} finally {
    Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
}
