Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot

if (-not (Test-Path out)) {
    New-Item -ItemType Directory -Path out | Out-Null
}

if (-not (Test-Path dist)) {
    New-Item -ItemType Directory -Path dist | Out-Null
}

Write-Host "Compiling source..."
javac -encoding UTF-8 -d out (Get-ChildItem -Recurse -Path src -Filter *.java | ForEach-Object { $_.FullName })

Write-Host "Packaging jar..."
jar cfe dist/ToolMaHoa.jar toolmahoa.Main -C out .

Write-Host "Done. Output: dist/ToolMaHoa.jar"
