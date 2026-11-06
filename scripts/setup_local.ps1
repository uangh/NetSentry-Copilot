param([switch]$WithFrontend)
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
$pythonExe=Join-Path $projectRoot '.venv/Scripts/python.exe'
$env:PYTHONUTF8='1'
if (-not (Test-Path -LiteralPath $pythonExe)) {
    python -m venv (Join-Path $projectRoot '.venv')
    if ($LASTEXITCODE -ne 0) { throw 'Creating local Python environment failed.' }
}
& $pythonExe -m pip install --index-url https://pypi.org/simple -r (Join-Path $projectRoot 'requirements-gemini.txt')
if ($LASTEXITCODE -ne 0) { throw 'Locked Python dependency installation failed; no version fallback.' }
& $pythonExe -m pip check
if ($LASTEXITCODE -ne 0) { throw 'Dependency compatibility check failed.' }
if ($WithFrontend) {
    pnpm.cmd --dir (Join-Path $projectRoot 'frontend') install --frozen-lockfile
    if ($LASTEXITCODE -ne 0) { throw 'Locked frontend installation failed.' }
    pnpm.cmd --dir (Join-Path $projectRoot 'frontend') build
    if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
}
Write-Host 'Local setup completed. No Gemini generation was sent.'
