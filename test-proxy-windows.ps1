[CmdletBinding()]
param(
    [int]$StartupTimeoutSeconds = 180,
    [int]$RequestTimeoutSeconds = 90,
    [int]$MetricsTimeoutSeconds = 35,
    [string]$ProxyUrl = "http://127.0.0.1:8080",
    [string]$TorCheckUrl = "https://check.torproject.org/api/ip"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $repoRoot

foreach ($commandName in @("cargo", "curl.exe")) {
    if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
        throw "Required command not found: $commandName"
    }
}

function Invoke-CargoStep {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & cargo @Arguments
    if ($LASTEXITCODE -ne 0) {
        if ($Arguments[0] -eq "check") {
            Write-Host ""
            Write-Host "Native Windows is not supported by the current bridge transport." -ForegroundColor Yellow
            Write-Host "src/main.rs uses Tokio UnixListener/UnixStream and /tmp/proxy-bridge.sock."
            Write-Host "Port the internal bridge to loopback TCP or a Windows-compatible transport, then rerun this script."
        }
        throw "cargo $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Test-ProxyPort {
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $connectTask = $client.ConnectAsync("127.0.0.1", 8080)
        return $connectTask.Wait(500) -and $client.Connected
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

$testDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("proxy-smoke-" + [guid]::NewGuid().ToString("N"))
$stdoutLog = Join-Path $testDirectory "proxy.stdout.log"
$stderrLog = Join-Path $testDirectory "proxy.stderr.log"
$proxyProcess = $null
New-Item -ItemType Directory -Path $testDirectory | Out-Null

try {
    Write-Host "==> Checking, testing, and building on native Windows"
    Invoke-CargoStep -Arguments @("check", "--locked")
    Invoke-CargoStep -Arguments @("test", "--locked")
    Invoke-CargoStep -Arguments @("build", "--release", "--locked")

    Write-Host "==> Starting proxy"
    $proxyProcess = Start-Process `
        -FilePath (Join-Path $repoRoot "target\release\proxy.exe") `
        -PassThru `
        -NoNewWindow `
        -RedirectStandardOutput $stdoutLog `
        -RedirectStandardError $stderrLog

    $deadline = [DateTime]::UtcNow.AddSeconds($StartupTimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $proxyProcess.Refresh()
        if ($proxyProcess.HasExited) {
            Get-Content $stderrLog -ErrorAction SilentlyContinue
            throw "Proxy exited before becoming ready"
        }
        if (Test-ProxyPort) {
            break
        }
        Start-Sleep -Seconds 1
    }

    if (-not (Test-ProxyPort)) {
        Get-Content $stderrLog -ErrorAction SilentlyContinue
        throw "Proxy did not listen on 127.0.0.1:8080 within ${StartupTimeoutSeconds}s"
    }

    Write-Host "==> Verifying Tor routing through $ProxyUrl"
    $responseLines = & curl.exe `
        --fail `
        --silent `
        --show-error `
        --retry 2 `
        --max-time $RequestTimeoutSeconds `
        --proxy $ProxyUrl `
        $TorCheckUrl
    if ($LASTEXITCODE -ne 0) {
        Get-Content $stderrLog -ErrorAction SilentlyContinue
        throw "Tor check request failed with curl status $LASTEXITCODE"
    }

    $responseText = $responseLines -join "`n"
    $torCheck = $responseText | ConvertFrom-Json
    if ($torCheck.IsTor -ne $true) {
        throw "Tor Check did not report IsTor=true. Response: $responseText"
    }
    Write-Host "Tor Check response: $responseText"

    Write-Host "==> Waiting for the periodic scheduler metrics sample"
    $metricsDeadline = [DateTime]::UtcNow.AddSeconds($MetricsTimeoutSeconds)
    $metricsFound = $false
    while ([DateTime]::UtcNow -lt $metricsDeadline) {
        if (Test-Path $stderrLog) {
            $metricsFound = [bool](Select-String `
                -Path $stderrLog `
                -Pattern 'permits_in_use=0.*circuit_build_count=[1-9][0-9]*' `
                -Quiet)
            if ($metricsFound) {
                break
            }
        }
        Start-Sleep -Seconds 1
    }

    if (-not $metricsFound) {
        Get-Content $stderrLog -ErrorAction SilentlyContinue
        throw "No completed circuit-build metrics sample appeared within ${MetricsTimeoutSeconds}s"
    }

    Write-Host "==> Native Windows smoke test passed" -ForegroundColor Green
    Select-String -Path $stderrLog -Pattern 'circuit metrics:' | Select-Object -Last 3
}
finally {
    if ($null -ne $proxyProcess) {
        $proxyProcess.Refresh()
        if (-not $proxyProcess.HasExited) {
            Stop-Process -Id $proxyProcess.Id -Force -ErrorAction SilentlyContinue
            $proxyProcess.WaitForExit()
        }
    }
    if (Test-Path $testDirectory) {
        Remove-Item -Recurse -Force $testDirectory
    }
}

