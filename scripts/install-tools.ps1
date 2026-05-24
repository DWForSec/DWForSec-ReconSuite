# Install and update recon tools for DWForSec-ReconSuite

$toolsDir = Join-Path $PSScriptRoot "..\dwforsec\tools"
if (-not (Test-Path $toolsDir)) {
    New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
}

$ToolsList = @{
    "subfinder"   = "https://github.com/projectdiscovery/subfinder"
    "assetfinder" = "https://github.com/tomnomnom/assetfinder"
    "httpx"        = "https://github.com/projectdiscovery/httpx"
    "naabu"        = "https://github.com/projectdiscovery/naabu"
    "nuclei"       = "https://github.com/projectdiscovery/nuclei"
    "katana"       = "https://github.com/projectdiscovery/katana"
    "amass"        = "https://github.com/owasp-amass/amass"
    "whatweb"      = "https://github.com/urbanadventurer/WhatWeb"
    "wafw00f"      = "https://github.com/EnableSecurity/wafw00f"
    "gau"          = "https://github.com/lc/gau"
    "waybackurls"  = "https://github.com/tomnomnom/waybackurls"
    "hakrawler"    = "https://github.com/hakluke/hakrawler"
    "sslscan"      = "https://github.com/rbsec/sslscan"
    "testssl.sh"   = "https://github.com/drwetter/testssl.sh"
}

Write-Host "[*] Checking dependency tools..." -ForegroundColor Cyan

# Check Go
$hasGo = $null -ne (Get-Command "go" -ErrorAction SilentlyContinue)
if ($hasGo) {
    Write-Host "[+] Go detected! Will compile Go tools if needed." -ForegroundColor Green
} else {
    Write-Host "[-] Go not detected. Some Go tools might not build automatically. Falling back to local bin downloads." -ForegroundColor Yellow
}

foreach ($tool in $ToolsList.Keys) {
    $repo = $ToolsList[$tool]
    $dest = Join-Path $toolsDir $tool
    
    if (-not (Test-Path $dest)) {
        Write-Host "[*] Cloning $tool from $repo..." -ForegroundColor Cyan
        git clone $repo $dest
    } else {
        Write-Host "[+] $tool already exists. Pulling latest updates..." -ForegroundColor Green
        Push-Location $dest
        git pull
        Pop-Location
    }

    # Custom compile/build processes
    if ($tool -eq "wafw00f") {
        Write-Host "[*] Setting up wafw00f python package..." -ForegroundColor Cyan
        Push-Location $dest
        python setup.py install --user
        Pop-Location
    }
    
    if ($hasGo -and ($tool -eq "subfinder" -or $tool -eq "httpx" -or $tool -eq "naabu" -or $tool -eq "nuclei" -or $tool -eq "katana" -or $tool -eq "amass" -or $tool -eq "gau" -or $tool -eq "waybackurls" -or $tool -eq "hakrawler")) {
        Write-Host "[*] Compiling $tool using Go..." -ForegroundColor Cyan
        Push-Location $dest
        # Find main file or run go build
        if ($tool -eq "subfinder") {
            Push-Location v2/cmd/subfinder
            go build -o ../../../subfinder.exe
            Pop-Location
        } elseif ($tool -eq "httpx") {
            Push-Location cmd/httpx
            go build -o ../../httpx.exe
            Pop-Location
        } elseif ($tool -eq "naabu") {
            Push-Location v2/cmd/naabu
            go build -o ../../../naabu.exe
            Pop-Location
        } elseif ($tool -eq "nuclei") {
            Push-Location v2/cmd/nuclei
            go build -o ../../../nuclei.exe
            Pop-Location
        } elseif ($tool -eq "katana") {
            Push-Location cmd/katana
            go build -o ../../katana.exe
            Pop-Location
        } else {
            go build -o "$tool.exe"
        }
        Pop-Location
    }
}

Write-Host "[+] Installation script finished!" -ForegroundColor Green
