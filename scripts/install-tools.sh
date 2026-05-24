#!/bin/bash
# Install and update recon tools for DWForSec-ReconSuite

TOOLS_DIR="$(dirname "$0")/../dwforsec/tools"
mkdir -p "$TOOLS_DIR"

declare -A TOOLS_LIST=(
    ["subfinder"]="https://github.com/projectdiscovery/subfinder"
    ["assetfinder"]="https://github.com/tomnomnom/assetfinder"
    ["httpx"]="https://github.com/projectdiscovery/httpx"
    ["naabu"]="https://github.com/projectdiscovery/naabu"
    ["nuclei"]="https://github.com/projectdiscovery/nuclei"
    ["katana"]="https://github.com/projectdiscovery/katana"
    ["amass"]="https://github.com/owasp-amass/amass"
    ["whatweb"]="https://github.com/urbanadventurer/WhatWeb"
    ["wafw00f"]="https://github.com/EnableSecurity/wafw00f"
    ["gau"]="https://github.com/lc/gau"
    ["waybackurls"]="https://github.com/tomnomnom/waybackurls"
    ["hakrawler"]="https://github.com/hakluke/hakrawler"
    ["sslscan"]="https://github.com/rbsec/sslscan"
    ["testssl.sh"]="https://github.com/drwetter/testssl.sh"
)

echo -e "\e[36m[*] Checking dependency tools...\e[0m"

# Check Go
if command -v go &>/dev/null; then
    echo -e "\e[32m[+] Go detected! Will compile Go tools if needed.\e[0m"
    HAS_GO=true
else
    echo -e "\e[33m[-] Go not detected. Some Go tools might not build automatically.\e[0m"
    HAS_GO=false
fi

for tool in "${!TOOLS_LIST[@]}"; do
    repo="${TOOLS_LIST[$tool]}"
    dest="$TOOLS_DIR/$tool"
    
    if [ ! -d "$dest" ]; then
        echo -e "\e[36m[*] Cloning $tool from $repo...\e[0m"
        git clone "$repo" "$dest"
    else
        echo -e "\e[32m[+] $tool already exists. Pulling latest updates...\e[0m"
        cd "$dest" && git pull && cd - &>/dev/null
    fi

    # Compile Go tools
    if [ "$HAS_GO" = true ]; then
        cd "$dest"
        if [ "$tool" = "subfinder" ]; then
            cd v2/cmd/subfinder && go build -o ../../../subfinder && cd - &>/dev/null
        elif [ "$tool" = "httpx" ]; then
            cd cmd/httpx && go build -o ../../httpx && cd - &>/dev/null
        elif [ "$tool" = "naabu" ]; then
            cd v2/cmd/naabu && go build -o ../../../naabu && cd - &>/dev/null
        elif [ "$tool" = "nuclei" ]; then
            cd v2/cmd/nuclei && go build -o ../../../nuclei && cd - &>/dev/null
        elif [ "$tool" = "katana" ]; then
            cd cmd/katana && go build -o ../../katana && cd - &>/dev/null
        elif [ "$tool" = "amass" ] || [ "$tool" = "gau" ] || [ "$tool" = "waybackurls" ] || [ "$tool" = "hakrawler" ]; then
            go build -o "$tool"
        fi
        cd - &>/dev/null
    fi
done

echo -e "\e[32m[+] Installation script finished!\e[0m"
