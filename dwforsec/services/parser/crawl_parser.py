import os

def parse_crawled_urls(stdout: str) -> list[str]:
    """
    Parses outputs of crawlers (Katana, gau, waybackurls) which usually return one URL per line.
    """
    urls = []
    if not stdout:
        return urls
        
    for line in stdout.splitlines():
        line = line.strip()
        if line and (line.startswith("http://") or line.startswith("https://")):
            urls.append(line)
            
    return sorted(list(set(urls)))
