def classify_technologies(tech_strings: list[str]) -> list[str]:
    """
    Cleans up and categorizes raw technology strings from Wappalyzer/WhatWeb outputs.
    """
    classified = set()
    for tech in tech_strings:
        tech_lower = tech.strip().lower()
        if not tech_lower:
            continue
            
        # Standard classification mappings
        if any(x in tech_lower for x in ["nginx", "apache", "cloudflare", "iis", "caddy", "litespeed"]):
            classified.add(f"Web Server: {tech}")
        elif any(x in tech_lower for x in ["react", "vue", "angular", "next.js", "nuxt", "jquery", "bootstrap"]):
            classified.add(f"Frontend Framework: {tech}")
        elif any(x in tech_lower for x in ["wordpress", "drupal", "joomla", "ghost", "magento"]):
            classified.add(f"CMS: {tech}")
        elif any(x in tech_lower for x in ["php", "python", "node", "ruby", "java", "golang", "asp.net"]):
            classified.add(f"Backend Tech: {tech}")
        elif any(x in tech_lower for x in ["mysql", "postgresql", "sqlite", "mongodb", "redis", "oracle"]):
            classified.add(f"Database: {tech}")
        else:
            classified.add(tech)
            
    return sorted(list(classified))
