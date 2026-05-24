def classify_risk(
    findings_count: dict[str, int], 
    has_secrets: bool, 
    ssl_issues_count: int
) -> str:
    """
    Returns an overall risk level (Critical, High, Medium, Low) for the target scan.
    """
    crits = findings_count.get("critical", 0)
    highs = findings_count.get("high", 0)
    meds = findings_count.get("medium", 0)
    lows = findings_count.get("low", 0)
    
    if crits > 0:
        return "Critical"
    elif highs > 0 or (has_secrets and meds > 0):
        return "High"
    elif meds > 2 or ssl_issues_count > 3:
        return "Medium"
    else:
        return "Low"
