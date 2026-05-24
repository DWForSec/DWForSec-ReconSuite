import re

ROUTE_REGEX = re.compile(
    r'(?:"|\')'                  # opening quote
    r'('                         # start capture group
    r'/(?:api/|v[12]/|admin/|login|auth/|oauth/|upload|users|orders|payment|internal|debug|swagger|openapi)[a-zA-Z0-9\-\._~!\$&\'\(\)\*\+,;=:@/%]*'
    r')'                         # end capture group
    r'(?:"|\')'                  # closing quote
)

def extract_routes(content: str) -> list[str]:
    """
    Extracts matches for routing endpoints from JS/HTML source codes.
    """
    if not content:
        return []
    matches = ROUTE_REGEX.findall(content)
    # Deduplicate and sort
    return sorted(list(set(matches)))
