import re

PATTERNS = {
    "Google API Key": r"AIzaSy[a-zA-Z0-9\-_]{35}",
    "AWS Access Key": r"AKIA[a-zA-Z0-9]{16}",
    "AWS Secret Key": r"aws_secret_access_key\s*[:=]\s*['\"][a-zA-Z0-9/\+=]{40}['\"]",
    "JWT": r"eyJhbGciOi[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
    "Bearer token": r"Bearer\s+[a-zA-Z0-9\-\._~\+\/]+=*",
    "API Key Assignment": r"(?:api_key|apikey|api-key)\s*[:=]\s*['\"][a-zA-Z0-9\-_]{16,}['\"]",
    "Secret Assignment": r"(?:secret|client_secret|client-secret)\s*[:=]\s*['\"][a-zA-Z0-9\-_]{16,}['\"]",
    "Firebase Config": r"apiKey\s*:\s*['\"]AIzaSy[a-zA-Z0-9\-_]{35}['\"]",
    "Stripe Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Supabase Key": r"sbp_[a-zA-Z0-9]{40}",
    "GraphQL Endpoint": r"/(?:graphql|v1/graphql|v2/graphql|api/graphql|query)",
    "Swagger/OpenAPI": r"/(?:swagger|swagger-ui|openapi|api-docs|swagger\.json|v1/swagger\.json|v2/swagger\.json)",
    "Admin Route": r"/(?:admin|dashboard|wp-admin|settings/admin|manage|panel|controlpanel)",
    "Staging URL": r"https?://[a-zA-Z0-9\-\.]*(?:staging|dev|uat|local|test|sandbox|stage)[a-zA-Z0-9\-\.]*\.[a-zA-Z]{2,}",
    "Internal IP": r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
    "WebSocket Endpoint": r"wss?://[a-zA-Z0-9\-\.\/\?&:=]+",
    "Cloud Storage URL": r"https?://[a-zA-Z0-9\-\.]*(?:s3\.amazonaws\.com|blob\.core\.windows\.net|googleapis\.com/|[a-zA-Z0-9\-\.]*s3[a-zA-Z0-9\-\.]*\.amazonaws\.com)",
    "Debug Keyword": r"(?:console\.log|debugger|console\.debug|debug\s*[:=]\s*true|environment\s*[:=]\s*['\"]development['\"])"
}

# Compile patterns for faster execution
COMPILED_PATTERNS = {name: re.compile(pat, re.IGNORECASE) for name, pat in PATTERNS.items()}
