from dwforsec.core.config import settings

def mask_credential(secret: str, reveal: bool = None) -> str:
    """
    Masks a credential/API key. Example: AIzaSy********abcd
    If reveal is True (or config reveal_secrets is True), returns the original secret.
    """
    if reveal is None:
        reveal = settings.REVEAL_SECRETS
        
    if reveal or not settings.MASK_SECRETS:
        return secret
        
    if not secret:
        return ""
        
    length = len(secret)
    if length <= 8:
        return "*" * length
        
    prefix = secret[:6]
    suffix = secret[-4:]
    return f"{prefix}{'*' * (length - 10)}{suffix}"
