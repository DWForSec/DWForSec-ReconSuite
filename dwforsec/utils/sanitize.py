import re

# Characters that are unsafe in shell commands
UNSAFE_CHARS = re.compile(r"[`;$&|<>*?(){}\[\]\n\r\t ]")

def sanitize_arg(arg: str) -> str:
    """
    Sanitizes a single command line argument to ensure it doesn't contain shell metacharacters.
    Spaces are allowed only if we are passing lists of arguments directly to subprocess_exec (which doesn't invoke a shell).
    However, we remove hazardous characters.
    """
    if not arg:
        return ""
    # Strip dangerous control chars
    return re.sub(r"[`;$&|<>\n\r\t]", "", arg)

def clean_filename(name: str) -> str:
    """
    Cleans a string to make it safe for use as a file name.
    """
    return re.sub(r"[^a-zA-Z0-9\-\._]", "_", name)
