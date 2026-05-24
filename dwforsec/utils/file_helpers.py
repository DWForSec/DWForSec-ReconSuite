import aiofiles
import os
from pathlib import Path
from dwforsec.core.logging import logger

async def write_file_async(file_path: str | Path, content: str) -> None:
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        async with aiofiles.open(path, mode='w', encoding='utf-8') as f:
            await f.write(content)
        logger.debug(f"Successfully wrote to {path}")
    except Exception as e:
        logger.error(f"Failed to write to {path}: {e}")
        raise

async def read_file_async(file_path: str | Path) -> str:
    path = Path(file_path)
    if not path.exists():
        logger.warning(f"File {path} does not exist. Returning empty string.")
        return ""
    try:
        async with aiofiles.open(path, mode='r', encoding='utf-8') as f:
            return await f.read()
    except Exception as e:
        logger.error(f"Failed to read from {path}: {e}")
        raise
