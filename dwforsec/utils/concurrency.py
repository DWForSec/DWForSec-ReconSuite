import asyncio
from dwforsec.core.config import settings

class ConcurrencyManager:
    def __init__(self, max_concurrency: int = None):
        limit = max_concurrency or settings.MAX_CONCURRENCY
        self.semaphore = asyncio.Semaphore(limit)
        
    async def run_concurrent(self, coro):
        async with self.semaphore:
            return await coro
            
# Global manager instance
concurrency_manager = ConcurrencyManager()
