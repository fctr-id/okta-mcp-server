import asyncio
import logging
from typing import Callable, Awaitable, TypeVar, Any

logger = logging.getLogger('okta-mcp-server')

# Type variable for generic function return types
T = TypeVar('T')

class RequestManager:
    """
    Manages concurrent Okta API requests to prevent exceeding rate limits.
    
    This simple implementation uses a counter and queue to ensure that
    the number of concurrent requests never exceeds the configured limit.
    """
    
    def __init__(self, concurrent_limit: int = 15):
        """
        Initialize the request manager with a concurrent request limit.
        
        Args:
            concurrent_limit: Maximum number of concurrent requests (default: 15)
        """
        self.concurrent_limit = concurrent_limit
        self.active_requests = 0
        self.request_queue = asyncio.Queue()
        self.lock = asyncio.Lock()
        logger.debug(f"RequestManager initialized with concurrent limit of {concurrent_limit}")
        
    async def execute(self, func: Callable[..., Awaitable[T]], *args, **kwargs) -> T:
        """
        Execute a function with concurrency control.
        
        If the number of active requests is below the limit, executes immediately.
        Otherwise, queues the request and waits until a slot becomes available.
        
        Args:
            func: The async function to execute
            args: Positional arguments for the function
            kwargs: Keyword arguments for the function
            
        Returns:
            The result of the function call
        """
        # Create a task descriptor
        task_desc = {
            "func": func,
            "args": args,
            "kwargs": kwargs,
            "future": asyncio.Future()
        }
        
        # Check if we can execute immediately or need to queue
        can_execute = False
        async with self.lock:
            if self.active_requests < self.concurrent_limit:
                self.active_requests += 1
                can_execute = True
                logger.debug(f"Starting request immediately ({self.active_requests}/{self.concurrent_limit} active)")
            else:
                # Need to queue this request
                logger.debug(f"Queueing request (limit of {self.concurrent_limit} reached, {self.request_queue.qsize()} waiting)")
                await self.request_queue.put(task_desc)
                
        if can_execute:
            # Execute immediately
            try:
                result = await func(*args, **kwargs)
                task_desc["future"].set_result(result)
            except Exception as e:
                task_desc["future"].set_exception(e)
                raise
            finally:
                # Release the slot and process next queued request if any
                await self._release_slot()
                
        # Wait for the result
        return await task_desc["future"]
    
    async def _release_slot(self):
        """
        Release a request slot and process the next queued request if available.
        """
        # Process next queued request if any
        next_task = None
        async with self.lock:
            if not self.request_queue.empty():
                next_task = await self.request_queue.get()
                logger.debug(f"Processing next queued request ({self.active_requests}/{self.concurrent_limit} active, {self.request_queue.qsize()} waiting)")
            else:
                self.active_requests -= 1
                logger.debug(f"Released request slot ({self.active_requests}/{self.concurrent_limit} active)")
                
        # Execute the next task if we dequeued one
        if next_task:
            asyncio.create_task(self._execute_queued_task(next_task))
    
    async def _execute_queued_task(self, task_desc):
        """
        Execute a previously queued task.
        
        Args:
            task_desc: Task descriptor containing function and arguments
        """
        try:
            result = await task_desc["func"](*task_desc["args"], **task_desc["kwargs"])
            task_desc["future"].set_result(result)
        except Exception as e:
            task_desc["future"].set_exception(e)
        finally:
            # Release the slot for the next request
            await self._release_slot()
    
    @property
    def active_count(self):
        """Get the current number of active requests."""
        return self.active_requests
    
    @property
    def queue_size(self):
        """Get the current queue size."""
        return self.request_queue.qsize()