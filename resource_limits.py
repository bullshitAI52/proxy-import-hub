"""Single-process bounded memory cache and request windows; no disk credentials."""
from collections import OrderedDict,deque
import threading
import time

class Cache:
    def __init__(self,ttl=300,max_bytes=16*1024*1024,max_items=128):
        self.ttl=ttl;self.max_bytes=max_bytes;self.max_items=max_items
        self.items=OrderedDict();self.size=0;self.lock=threading.Lock()
    def get(self,key):
        with self.lock:
            item=self.items.get(key)
            if item is None:return None
            deadline,value,size=item
            if time.monotonic()>=deadline:
                self.items.pop(key);self.size-=size;return None
            self.items.move_to_end(key);return value
    def put(self,key,value):
        size=len(value.encode()) if isinstance(value,str) else len(value)
        if size>self.max_bytes:return
        with self.lock:
            old=self.items.pop(key,None)
            if old:self.size-=old[2]
            self.items[key]=(time.monotonic()+self.ttl,value,size);self.size+=size
            while self.size>self.max_bytes or len(self.items)>self.max_items:
                _,item=self.items.popitem(last=False);self.size-=item[2]
    def drop(self,prefix):
        with self.lock:
            for key in list(self.items):
                if key[0]==prefix:self.size-=self.items.pop(key)[2]
    def clear(self):
        with self.lock:self.items.clear();self.size=0

class Limiter:
    def __init__(self):self.windows=OrderedDict();self.lock=threading.Lock()
    def allow(self,key,limit,seconds=60):
        now=time.monotonic()
        with self.lock:
            queue=self.windows.setdefault(key,deque());self.windows.move_to_end(key)
            while queue and queue[0]<=now-seconds:queue.popleft()
            if len(queue)>=limit:return False
            queue.append(now)
            while len(self.windows)>128:self.windows.popitem(last=False)
            return True
    def clear(self):
        with self.lock:self.windows.clear()

CACHE=Cache()
LIMITER=Limiter()
