"""轻量线程安全事件总线，模块解耦的纽带。"""
import threading

from core import logger


class EventBus:
    def __init__(self):
        self._subs = {}
        self._lock = threading.Lock()

    def subscribe(self, event, handler):
        with self._lock:
            handlers = self._subs.setdefault(event, [])
            if handler not in handlers:
                handlers.append(handler)

    def unsubscribe(self, event, handler):
        with self._lock:
            handlers = self._subs.get(event, [])
            if handler in handlers:
                handlers.remove(handler)

    def publish(self, event, data=None):
        with self._lock:
            handlers = list(self._subs.get(event, []))
        for h in handlers:
            try:
                h(data)
            except Exception as e:
                try:
                    logger.record_err("events.publish.%s" % event, e)
                except Exception:
                    pass

    def clear(self):
        with self._lock:
            self._subs.clear()

    def events(self):
        with self._lock:
            return sorted(self._subs.keys())


bus = EventBus()