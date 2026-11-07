"""Self-diagnosis for a process that is burning CPU.

A background thread samples the process's CPU time. If it stays above a threshold for several samples, one WARNING is logged
with the stack of every thread (so the code that is spinning is named), then it stays quiet for a while. `kill -USR1`
dumps all thread stacks to stderr on demand. Only code locations are logged, never variables, arguments or secrets.
"""

from __future__ import annotations

import faulthandler
import logging
import signal
import sys
import threading
import time
import traceback

log = logging.getLogger("mcpopus.diag")


def thread_stacks(limit: int = 12) -> str:
    names = {t.ident: t.name for t in threading.enumerate()}
    parts = []
    for ident, frame in sys._current_frames().items():
        if ident == threading.get_ident():
            continue  # the watchdog itself
        lines = traceback.format_stack(frame, limit=limit)
        parts.append(f"--- thread {names.get(ident, ident)} ---\n" + "".join(lines).rstrip())
    return "\n".join(parts)


class CpuWatchdog(threading.Thread):
    def __init__(self, interval: float = 10.0, threshold: float = 0.85, samples: int = 3, quiet: float = 600.0) -> None:
        super().__init__(name="mcpopus-cpu-watchdog", daemon=True)
        self.interval, self.threshold, self.samples, self.quiet = interval, threshold, samples, quiet
        self._stop_event = threading.Event()
        self.reports = 0

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        busy, last_cpu, last_wall, last_report = 0, time.process_time(), time.monotonic(), -1e9
        while not self._stop_event.wait(self.interval):
            cpu, wall = time.process_time(), time.monotonic()
            usage = (cpu - last_cpu) / max(wall - last_wall, 1e-6)
            last_cpu, last_wall = cpu, wall
            busy = busy + 1 if usage >= self.threshold else 0
            if busy >= self.samples and wall - last_report >= self.quiet:
                last_report = wall
                self.reports += 1
                log.warning("process CPU has been at %.0f%% of one core for about %.0fs; thread stacks follow\n%s",
                            usage * 100, self.interval * busy, thread_stacks())


def install(interval: float = 10.0) -> CpuWatchdog:
    try:
        faulthandler.register(signal.SIGUSR1, all_threads=True)  # docker kill -s USR1 <container>
    except (AttributeError, ValueError, OSError):
        pass
    wd = CpuWatchdog(interval=interval)
    wd.start()
    return wd
