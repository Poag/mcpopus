"""The CPU watchdog names the code that is spinning, and stays quiet for an idle process."""

import logging
import threading
import time

from mcpopus.diag import CpuWatchdog


def spin_forever_marker(stop: threading.Event) -> None:
    while not stop.is_set():
        sum(range(1000))


def test_busy_process_gets_one_report_naming_the_spinning_function(caplog):
    stop = threading.Event()
    t = threading.Thread(target=spin_forever_marker, args=(stop,), name="spinner")
    t.start()
    wd = CpuWatchdog(interval=0.15, threshold=0.5, samples=2, quiet=60)
    caplog.set_level(logging.WARNING, logger="mcpopus.diag")
    wd.start()
    try:
        deadline = time.time() + 5
        while wd.reports == 0 and time.time() < deadline:
            time.sleep(0.05)
        time.sleep(0.6)  # still spinning: the quiet period must stop a second report
    finally:
        stop.set(); wd.stop(); t.join(); wd.join()
    assert wd.reports == 1
    assert "spin_forever_marker" in caplog.text and "thread spinner" in caplog.text


def test_idle_process_is_not_reported(caplog):
    wd = CpuWatchdog(interval=0.1, threshold=0.5, samples=2, quiet=60)
    wd.start()
    time.sleep(0.8)
    wd.stop(); wd.join()
    assert wd.reports == 0
