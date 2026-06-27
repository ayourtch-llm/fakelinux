#!/usr/bin/env python3
"""Exercise Python multiprocessing's AF_UNIX manager listener."""

from multiprocessing.managers import SyncManager


def main():
    manager = SyncManager()
    manager.start()
    try:
        address = manager.address
        if not isinstance(address, str):
            raise AssertionError(f"expected AF_UNIX address, got {address!r}")
        if not address.startswith("/tmp/pymp-"):
            raise AssertionError(f"unexpected manager address {address!r}")

        queue = manager.Queue()
        queue.put(("fakelinux", 42))
        if queue.get(timeout=5) != ("fakelinux", 42):
            raise AssertionError("manager queue round-trip failed")

        print(f"manager-ok {address}")
    finally:
        manager.shutdown()


if __name__ == "__main__":
    main()
