#!/usr/bin/env python3
"""Exercise Python socket timeout and close wakeup behavior."""

import os
import multiprocessing
import select
import socket
import sys
import threading
import time


def check_timeout():
    reader, writer = socket.socketpair()
    try:
        reader.settimeout(0.2)
        if os.get_blocking(reader.fileno()):
            raise AssertionError("settimeout() did not put fd in non-blocking mode")

        start = time.monotonic()
        try:
            reader.recv(1)
        except socket.timeout:
            elapsed = time.monotonic() - start
            if elapsed > 1.5:
                raise AssertionError(f"socket timeout took too long: {elapsed:.3f}s")
        else:
            raise AssertionError("idle timed recv unexpectedly succeeded")
    finally:
        reader.close()
        writer.close()


def check_close_wakeup():
    reader, writer = socket.socketpair()
    done = []

    def recv_loop():
        try:
            data = reader.recv(1)
            done.append(data)
        except OSError as exc:
            done.append(type(exc).__name__)

    try:
        thread = threading.Thread(target=recv_loop)
        thread.start()
        time.sleep(0.1)
        reader.close()
        thread.join(1.5)
        if thread.is_alive():
            raise AssertionError("closing a socket did not wake blocked recv thread")
    finally:
        writer.close()


def check_fork_child_close_wakeup():
    pid = os.fork()
    if pid == 0:
        try:
            check_close_wakeup()
        except BaseException as exc:
            print(f"fork-child-close-wakeup-failed: {exc}", file=sys.stderr)
            os._exit(1)
        os._exit(0)

    deadline = time.monotonic() + 3
    while True:
        done_pid, status = os.waitpid(pid, os.WNOHANG)
        if done_pid == pid:
            if status != 0:
                raise AssertionError(f"fork child failed with wait status {status}")
            return
        if time.monotonic() >= deadline:
            try:
                os.kill(pid, 9)
            finally:
                os.waitpid(pid, 0)
            raise AssertionError("fork child close wakeup hung")
        time.sleep(0.05)


def check_poll_queue_socket_teardown():
    sock, peer = socket.socketpair()
    sock.settimeout(5)
    stopq = multiprocessing.Queue()
    done = []

    def message_thread():
        poller = select.poll()
        poller.register(sock.fileno(), select.POLLIN)
        poller.register(stopq._reader.fileno(), select.POLLIN)
        while True:
            for fd, event in poller.poll():
                if fd == stopq._reader.fileno():
                    done.append("queue")
                    return
                if fd == sock.fileno():
                    if event & (select.POLLERR | select.POLLNVAL | select.POLLHUP):
                        done.append("socket-gone")
                        return
                    try:
                        if not sock.recv(1):
                            done.append("eof")
                            return
                    except OSError:
                        done.append("socket-error")
                        return

    thread = threading.Thread(target=message_thread)
    thread.daemon = True
    thread.start()
    time.sleep(0.1)
    sock.close()
    stopq.put(True)
    thread.join(1.5)
    try:
        stopq.close()
        stopq.join_thread()
    finally:
        peer.close()
    if thread.is_alive():
        raise AssertionError("poll/queue/socket teardown thread did not stop")
    if not done:
        raise AssertionError("poll/queue/socket teardown exited without a reason")


def check_poll_socket_close_wakeup():
    sock, peer = socket.socketpair()
    done = []

    def message_thread():
        poller = select.poll()
        poller.register(sock.fileno(), select.POLLIN)
        for _fd, event in poller.poll(2000):
            done.append(event)
            return
        done.append("timeout")

    thread = threading.Thread(target=message_thread)
    thread.daemon = True
    thread.start()
    time.sleep(0.1)
    sock.close()
    thread.join(1.5)
    peer.close()
    if thread.is_alive():
        raise AssertionError("closing a socket did not wake blocked poll thread")
    if done == ["timeout"]:
        raise AssertionError("poll waiter timed out instead of waking on socket close")
    if not done:
        raise AssertionError("poll waiter exited without a reason")


def main():
    check_timeout()
    check_close_wakeup()
    check_fork_child_close_wakeup()
    check_poll_socket_close_wakeup()
    check_poll_queue_socket_teardown()
    print("socket-timeout-ok")


if __name__ == "__main__":
    main()
