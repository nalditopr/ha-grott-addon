"""Tiny TCP accept-and-discard sink used when forward_to_cloud is disabled.

Grott proxy mode requires a reachable upstream; without one, it drops the
dongle connection before decoding. We point grott at this sink so the
forward succeeds (silently swallowing the bytes) and decode + MQTT publish
run normally. We never write back — the inverter doesn't get cloud commands,
but it doesn't need to for local-only operation.
"""

import socket
import sys
import threading


def handle(conn: socket.socket) -> None:
    try:
        while conn.recv(4096):
            pass
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5280
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)
    print(f"localsink listening on 127.0.0.1:{port}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
