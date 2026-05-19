"""Local TCP responder for the grott add-on.

Two modes, set by env var GROTT_SINK_MODE:

- ``discard`` (default): accept connections, read & discard, never reply.
  Used when ``forward_to_cloud=false`` and we just need grott's proxy
  forward to succeed so decode + MQTT publish run normally.

- ``capture``: log every byte received (hex + ASCII), with timestamps
  and per-connection IDs, and echo bytes back to the sender. Used for
  protocol reverse-engineering against OEM Growatt stacks (Vidagrid,
  etc.) that use a non-standard wire format.
"""

import datetime
import os
import socket
import sys
import threading


def hexdump(data: bytes) -> str:
    hexed = data.hex()
    ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return f"{hexed}   |{ascii_repr}|"


def _ts() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]


def handle_capture(conn: socket.socket, addr, cid: int) -> None:
    peer = f"{addr[0]}:{addr[1]}"
    print(f"[{_ts()}] [conn#{cid}] OPEN  from grott (representing dongle->upstream)", flush=True)
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            print(f"[{_ts()}] [conn#{cid}] RX {len(data)}B: {hexdump(data)}", flush=True)
            try:
                conn.sendall(data)  # echo back; dongle may treat as ACK
                print(f"[{_ts()}] [conn#{cid}] TX {len(data)}B (echo)", flush=True)
            except OSError as e:
                print(f"[{_ts()}] [conn#{cid}] TX failed: {e}", flush=True)
                break
    except OSError as e:
        print(f"[{_ts()}] [conn#{cid}] RX failed: {e}", flush=True)
    finally:
        print(f"[{_ts()}] [conn#{cid}] CLOSE", flush=True)
        try:
            conn.close()
        except OSError:
            pass


def handle_discard(conn: socket.socket, addr, cid: int) -> None:
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
    mode = os.environ.get("GROTT_SINK_MODE", "discard").strip().lower()
    handler = handle_capture if mode == "capture" else handle_discard

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)
    print(f"localsink mode={mode} listening on 127.0.0.1:{port}", flush=True)

    cid = 0
    while True:
        conn, addr = srv.accept()
        cid += 1
        threading.Thread(target=handler, args=(conn, addr, cid), daemon=True).start()


if __name__ == "__main__":
    main()
