"""Replay the pseudonymized honeypot copy into analysisd, as if logcollector had read it.

Runs inside the manager container (./hp wazuh load), with the manager's own Python:
  python3 -I inject.py LOCATION < cowrie-2026-11-11.json
Each line goes to the analysis queue as a localfile message (type 1) from LOCATION. The JSON
decoder then turns its keys into data.* fields. A short pause every 200 lines keeps the
datagram queue from dropping messages.
"""
import socket
import sys
import time

QUEUE = "/var/ossec/queue/sockets/queue"


def main():
    location = sys.argv[1]
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.connect(QUEUE)
    n = 0
    for line in sys.stdin.buffer:
        line = line.strip()
        if not line:
            continue
        sock.send(b"1:" + location.encode() + b":" + line)
        n += 1
        if n % 200 == 0:
            time.sleep(0.05)
    print(n)


if __name__ == "__main__":
    main()
