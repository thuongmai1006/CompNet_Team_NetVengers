#!/usr/bin/env python3
import socket
import threading
import argparse
import sys

ENC = "utf-8"

def receiver(sock: socket.socket):
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                print("\n[disconnected]")
                break
            sys.stdout.write(data.decode(ENC))
            sys.stdout.flush()
    except Exception as e:
        print(f"\n[receiver error] {e}")
    finally:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        sock.close()

def main():
    ap = argparse.ArgumentParser(description="Simple chat client")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--username", "-u", default=None, help="Your nickname")
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((args.host, args.port))

    # Read initial prompt and send username
    prompt = sock.recv(1024).decode(ENC)
    if args.username:
        username = args.username
    else:
        username = input(prompt) or "guest"
    sock.sendall((username + "\n").encode(ENC))

    threading.Thread(target=receiver, args=(sock,), daemon=True).start()

    print("Connected. Type messages and press Enter. '/help' for commands.")
    try:
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            sock.sendall(line.encode(ENC))
            if line.strip().lower() == "/quit":
                break
    except KeyboardInterrupt:
        pass
    finally:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        sock.close()

if __name__ == "__main__":
    main()
