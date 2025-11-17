#!/usr/bin/env python3
import logging 
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
import socket
import threading
import argparse
import sys
from typing import Dict, Tuple

ENC = "utf-8"

class ClientInfo:
    def __init__(self, conn: socket.socket, addr: Tuple[str, int], username: str, room: str):
        self.conn = conn
        self.addr = addr
        self.username = username
        self.room = room
        

class ChatServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clients: Dict[socket.socket, ClientInfo] = {}
        self.lock = threading.RLock()
        self.admins = set(["admin"])

    def is_admin(self, username: str) -> bool:
        return username in self.admins
    
    def start(self):
        self.server.bind((self.host, self.port))
        self.server.listen(50)
        print(f"Chat server listening on {self.host}:{self.port}")
        try:
            while True:
                conn, addr = self.server.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            print("\nShutting down...")
        finally:
            with self.lock:
                for c in list(self.clients.keys()):
                    try:
                        c.shutdown(socket.SHUT_RDWR)
                        c.close()
                    except Exception:
                        pass
            self.server.close()

    def broadcast(self, room: str, msg: str, exclude: socket.socket = None):
        with self.lock:
            for c, info in list(self.clients.items()):
                if info.room == room and c is not exclude:
                    try:
                        c.sendall((msg + "\n").encode(ENC))
                    except Exception:
                        pass

    def system(self, room: str, text: str):
        self.broadcast(room, f"[system] {text}")

    def private_msg(self, to_username: str, text: str, from_user: str):
        with self.lock:
            for c, info in self.clients.items():
                if info.username == to_username:
                    try:
                        c.sendall((f"[whisper from {from_user}] {text}\n").encode(ENC))
                        return True
                    except Exception:
                        return False
        return False

    def list_users(self, room: str):
        with self.lock:
            return sorted([info.username for info in self.clients.values() if info.room == room])

    def handle_client(self, conn: socket.socket, addr: Tuple[str, int]):
        def recvline() -> str:
            data = b""
            while True:
                ch = conn.recv(1)
                if not ch:
                    return ""
                if ch == b"\n":
                    return data.decode(ENC).rstrip("\r")
                data += ch

        try:
            conn.sendall(b"Enter username: ")
            username = recvline().strip()
            if not username:
                conn.close()
                return

            # Ensure unique username
            with self.lock:
                taken = {info.username for info in self.clients.values()}
                base_name = username
                i = 2
                while username in taken:
                    username = f"{base_name}{i}"
                    i += 1

            # Default room
            room = "lobby"
            logging.info(f"Client connected from {addr}: username={username}, room={room}")

            with self.lock:
                self.clients[conn] = ClientInfo(conn, addr, username, room)

            conn.sendall(f"Welcome, {username}! Type /help for commands.\n".encode(ENC))
            self.system(room, f"{username} joined {room}")
            self.broadcast(room, f"[{username}] joined.", exclude=conn)

            while True:
                line = recvline()
                if line == "":
                    break
                line = line.strip()
                if not line:
                    continue

                if line.startswith("/"):
                    parts = line.split(" ", 2)
                    cmd = parts[0].lower()
                    if cmd == "/help":
                        help_text = (
                            "Commands:\n"
                            "/help                 Show this help\n"
                            "/join ROOM            Join or create ROOM\n"
                            "/lobby                Go Back To Lobby\n"
                            "/list                 List users in your room\n"
                            "/w USER MESSAGE       Whisper/private message USER\n"
                            "/quit                 Disconnect\n"
                        )
                        conn.sendall((help_text).encode(ENC))
                    elif cmd == "/join":
                        if len(parts) < 2 or not parts[1].strip():
                            conn.sendall(b"Usage: /join ROOM\n")
                            continue
                        new_room = parts[1].strip()
                        with self.lock:
                            info = self.clients.get(conn)
                            old_room = info.room
                            if old_room != new_room:
                                self.system(old_room, f"{info.username} left {old_room}")
                                info.room = new_room
                                conn.sendall(f"Joined room {new_room}\n".encode(ENC))
                                self.system(new_room, f"{info.username} joined {new_room}")
                    elif cmd == "/lobby": 
                        with self.lock:
                            info = self.clients.get(conn)
                            old_room = info.room
                            new_room = "lobby"
                            if old_room != new_room:
                                self.system(old_room, f"{info.username} left {old_room}")
                                info.room = new_room
                                conn.sendall(f"Joined room {new_room}\n".encode(ENC))
                                self.system(new_room, f"{info.username} joined {new_room}")
                    elif cmd == "/list":
                        with self.lock:
                            info = self.clients.get(conn)
                            users = self.list_users(info.room)
                        conn.sendall(("Users: " + ", ".join(users) + "\n").encode(ENC))
                    elif cmd == "/w":
                        if len(parts) < 3:
                            conn.sendall(b"Usage: /w USER MESSAGE\n")
                            continue
                        to_user, text = parts[1], parts[2]
                        with self.lock:
                            info = self.clients.get(conn)
                            ok = self.private_msg(to_user, text, info.username)
                        if not ok:
                            conn.sendall(f"User {to_user} not found or delivery failed.\n".encode(ENC))
                    elif cmd == "/quit":
                        break

                    elif cmd == "/shutdown":
                        with self.lock:
                            info = self.clients.get(conn)
                            if not self.is_admin(info.username):
                                conn.sendall(b"You do not have permission for /shutdown\n")
                                continue
                            conn.sendall(b"Shutting down server...\n")
                            for c in list(self.clients.keys()):
                                try:
                                    c.shutdown(socket.SHUT_RDWR)
                                    c.close()
                                except Exception:
                                    pass
                        self.server.close()
                    else:
                        conn.sendall(b"Unknown command. Try /help\n")
                else:
                    with self.lock:
                        info = self.clients.get(conn)
                        room = info.room
                        name = info.username
                    logging.info(f"[{room}] {name}: {line}")
                    self.broadcast(room, f"[{name}] {line}")
        except Exception as e:
            try:
                conn.sendall(f"[system] error: {e}\n".encode(ENC))
            except Exception:
                pass
        finally:
            with self.lock:
                info = self.clients.pop(conn, None)
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            conn.close()
            if info:
                logging.info(f"Client disconnected: {info.username} from {info.addr}, last room={info.room}")
                self.system(info.room, f"{info.username} disconnected")
                

def main():
    ap = argparse.ArgumentParser(description="Simple multi-room chat server")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()
    server = ChatServer(args.host, args.port)
    server.start()

if __name__ == "__main__":
    main()
