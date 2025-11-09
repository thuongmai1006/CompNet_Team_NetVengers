#!/usr/bin/env python3
import logging 
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
import socket
import threading
import argparse
import sys
import time
from typing import Dict, Tuple

ENC = "utf-8"

class NetworkStats:
    """Track network statistics for monitoring"""
    def __init__(self):
        self.bytes_sent = 0
        self.bytes_received = 0
        self.messages_sent = 0
        self.messages_received = 0
        self.user_messages_sent = 0  # Only count actual user chat messages
        self.user_messages_received = 0
        self.start_time = time.time()
        self.lock = threading.Lock()
    
    def record_sent(self, num_bytes, is_user_message=False):
        with self.lock:
            self.bytes_sent += num_bytes
            self.messages_sent += 1
            if is_user_message:
                self.user_messages_sent += 1
    
    def record_received(self, num_bytes, is_user_message=False):
        with self.lock:
            self.bytes_received += num_bytes
            self.messages_received += 1
            if is_user_message:
                self.user_messages_received += 1
    
    def get_stats(self):
        with self.lock:
            uptime = time.time() - self.start_time
            return {
                'uptime_seconds': uptime,
                'bytes_sent': self.bytes_sent,
                'bytes_received': self.bytes_received,
                'messages_sent': self.messages_sent,
                'messages_received': self.messages_received,
                'user_messages_sent': self.user_messages_sent,
                'user_messages_received': self.user_messages_received,
                'throughput_sent': self.bytes_sent / uptime if uptime > 0 else 0,
                'throughput_received': self.bytes_received / uptime if uptime > 0 else 0,
                'msg_rate': self.messages_sent / uptime if uptime > 0 else 0
            }
    
    def print_stats(self):
        stats = self.get_stats()
        uptime_mins = stats['uptime_seconds'] / 60
        print("\n" + "="*50)
        print("NETWORK STATISTICS")
        print("="*50)
        print(f"Uptime: {uptime_mins:.2f} minutes")
        print(f"Bytes Sent: {stats['bytes_sent']:,} ({stats['bytes_sent']/1024:.2f} KB)")
        print(f"Bytes Received: {stats['bytes_received']:,} ({stats['bytes_received']/1024:.2f} KB)")
        print(f"Chat Messages Sent: {stats['user_messages_sent']:,}")
        print(f"Chat Messages Received: {stats['user_messages_received']:,}")
        print(f"Throughput (sent): {stats['throughput_sent']:.2f} bytes/sec")
        print(f"Throughput (received): {stats['throughput_received']:.2f} bytes/sec")
        if stats['user_messages_sent'] > 0:
            print(f"Message Rate: {stats['user_messages_sent'] / stats['uptime_seconds']:.2f} msg/sec")
        print("="*50 + "\n")

class ClientInfo:
    def __init__(self, conn: socket.socket, addr: Tuple[str, int], username: str, room: str):
        self.conn = conn
        self.addr = addr
        self.username = username
        self.room = room
        self.connected_at = time.time()
        self.stats = NetworkStats()  # Per-client statistics

class ChatServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clients: Dict[socket.socket, ClientInfo] = {}
        self.lock = threading.RLock()
        self.server_stats = NetworkStats()  # Global server statistics

    def start(self):
        self.server.bind((self.host, self.port))
        self.server.listen(50)
        print(f"Chat server listening on {self.host}:{self.port}")
        
        # Start statistics reporter thread
        stats_thread = threading.Thread(target=self.stats_reporter, daemon=True)
        stats_thread.start()
        
        try:
            while True:
                conn, addr = self.server.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            print("\nShutting down...")
            self.print_final_stats()
        finally:
            with self.lock:
                for c in list(self.clients.keys()):
                    try:
                        c.shutdown(socket.SHUT_RDWR)
                        c.close()
                    except Exception:
                        pass
            self.server.close()

    def stats_reporter(self):
        """Periodically print statistics every 60 seconds"""
        while True:
            time.sleep(60)
            with self.lock:
                num_clients = len(self.clients)
            logging.info(f"Active connections: {num_clients}")
            self.server_stats.print_stats()

    def print_final_stats(self):
        """Print final statistics on shutdown"""
        print("\n" + "="*50)
        print("FINAL SERVER STATISTICS")
        print("="*50)
        self.server_stats.print_stats()
        
        with self.lock:
            if self.clients:
                print("\nPER-CLIENT STATISTICS:")
                print("-"*50)
                for info in self.clients.values():
                    duration = time.time() - info.connected_at
                    print(f"\nUser: {info.username} (connected {duration/60:.1f} minutes)")
                    stats = info.stats.get_stats()
                    print(f"  Sent: {stats['bytes_sent']:,} bytes")
                    print(f"  Received: {stats['bytes_received']:,} bytes")
                    print(f"  Chat Messages Sent: {stats['user_messages_sent']}")
                    print(f"  Chat Messages Received: {stats['user_messages_received']}")

    def broadcast(self, room: str, msg: str, exclude: socket.socket = None, is_user_message=False, include_sender=False):
        """
        Broadcast message to all clients in a room.
        If include_sender=True, also send to the original sender (for echo)
        """
        data = (msg + "\n").encode(ENC)
        with self.lock:
            for c, info in list(self.clients.items()):
                # Send to everyone in room, including sender if include_sender=True
                if info.room == room and (include_sender or c is not exclude):
                    try:
                        c.sendall(data)
                        # Track statistics
                        info.stats.record_sent(len(data), is_user_message=is_user_message)
                        self.server_stats.record_sent(len(data), is_user_message=is_user_message)
                    except Exception:
                        pass

    def system(self, room: str, text: str):
        self.broadcast(room, f"[system] {text}")

    def private_msg(self, to_username: str, text: str, from_user: str):
        data = (f"[whisper from {from_user}] {text}\n").encode(ENC)
        with self.lock:
            for c, info in self.clients.items():
                if info.username == to_username:
                    try:
                        c.sendall(data)
                        info.stats.record_sent(len(data), is_user_message=True)
                        self.server_stats.record_sent(len(data), is_user_message=True)
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
                    line = data.decode(ENC).rstrip("\r")
                    # Track received bytes (but don't count as message yet)
                    byte_count = len(data) + 1
                    with self.lock:
                        if conn in self.clients:
                            self.clients[conn].stats.bytes_received += byte_count
                    self.server_stats.bytes_received += byte_count
                    return line
                data += ch

        try:
            prompt = b"Enter username: "
            conn.sendall(prompt)
            
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

            welcome = f"Welcome, {username}! Type /help for commands.\n".encode(ENC)
            conn.sendall(welcome)
            
            # Don't broadcast join messages to make stats cleaner
            # Just log it
            logging.info(f"{username} joined {room}")

            while True:
                line = recvline()
                if line == "":
                    break
                line = line.strip()
                if not line:
                    continue

                # Only count non-command messages in statistics
                is_command = line.startswith("/")
                
                if not is_command:
                    # Mark that we received a user message (not a command)
                    with self.lock:
                        if conn in self.clients:
                            self.clients[conn].stats.messages_received += 1
                    self.server_stats.messages_received += 1

                if is_command:
                    parts = line.split(" ", 2)
                    cmd = parts[0].lower()
                    if cmd == "/help":
                        help_text = (
                            "Commands:\n"
                            "/help                 Show this help\n"
                            "/join ROOM            Join or create ROOM\n"
                            "/list                 List users in your room\n"
                            "/w USER MESSAGE       Whisper/private message USER\n"
                            "/stats                Show your connection statistics\n"
                            "/quit                 Disconnect\n"
                        )
                        data = help_text.encode(ENC)
                        conn.sendall(data)
                        with self.lock:
                            if conn in self.clients:
                                self.clients[conn].stats.bytes_sent += len(data)
                                self.clients[conn].stats.messages_sent += 1
                        self.server_stats.bytes_sent += len(data)
                        self.server_stats.messages_sent += 1
                    elif cmd == "/stats":
                        # Show user their own statistics
                        with self.lock:
                            info = self.clients.get(conn)
                            stats = info.stats.get_stats()
                            duration = time.time() - info.connected_at
                        
                        stats_text = (
                            f"\n{'='*40}\n"
                            f"YOUR CONNECTION STATISTICS\n"
                            f"{'='*40}\n"
                            f"Connected for: {duration/60:.2f} minutes\n"
                            f"Total Bytes Sent: {stats['bytes_sent']:,} ({stats['bytes_sent']/1024:.2f} KB)\n"
                            f"Total Bytes Received: {stats['bytes_received']:,} ({stats['bytes_received']/1024:.2f} KB)\n"
                            f"Total Messages Sent: {stats['messages_sent']:,}\n"
                            f"Total Messages Received: {stats['messages_received']:,}\n"
                            f"User Chat Messages Sent: {stats['user_messages_sent']:,}\n"
                            f"User Chat Messages Received: {stats['user_messages_received']:,}\n"
                            f"{'='*40}\n"
                        )
                        data = stats_text.encode(ENC)
                        conn.sendall(data)
                        with self.lock:
                            if conn in self.clients:
                                self.clients[conn].stats.bytes_sent += len(data)
                                self.clients[conn].stats.messages_sent += 1
                        self.server_stats.bytes_sent += len(data)
                        self.server_stats.messages_sent += 1
                    elif cmd == "/join":
                        if len(parts) < 2 or not parts[1].strip():
                            msg = b"Usage: /join ROOM\n"
                            conn.sendall(msg)
                            with self.lock:
                                if conn in self.clients:
                                    self.clients[conn].stats.bytes_sent += len(msg)
                                    self.clients[conn].stats.messages_sent += 1
                            self.server_stats.bytes_sent += len(msg)
                            self.server_stats.messages_sent += 1
                            continue
                        new_room = parts[1].strip()
                        with self.lock:
                            info = self.clients.get(conn)
                            old_room = info.room
                            if old_room != new_room:
                                info.room = new_room
                                msg = f"Joined room {new_room}\n".encode(ENC)
                                conn.sendall(msg)
                                self.clients[conn].stats.bytes_sent += len(msg)
                                self.clients[conn].stats.messages_sent += 1
                                self.server_stats.bytes_sent += len(msg)
                                self.server_stats.messages_sent += 1
                                logging.info(f"{info.username} moved from {old_room} to {new_room}")
                    elif cmd == "/list":
                        with self.lock:
                            info = self.clients.get(conn)
                            users = self.list_users(info.room)
                        msg = ("Users: " + ", ".join(users) + "\n").encode(ENC)
                        conn.sendall(msg)
                        with self.lock:
                            if conn in self.clients:
                                self.clients[conn].stats.bytes_sent += len(msg)
                                self.clients[conn].stats.messages_sent += 1
                        self.server_stats.bytes_sent += len(msg)
                        self.server_stats.messages_sent += 1
                    elif cmd == "/w":
                        if len(parts) < 3:
                            msg = b"Usage: /w USER MESSAGE\n"
                            conn.sendall(msg)
                            with self.lock:
                                if conn in self.clients:
                                    self.clients[conn].stats.bytes_sent += len(msg)
                                    self.clients[conn].stats.messages_sent += 1
                            self.server_stats.bytes_sent += len(msg)
                            self.server_stats.messages_sent += 1
                            continue
                        to_user, text = parts[1], parts[2]
                        with self.lock:
                            info = self.clients.get(conn)
                            # Mark as user message for sender
                            info.stats.user_messages_sent += 1
                            ok = self.private_msg(to_user, text, info.username)
                        if not ok:
                            msg = f"User {to_user} not found or delivery failed.\n".encode(ENC)
                            conn.sendall(msg)
                            with self.lock:
                                if conn in self.clients:
                                    self.clients[conn].stats.bytes_sent += len(msg)
                                    self.clients[conn].stats.messages_sent += 1
                            self.server_stats.bytes_sent += len(msg)
                            self.server_stats.messages_sent += 1
                    elif cmd == "/quit":
                        break
                    else:
                        msg = b"Unknown command. Try /help\n"
                        conn.sendall(msg)
                        with self.lock:
                            if conn in self.clients:
                                self.clients[conn].stats.bytes_sent += len(msg)
                                self.clients[conn].stats.messages_sent += 1
                        self.server_stats.bytes_sent += len(msg)
                        self.server_stats.messages_sent += 1
                else:
                    # Regular chat message - broadcast to ALL users in room INCLUDING sender
                    with self.lock:
                        info = self.clients.get(conn)
                        room = info.room
                        name = info.username
                        # Mark as user message sent
                        info.stats.user_messages_sent += 1
                    
                    logging.info(f"[{room}] {name}: {line}")
                    
                    # Broadcast to everyone INCLUDING sender (echo back)
                    # This makes sent/received counts symmetric
                    self.broadcast(room, f"[{name}] {line}", include_sender=True, is_user_message=True)
                    
        except Exception as e:
            try:
                msg = f"[system] error: {e}\n".encode(ENC)
                conn.sendall(msg)
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
                duration = time.time() - info.connected_at
                logging.info(f"Client disconnected: {info.username} from {info.addr}, "
                           f"last room={info.room}, connected for {duration/60:.1f} minutes")
                

def main():
    ap = argparse.ArgumentParser(description="Simple multi-room chat server with network statistics")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()
    server = ChatServer(args.host, args.port)
    server.start()

if __name__ == "__main__":
    main()