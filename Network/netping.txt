from socket import *
import os, sys, struct, time, select

ICMP_ECHO_REQUEST = 8

def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    for count in range(0, countTo, 2):
        thisVal = string[count + 1] * 256 + string[count]
        csum += thisVal
        csum &= 0xffffffff
    if countTo < len(string):
        csum += string[-1]
        csum &= 0xffffffff
    csum = (csum >> 16) + (csum & 0xffff)
    csum += (csum >> 16)
    answer = ~csum & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def send_one_ping(sock, dest_addr, ID):
    dest_addr = gethostbyname(dest_addr)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, ID, 1)
    data = struct.pack("d", time.time())
    my_checksum = checksum(header + data)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, htons(my_checksum), ID, 1)
    packet = header + data
    sock.sendto(packet, (dest_addr, 1))

def receive_one_ping(sock, ID, timeout):
    time_left = timeout
    while True:
        start_select = time.time()
        ready = select.select([sock], [], [], time_left)
        how_long_in_select = (time.time() - start_select)
        if ready[0] == []:  # Timeout
            return None
        time_received = time.time()
        rec_packet, addr = sock.recvfrom(1024)
        icmp_header = rec_packet[20:28]
        type, code, checksum, packet_id, sequence = struct.unpack("bbHHh", icmp_header)
        if packet_id == ID:
            bytes_in_double = struct.calcsize("d")
            time_sent = struct.unpack("d", rec_packet[28:28 + bytes_in_double])[0]
            return time_received - time_sent
        time_left -= how_long_in_select
        if time_left <= 0:
            return None

def do_one_ping(dest_addr, timeout=1):
    icmp = getprotobyname("icmp")
    sock = socket(AF_INET, SOCK_RAW, icmp)
    my_id = os.getpid() & 0xFFFF
    send_one_ping(sock, dest_addr, my_id)
    delay = receive_one_ping(sock, my_id, timeout)
    sock.close()
    return delay

def ping(host):
    for i in range(4):
        delay = do_one_ping(host)
        if delay is None:
            print("Request timed out.")
        else:
            print(f"Reply from {host}: time={delay*1000:.2f} ms")
        time.sleep(1)

if __name__ == '__main__':
    ping("8.8.8.8")
