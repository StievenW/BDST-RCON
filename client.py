import os
import sys


try:
    import config
except (ModuleNotFoundError, FileNotFoundError):
    print("config.py not found.")
    answer = input("Create a new config.py? (y/n): ").strip().lower()
    if answer != 'y':
        print("Exiting program because config.py is missing.")
        os._exit(0)
    host = input("Host [default: 127.0.0.1]: ").strip() or '127.0.0.1'
    port_input = input("Port [default: 25575]: ").strip()
    port = int(port_input) if port_input else 25575
    password = input("Password [default: yourpassword]: ").strip() or 'yourpassword'
    with open('config.py', 'w', encoding='utf-8') as f:
        f.write(f"# config.py\nHOST = '{host}'\nPORT = {port}\nPASSWORD = '{password}'\n")
    print("config.py created successfully. Please restart the program.")
    os._exit(0)

import socket
import struct

def send_packet(sock, packet_type, request_id, body=''):
    body_bytes = body.encode('utf-8')
    size = len(body_bytes) + 14
    packet = struct.pack('<III', size - 4, request_id, packet_type) + body_bytes + b'\x00\x00'
    sock.sendall(packet)

def recv_packet(sock):
    def recv_bytes(num_bytes):
        buffer = b''
        while len(buffer) < num_bytes:
            fragment = sock.recv(num_bytes - len(buffer))
            if not fragment:

                return None
            buffer += fragment
        return buffer
    size_bytes = recv_bytes(4)
    if size_bytes is None:
        return None, None, None
    size = struct.unpack('<I', size_bytes)[0]
    request_id_bytes = recv_bytes(4)
    if request_id_bytes is None:
        return None, None, None
    request_id = struct.unpack('<I', request_id_bytes)[0]
    packet_type_bytes = recv_bytes(4)
    if packet_type_bytes is None:
        return None, None, None
    packet_type = struct.unpack('<I', packet_type_bytes)[0]
    body_bytes = recv_bytes(size - 10)
    if body_bytes is None:
        return None, None, None
    recv_bytes(2)
    body = body_bytes.decode('utf-8', errors='replace')
    return request_id, packet_type, body

def mc_color_to_ansi(text):
    import re
    MC_COLOR_TO_ANSI = {
        '0': '\033[30m', '1': '\033[34m', '2': '\033[32m', '3': '\033[36m',
        '4': '\033[31m', '5': '\033[35m', '6': '\033[33m', '7': '\033[37m',
        '8': '\033[90m', '9': '\033[94m', 'a': '\033[92m', 'b': '\033[96m',
        'c': '\033[91m', 'd': '\033[95m', 'e': '\033[93m', 'f': '\033[97m',
        'r': '\033[0m', 'l': '\033[1m', 'n': '\033[4m', 'o': '\033[3m', 'm': '\033[9m',
    }
    def repl(match):
        code = match.group(1).lower()
        return MC_COLOR_TO_ANSI.get(code, '')
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if '§' in line:
            line = re.sub(r'§([0-9a-frlonmk])', repl, line, flags=re.IGNORECASE)
        line += '\033[0m'
        lines[i] = line
    text = '\n'.join(lines)
    def colorize_log(match):
        timestamp = match.group(1)
        level = match.group(2).upper()
        rest = match.group(3)
        ts_col = '\033[96m' + timestamp + '\033[0m'
        if level == 'ERROR':
            lvl_col = '\033[91m' + level + '\033[0m'
        elif level == 'INFO':
            lvl_col = '\033[97m' + level + '\033[0m'
        elif level in ('WARN', 'WARNING'):
            lvl_col = '\033[93m' + level + '\033[0m'
        else:
            lvl_col = level
        return f"[{ts_col} {lvl_col}]{rest}"
    text = re.sub(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}:\d{3}) (ERROR|INFO|WARN|WARNING)](.*)', colorize_log, text)
    return text

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((config.HOST, config.PORT))
        send_packet(sock, 3, 1, config.PASSWORD)
        result = recv_packet(sock)
        if result == (None, None, None):
            print("Connection closed by server during auth.")
            return
        req_id, pkt_type, body = result
        if pkt_type != 2 or req_id == -1:
            print("Auth failed")
            return
        print("Auth success")
        while True:
            cmd = input("RCON> ")
            if cmd.lower() in ['exit', 'quit']:
                break
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock2.connect((config.HOST, config.PORT))
                send_packet(sock2, 3, 1, config.PASSWORD)
                result2 = recv_packet(sock2)
                if result2 == (None, None, None):
                    print("Connection closed by server during auth.")
                    continue
                req_id2, pkt_type2, body2 = result2
                if pkt_type2 != 2 or req_id2 == -1:
                    print("Auth failed")
                    continue
                send_packet(sock2, 2, 2, cmd)
                result2 = recv_packet(sock2)
                if result2 == (None, None, None):
                    print("Connection closed by server.")
                    continue
                req_id2, pkt_type2, body2 = result2
                if body2:
                    print(mc_color_to_ansi(body2))
            except Exception as e:
                print(f"Error: {e}")
            finally:
                sock2.close()
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()