import subprocess
import threading
import socket
import queue
import struct
import config
import ftfy
import os
import sys
import re

os.environ["PYTHONIOENCODING"] = "utf-8"
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

RCON_PACKET_TYPE = {
    'SERVERDATA_AUTH': 3,
    'SERVERDATA_AUTH_RESPONSE': 2,
    'SERVERDATA_EXECCOMMAND': 2,
    'SERVERDATA_RESPONSE_VALUE': 0
}

MC_COLOR_TO_ANSI = {
    '0': '\033[30m', '1': '\033[34m', '2': '\033[32m', '3': '\033[36m',
    '4': '\033[31m', '5': '\033[35m', '6': '\033[33m', '7': '\033[37m',
    '8': '\033[90m', '9': '\033[94m', 'a': '\033[92m', 'b': '\033[96m',
    'c': '\033[91m', 'd': '\033[95m', 'e': '\033[93m', 'f': '\033[97m',
    'r': '\033[0m', 'l': '\033[1m', 'n': '\033[4m', 'o': '\033[3m', 'm': '\033[9m',
}

def mc_color_to_ansi(text):
    def repl(match):
        code = match.group(1).lower()
        return MC_COLOR_TO_ANSI.get(code, '')
    return re.sub(r'§([0-9a-frlonmk])', repl, text, flags=re.IGNORECASE) + '\033[0m'

def send_packet(client_socket, packet_type, request_id, body=''):
    body_bytes = body.encode('utf-8')
    size = len(body_bytes) + 14
    packet = struct.pack('<III', size - 4, request_id, packet_type) + body_bytes + b'\x00\x00'
    client_socket.sendall(packet)

def recv_packet(client_socket):
    def recv_bytes(sock, num_bytes):
        buffer = b''
        while len(buffer) < num_bytes:
            fragment = sock.recv(num_bytes - len(buffer))
            if not fragment:
                raise ConnectionResetError("Connection closed")
            buffer += fragment
        return buffer
    size = struct.unpack('<I', recv_bytes(client_socket, 4))[0]
    request_id = struct.unpack('<I', recv_bytes(client_socket, 4))[0]
    packet_type = struct.unpack('<I', recv_bytes(client_socket, 4))[0]
    body_bytes = recv_bytes(client_socket, size - 10)
    recv_bytes(client_socket, 2)
    body = ftfy.fix_text(body_bytes.decode('utf-8', errors='replace'))
    return request_id, packet_type, body

def client_handler(client_socket, client_address, input_queue):
    print(f"New connection from {client_address}")
    try:
        request_id, packet_type, _ = recv_packet(client_socket)
        if packet_type == RCON_PACKET_TYPE['SERVERDATA_AUTH']:
            auth_data = _
            if auth_data == config.PASSWORD:
                send_packet(client_socket, RCON_PACKET_TYPE['SERVERDATA_AUTH_RESPONSE'], request_id)
            else:
                send_packet(client_socket, RCON_PACKET_TYPE['SERVERDATA_AUTH_RESPONSE'], request_id, '')
                print(f"Authentication failed from {client_address}")
                client_socket.close()
                return
        else:
            print(f"Invalid authentication request from {client_address}")
            client_socket.close()
            return
        while True:
            request_id, packet_type, command_data = recv_packet(client_socket)
            if packet_type == RCON_PACKET_TYPE['SERVERDATA_EXECCOMMAND'] and command_data:
                print(f"Received command from {client_address}")
                input_queue.put(command_data)
                send_packet(client_socket, RCON_PACKET_TYPE['SERVERDATA_RESPONSE_VALUE'], request_id)
            else:
                break
    except ConnectionResetError:
        print(f"Connection lost from {client_address}")
    finally:
        client_socket.close()

def rcon_server(input_queue):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((config.HOST, config.PORT))
    server_socket.listen(5)
    print(f"RCON server listening on {config.HOST}:{config.PORT}")
    try:
        while True:
            client_sock, client_addr = server_socket.accept()
            client_thread = threading.Thread(target=client_handler, args=(client_sock, client_addr, input_queue))
            client_thread.daemon = True
            client_thread.start()
    finally:
        server_socket.close()

def run_server(input_queue):
    proc = subprocess.Popen(
        "bedrock_server.exe",
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        universal_newlines=True,
        encoding='utf-8'
    )
    output_thread = threading.Thread(target=read_output, args=(proc,))
    output_thread.daemon = True
    output_thread.start()
    while True:
        try:
            command = input_queue.get()
            if command is None:
                break
            if proc.poll() is not None:
                os._exit(0)
            proc.stdin.write(command + "\n")
            proc.stdin.flush()
        except RuntimeError as e:
            print(f"Error while sending command: {e}")
            os._exit(0)
        except Exception as e:
            print(f"Unknown command: {command}. Please check that the command exists and that you have permission to use it.")
            try:
                fixed_command = ftfy.fix_text(command)
                proc.stdin.write(fixed_command + "\n")
                proc.stdin.flush()
            except Exception:
                print(f"Unknown command: {command}. Please check that the command exists and that you have permission to use it.")
    proc.terminate()
    proc.wait()
    os._exit(0)

def read_output(proc):
    server_running = False
    while True:
        line = proc.stdout.readline()
        if line:
            fixed_line = ftfy.fix_text(line.strip())
            print(mc_color_to_ansi(fixed_line))
            if "Starting Server" in line:
                if not server_running:
                    print("Server is starting...")
                    server_running = True
            elif "Server started." in line:
                if server_running:
                    print("Server has started.")
                    server_running = False
            elif "Quit correctly" in line:
                if not server_running:
                    print("Server stopped correctly.")
            elif "Stopping server..." in line:
                print("Stopping server...")
        else:
            break

def stop_server(input_queue):
    input_queue.put("stop")
    input_queue.put("stop")

def start_server(input_queue):
    server_thread = threading.Thread(target=run_server, args=(input_queue,))
    server_thread.daemon = True
    server_thread.start()

if __name__ == '__main__':
    input_queue = queue.Queue()
    rcon_thread = threading.Thread(target=rcon_server, args=(input_queue,))
    rcon_thread.daemon = True
    rcon_thread.start()
    start_server(input_queue)
    try:
        while True:
            command = input()
            if command.lower() in ['exit', 'quit']:
                stop_server(input_queue)
                break
            input_queue.put(command)
    except KeyboardInterrupt:
        stop_server(input_queue)
    os._exit(0)
