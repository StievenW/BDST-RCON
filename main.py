import tkinter as tk
from tkinter import scrolledtext
import subprocess
import threading
import socket
import queue
import struct
import config

# RCON Packet Types
RCON_PACKET_TYPE = {
    'SERVERDATA_AUTH': 3,
    'SERVERDATA_AUTH_RESPONSE': 2,
    'SERVERDATA_EXECCOMMAND': 2,
    'SERVERDATA_RESPONSE_VALUE': 0
}

def send_packet(client_socket, packet_type, request_id, body=''):
    size = len(body) + 14
    packet = struct.pack(
        '<III', size - 4, request_id, packet_type
    ) + body.encode('ascii') + b'\x00\x00'
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
    body = recv_bytes(client_socket, size - 10).decode('ascii')
    recv_bytes(client_socket, 2)
    
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
                print(f"Received command from {client_address}: {command_data}")
                input_queue.put(command_data)
                send_packet(client_socket, RCON_PACKET_TYPE['SERVERDATA_RESPONSE_VALUE'], request_id, f"Executed: {command_data}")
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

def run_server(input_queue, log_box, root):
    proc = subprocess.Popen(
        "bedrock_server.exe",
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        universal_newlines=True
    )

    output_thread = threading.Thread(target=read_output, args=(proc, log_box, root))
    output_thread.daemon = True
    output_thread.start()

    while True:
        command = input_queue.get()
        if command is None:
            break
        proc.stdin.write(command + "\n")
        proc.stdin.flush()

    proc.terminate()

def read_output(proc, log_box, root):
    while True:
        line = proc.stdout.readline()
        if line:
            root.after(0, update_log_text, log_box, line)
        else:
            break

def update_log_text(log_box, line):
    log_box.configure(state='normal')
    log_box.insert(tk.END, line)
    log_box.configure(state='disabled')
    log_box.yview(tk.END)

def create_gui(input_queue):
    root = tk.Tk()
    root.title("Bedrock Server Console")

    # Apply dark theme
    root.configure(bg='#2e2e2e')
    root.option_add('*TButton*font', 'Helvetica 10')
    root.option_add('*TButton*background', '#3e3e3e')
    root.option_add('*TButton*foreground', 'white')
    root.option_add('*TButton*highlightBackground', '#2e2e2e')
    root.option_add('*TButton*highlightColor', 'black')
    root.option_add('*TLabel*foreground', 'white')
    root.option_add('*TLabel*background', '#2e2e2e')
    root.option_add('*TEntry*background', '#3e3e3e')
    root.option_add('*TEntry*foreground', 'white')

    log_box = scrolledtext.ScrolledText(root, state='disabled', height=20, width=120, bg='#1e1e1e', fg='white', insertbackground='white')
    log_box.configure(font='TkFixedFont')
    log_box.pack(padx=10, pady=10)

    cmd_input = tk.Entry(root, width=100, bg='#3e3e3e', fg='white', insertbackground='white')
    cmd_input.pack(padx=10, pady=5)

    def handle_send():
        command = cmd_input.get()
        input_queue.put(command)
        cmd_input.delete(0, tk.END)

    send_button = tk.Button(root, text="Send Command", command=handle_send)
    send_button.pack(side=tk.LEFT, padx=10)

    exit_button = tk.Button(root, text="Exit", command=root.destroy)
    exit_button.pack(side=tk.RIGHT, padx=10)

    server_thread = threading.Thread(target=run_server, args=(input_queue, log_box, root))
    server_thread.daemon = True
    server_thread.start()

    root.mainloop()

if __name__ == '__main__':
    input_queue = queue.Queue()

    rcon_server_thread = threading.Thread(target=rcon_server, args=(input_queue,))
    rcon_server_thread.daemon = True
    rcon_server_thread.start()

    create_gui(input_queue)
