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

# Functions for handling RCON communication
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

# Thread handling RCON client connections
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

# RCON server thread
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

def run_server(input_queue, log_box, root, buttons):
    buttons['start'].config(state=tk.DISABLED)
    buttons['stop'].config(state=tk.NORMAL)
    buttons['restart'].config(state=tk.DISABLED)

    proc = subprocess.Popen(
        "bedrock_server.exe",
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        universal_newlines=True
    )

    output_thread = threading.Thread(target=read_output, args=(proc, log_box, root, buttons))
    output_thread.daemon = True
    output_thread.start()

    while True:
        try:
            command = input_queue.get()
            if command is None:
                break
            if proc.poll() is not None:  # Check if process has terminated
                raise RuntimeError("The process has terminated unexpectedly.")
            proc.stdin.write(command + "\n")
            proc.stdin.flush()
        except RuntimeError as e:
            print(f"Error while sending command: {e}")
            root.after(0, update_log_text, log_box, "🦋 Since you restarted/stop or start again the server, you are receiving this message. You can continue sending commands. ✨\n")
            break
        except Exception as e:
            print(f"Error while sending command: {e}")
            root.after(0, update_log_text, log_box, "An unexpected error occurred. Please try sending the command again.\n")

    proc.terminate()
    proc.wait()  # Wait for the process to terminate cleanly

# Thread for reading server output
def read_output(proc, log_box, root, buttons):
    server_running = False
    while True:
        line = proc.stdout.readline()
        if line:
            root.after(0, update_log_text, log_box, line)
            if "Starting Server" in line:
                if not server_running:
                    root.after(0, on_starting_server, buttons)
                    server_running = True
            elif "Server started." in line:
                if server_running:
                    root.after(0, on_server_started, buttons)
                    server_running = False
            elif "Quit correctly" in line:
                if not server_running:
                    root.after(0, enable_start_restart_buttons, buttons)
            elif "Stopping server..." in line:
                root.after(0, disable_all_buttons, buttons)
        else:
            break

# Updating the log text in the GUI
def update_log_text(log_box, line):
    log_box.configure(state='normal')
    log_box.insert(tk.END, line)
    log_box.configure(state='disabled')
    log_box.yview(tk.END)

# Enabling start and restart buttons
def enable_start_restart_buttons(buttons):
    buttons['start'].config(state=tk.NORMAL)
    buttons['restart'].config(state=tk.NORMAL)
    buttons['stop'].config(state=tk.DISABLED)

# Disabling all buttons
def disable_all_buttons(buttons):
    buttons['start'].config(state=tk.DISABLED)
    buttons['stop'].config(state=tk.DISABLED)
    buttons['restart'].config(state=tk.DISABLED)

# Disable buttons when server is starting
def on_starting_server(buttons):
    buttons['start'].config(state=tk.DISABLED)
    buttons['restart'].config(state=tk.DISABLED)
    buttons['stop'].config(state=tk.NORMAL)

# Enable restart button when server is started
def on_server_started(buttons):
    buttons['restart'].config(state=tk.NORMAL)
    buttons['stop'].config(state=tk.NORMAL)

# Function to start the server
def start_server(input_queue, log_box, root, buttons):
    server_thread = threading.Thread(target=run_server, args=(input_queue, log_box, root, buttons))
    server_thread.daemon = True
    server_thread.start()

# Function to stop the server
def stop_server(input_queue, log_box):
    input_queue.put("stop")
    input_queue.put("stop")  # Tambahkan perintah stop kedua
    log_box.insert(tk.END, "Stopping server...\n")
    log_box.yview(tk.END)

# Function to restart the server
def restart_server(input_queue, log_box, root, buttons):
    stop_server(input_queue, log_box)
    stop_server(input_queue, log_box)  # Tambahkan perintah stop kedua
    log_box.insert(tk.END, "Restarting server...\n")
    log_box.yview(tk.END)
    # Ensure restart is handled properly
    root.after(1000, lambda: start_server(input_queue, log_box, root, buttons))

# Creating the GUI
def create_gui(input_queue):
    root = tk.Tk()
    root.title("Bedrock Server Console")

    # Apply dark theme with modern aesthetics
    root.configure(bg='#333333')
    root.option_add('*TButton*font', 'Helvetica 10')
    root.option_add('*TButton*background', '#444444')
    root.option_add('*TButton*foreground', 'white')
    root.option_add('*TButton*highlightBackground', '#444444')
    root.option_add('*TButton*highlightColor', 'black')
    root.option_add('*TLabel*foreground', 'white')
    root.option_add('*TLabel*background', '#333333')
    root.option_add('*TEntry*background', '#555555')
    root.option_add('*TEntry*foreground', 'white')

    log_box = scrolledtext.ScrolledText(root, state='disabled', height=20, width=120, bg='#222222', fg='white', insertbackground='white', borderwidth=2, relief="groove")
    log_box.configure(font='TkFixedFont')
    log_box.pack(padx=10, pady=10)

    cmd_input = tk.Entry(root, width=100, bg='#444444', fg='white', insertbackground='white', borderwidth=2, relief="groove")
    cmd_input.pack(padx=10, pady=5)

    buttons = {}

    # Button handler functions
    def handle_send():
        command = cmd_input.get()
        input_queue.put(command)
        cmd_input.delete(0, tk.END)

    buttons['send'] = tk.Button(root, text="Send Command", command=handle_send)
    buttons['send'].pack(side=tk.LEFT, padx=10, pady=5)

    buttons['start'] = tk.Button(root, text="Start Server", command=lambda: start_server(input_queue, log_box, root, buttons))
    buttons['start'].pack(side=tk.LEFT, padx=10, pady=5)

    buttons['stop'] = tk.Button(root, text="Stop Server", command=lambda: stop_server(input_queue, log_box))
    buttons['stop'].pack(side=tk.LEFT, padx=10, pady=5)
    buttons['stop'].config(state=tk.DISABLED)

    buttons['restart'] = tk.Button(root, text="Restart Server", command=lambda: restart_server(input_queue, log_box, root, buttons))
    buttons['restart'].pack(side=tk.LEFT, padx=10, pady=5)
    buttons['restart'].config(state=tk.DISABLED)

    buttons['exit'] = tk.Button(root, text="Exit", command=lambda: on_exit(root, buttons))
    buttons['exit'].pack(side=tk.RIGHT, padx=10, pady=5)

    # Ensure proper shutdown of processes
    def on_exit(root, buttons):
        if buttons['stop'].cget('state') == tk.NORMAL:
            stop_server(input_queue, log_box)
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", lambda: on_exit(root, buttons))
    root.mainloop()

if __name__ == '__main__':
    input_queue = queue.Queue()
    rcon_thread = threading.Thread(target=rcon_server, args=(input_queue,))
    rcon_thread.daemon = True
    rcon_thread.start()

    create_gui(input_queue)
