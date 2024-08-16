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
    input_queue.put("stop")  # Add the stop command again
    log_box.insert(tk.END, "Stopping server...\n")
    log_box.yview(tk.END)

# Function to restart the server
def restart_server(input_queue, log_box, root, buttons):
    stop_server(input_queue, log_box)
    stop_server(input_queue, log_box)  # Add the stop command again
    log_box.insert(tk.END, "Restarting server...\n")
    log_box.yview(tk.END)
    # Ensure restart is handled properly
    root.after(1000, lambda: start_server(input_queue, log_box, root, buttons))

# Function to handle exit with countdown
def exit_with_countdown(input_queue, log_box, root, buttons):
    # Check if the server is running
    if buttons['stop'].cget('state') == tk.DISABLED:  # Server is not running
        log_box.insert(tk.END, "Server is not running. Exiting immediately...\n")
        log_box.yview(tk.END)
        root.destroy()  # Close the application immediately
        return

    stop_server(input_queue, log_box)  # Send stop command
    stop_server(input_queue, log_box)  # Send stop command again
    log_box.insert(tk.END, "Stopping server...\n")
    log_box.yview(tk.END)

    # Countdown function
    def countdown(n):
        if n >= 0:
            log_box.insert(tk.END, f"Exiting in {n}...\n")
            log_box.yview(tk.END)
            root.after(1000, countdown, n - 1)  # Call countdown every second
        else:
            root.destroy()  # Close the application

    # Start countdown after receiving "Quit correctly" message
    def check_quit_message():
        if "Quit correctly" in log_box.get("1.0", tk.END):
            countdown(1)  # Change countdown to 1 second

    root.after(1000, check_quit_message)  # Check for quit message after 1 second

# Ensure proper shutdown of processes
def on_exit(root, buttons, log_box):  # Add log_box as a parameter
    exit_with_countdown(input_queue, log_box, root, buttons)  # Call exit_with_countdown function

# Creating the GUI
def create_gui(input_queue):
    root = tk.Tk()
    root.title("Bedrock Server Console")

    # Apply modern aesthetics
    root.configure(bg='#2E2E2E')  # Darker background for a modern look
    root.geometry("800x600")  # Set a proportional window size
    root.resizable(False, False)  # Disable resizing

    # Fullscreen toggle
    def toggle_fullscreen():
        is_fullscreen = root.attributes('-fullscreen')
        root.attributes('-fullscreen', not is_fullscreen)

    # Button styles with rounded corners
    button_style = {
        'font': ('Helvetica', 12),
        'bg': '#5A5A5A',  # Softer button color
        'fg': 'white',
        'activebackground': '#6A6A6A',
        'borderwidth': 0,
        'relief': 'flat'
    }

    log_box = scrolledtext.ScrolledText(root, state='disabled', height=20, width=100, bg='#222222', fg='white', insertbackground='white', borderwidth=2, relief="groove")
    log_box.configure(font='TkFixedFont')
    log_box.pack(padx=20, pady=20)

    cmd_input = tk.Entry(root, width=80, bg='#444444', fg='white', insertbackground='white', borderwidth=2, relief="groove")
    cmd_input.pack(padx=20, pady=10)

    buttons = {}

    # Button handler functions
    def handle_send(event=None):  # Allow event parameter for Enter key
        command = cmd_input.get()
        if command:  # Check if command is not empty
            input_queue.put(command)
            cmd_input.delete(0, tk.END)

    # Send Command Button
    buttons['send'] = tk.Button(root, text="Send Command", command=handle_send, **button_style)
    buttons['send'].pack(padx=20, pady=(0, 10))  # Adjust padding

    buttons['start'] = tk.Button(root, text="Start Server", command=lambda: start_server(input_queue, log_box, root, buttons), **button_style)
    buttons['start'].pack(side=tk.LEFT, padx=10, pady=10)

    buttons['stop'] = tk.Button(root, text="Stop Server", command=lambda: stop_server(input_queue, log_box), **button_style)
    buttons['stop'].pack(side=tk.LEFT, padx=10, pady=10)
    buttons['stop'].config(state=tk.DISABLED)

    buttons['restart'] = tk.Button(root, text="Restart Server", command=lambda: restart_server(input_queue, log_box, root, buttons), **button_style)
    buttons['restart'].pack(side=tk.LEFT, padx=10, pady=10)
    buttons['restart'].config(state=tk.DISABLED)

    # Add label for fullscreen information
    fullscreen_info = tk.Label(root, text="Press F11 for Fullscreen", bg='#2E2E2E', fg='white', font=('Helvetica', 10))
    fullscreen_info.pack(side=tk.BOTTOM, anchor='w', padx=10, pady=10)

    # Bind F11 key to toggle fullscreen
    root.bind('<F11>', lambda event: toggle_fullscreen())

    # Bind Ctrl+Q to exit the application with countdown
    root.bind('<Control-q>', lambda event: exit_with_countdown(input_queue, log_box, root, buttons))
    root.protocol("WM_DELETE_WINDOW", lambda: on_exit(root, buttons, log_box))  # Handle window closing

    root.mainloop()

if __name__ == '__main__':
    input_queue = queue.Queue()
    rcon_thread = threading.Thread(target=rcon_server, args=(input_queue,))
    rcon_thread.daemon = True
    rcon_thread.start()

    create_gui(input_queue)