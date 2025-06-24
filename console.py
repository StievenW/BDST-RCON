import subprocess
import threading
import socket
import queue
import struct
import ftfy
import os
import sys
import re
import time
import webbrowser

def create_config():
    host = input("Host [default: 127.0.0.1]: ").strip() or '127.0.0.1'
    port_input = input("Port [default: 25575]: ").strip()
    port = int(port_input) if port_input else 25575
    password = input("Password [default: yourpassword]: ").strip() or 'yourpassword'
    with open('config.py', 'w', encoding='utf-8') as f:
        f.write(f"HOST = '{host}'\nPORT = {port}\nPASSWORD = '{password}'\n")
    print("config.py created successfully.")
    return host, port, password

def load_config():
    """Load config from executable directory or current directory"""
    config_paths = [
        os.path.join(os.path.dirname(sys.executable), 'config.py'),
        os.path.join(os.getcwd(), 'config.py'),
        'config.py'
    ]
    
    for config_path in config_paths:
        if os.path.exists(config_path):
            import importlib.util
            spec = importlib.util.spec_from_file_location("config", config_path)
            config = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(config)
            if all(hasattr(config, attr) for attr in ['HOST', 'PORT', 'PASSWORD']):
                return config
    return None

try:
    config = load_config()
    if config is None:
        raise ImportError("Config not found or invalid")
except Exception as e:
    print(f"config.py not found or invalid. ({e})")
    answer = input("Create a new config.py? (y/n): ").strip().lower()
    if answer != 'y':
        print("Exiting program because config.py is missing.")
        os._exit(0)
        
    host, port, password = create_config()
    

    import types
    config = types.ModuleType('config')
    config.HOST = host
    config.PORT = port
    config.PASSWORD = password

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
        


        rest = re.sub(r'(Session ID: )([a-f0-9-]+)', r'\1\033[93m\2\033[0m', rest)
        rest = re.sub(r'(Build ID: )(\d+)', r'\1\033[92m\2\033[0m', rest)
        rest = re.sub(r'(Branch: )([^\s]+)', r'\1\033[94m\2\033[0m', rest)
        rest = re.sub(r'(Commit ID: )([a-f0-9]+)', r'\1\033[95m\2\033[0m', rest)
        rest = re.sub(r'Level Name: (.*?)(?=\s*$|\s+\w+:)', r'Level Name: \033[96m\1\033[0m', rest)
        rest = re.sub(r'(Game mode: )(\d+\s+[^\s]+)', r'\1\033[92m\2\033[0m', rest)
        rest = re.sub(r'(Difficulty: )(\d+\s+[^\s]+)', r'\1\033[93m\2\033[0m', rest)
        rest = re.sub(r'(port: )(\d+)', r'\1\033[92m\2\033[0m', rest)
        rest = re.sub(r'(RCON server listening on )([^\s]+)', r'\1\033[97m\2\033[0m', rest)
        
        return f"[{ts_col} {lvl_col}]{rest}"
    

    lines = text.splitlines()
    for i, line in enumerate(lines):
        if '§' in line:
            line = re.sub(r'§([0-9a-frlonmk])', repl, line, flags=re.IGNORECASE)

        line += '\033[0m'
        lines[i] = line
    text = '\n'.join(lines)
    text = re.sub(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}:\d{3}) (ERROR|INFO|WARN|WARNING)](.*)', colorize_log, text)
    return text

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

output_buffer = []
output_buffer_lock = threading.Lock()

client_command_flag = threading.Event()

rcon_response_queue = queue.Queue()

def get_timestamp():
    return time.strftime('%Y-%m-%d %H:%M:%S') + ':%03d' % (int(time.time() * 1000) % 1000)

def get_server_port():
    """Read server port from server.properties"""
    try:
        with open("server.properties", "r") as f:
            for line in f:
                if line.startswith("server-port="):
                    return int(line.strip().split("=")[1])
    except FileNotFoundError:
        print("\033[93mWarning: server.properties not found\033[0m")
        return None
    except Exception as e:
        print(f"\033[91mError reading server.properties: {e}\033[0m")
        return None
    return None

def scan_playit_tunnel(playit_log_file, target_port):
    setup_detected = False
    setup_completed = False
    port_mismatch_notified = False
    tunnel_already_verified = False
    

    if not hasattr(scan_playit_tunnel, 'tunnel_setup_state'):
        scan_playit_tunnel.tunnel_setup_state = {'verified': False, 'tunnel_info': None}
    

    if scan_playit_tunnel.tunnel_setup_state['verified']:
        return scan_playit_tunnel.tunnel_setup_state['tunnel_info']
    
    while True:

        if not os.path.exists(playit_log_file.name):
            time.sleep(1)
            continue
            
        with open(playit_log_file.name, 'r') as f:
            content = f.read()
            

            tunnel_pattern = r'(?:connection-forget|[a-zA-Z0-9.-]+)\.(?:gl\.at\.)?ply\.gg:\d+\s*=>\s*127\.0\.0\.1:' + str(target_port)
            tunnel_match = re.search(tunnel_pattern, content)
            if tunnel_match:
                tunnel_info = (tunnel_match.group(0), target_port)
                scan_playit_tunnel.tunnel_setup_state['verified'] = True
                scan_playit_tunnel.tunnel_setup_state['tunnel_info'] = tunnel_info
                print(f"\033[92mPlayit.gg tunnel found: {tunnel_match.group(0)} -> {target_port}\033[0m")
                return tunnel_info


            if 'tunnel running,' in content:

                if 'tunnel running, 0 tunnels registered' in content:

                    if not port_mismatch_notified:
                        port_mismatch_notified = True
                        print(f"\n\033[91mWarning: No tunnel configured for port {target_port}\033[0m")
                        print(f"\033[93mPlease add a tunnel with port {target_port} at:\033[0m")
                        print("\033[92mhttps://playit.gg/account/tunnels\033[0m")
                        webbrowser.open("https://playit.gg/account/tunnels")
                else:

                    wrong_port = re.search(r'127\.0\.0\.1:(\d+)', content)
                    if wrong_port and int(wrong_port.group(1)) != target_port:
                        print(f"\n\033[91mWarning: Found tunnel with wrong port {wrong_port.group(1)}, need port {target_port}\033[0m")
                        print("\033[93mPlease update tunnel configuration\033[0m")
                        webbrowser.open("https://playit.gg/account/tunnels")


            elif 'Visit link to setup' in content:
                setup_url = re.search(r'(https://playit\.gg/claim/[a-zA-Z0-9]+)', content)
                if setup_url and not setup_detected:
                    setup_detected = True
                    print("\n\033[93mFirst time setup: Need to register playit.gg agent\033[0m")
                    print(f"\033[92mOpening setup page: {setup_url.group(1)}\033[0m")
                    webbrowser.open(setup_url.group(1))

            time.sleep(1)
            continue

    return None, None


def output_reader(proc, playit_log):
    seen_lines = set()
    server_started = False
    rcon_announced = False
    server_port = get_server_port()
    playit_initialized = False
    tunnel_setup_done = False
    initial_check_done = False
    
    def resolve_domain(host):
        try:
            return socket.gethostbyname(host)
        except:
            return None
    
    def parse_playit_tunnel(content, target_port):
        """Parse playit log to find matching tunnel"""
        def check_tunnel():
            patterns = [
                r'([a-zA-Z0-9.-]+\.gl\.at\.ply\.gg:\d+)\s*=>\s*127\.0\.0\.1:(\d+)\s*\(minecraft-bedrock\)',
                r'([a-zA-Z0-9.-]+\.gl\.at\.ply\.gg:\d+)\s*=>\s*127\.0\.0\.1:(\d+)\s*\(proto:\s*Udp',
                r'([a-zA-Z0-9.-]+\.ply\.gg:\d+)\s*=>\s*127\.0\.0\.1:(\d+)\s*\(minecraft-bedrock\)',
                r'([a-zA-Z0-9.-]+\.ply\.gg:\d+)\s*=>\s*127\.0\.0\.1:(\d+)\s*\(proto:\s*Udp'
            ]
            
            for pattern in patterns:
                matches = list(re.finditer(pattern, content))
                for match in matches:
                    if int(match.group(2)) == target_port:
                        return match.group(1)
            return None
        

        tunnel = check_tunnel()
        if not tunnel:
            print("\033[93mWaiting for tunnel to be ready...\033[0m")
            max_attempts = 30
            for _ in range(max_attempts):
                with open(playit_log.name, 'r') as f:
                    new_content = f.read()
                    tunnel = check_tunnel()
                    if tunnel:
                        return tunnel
                time.sleep(1)
            return None
        return tunnel

    while True:
        line = proc.stdout.readline()
        if not line:
            break
            
        fixed_line = ftfy.fix_text(line.rstrip())
        now = time.time()
        
        if fixed_line not in seen_lines:
            seen_lines.add(fixed_line)
            
            with output_buffer_lock:
                output_buffer.append((now, fixed_line))
            if not client_command_flag.is_set():
                print(mc_color_to_ansi(fixed_line))
            
            if "Server started." in fixed_line and not server_started:
                server_started = True
                time.sleep(0.1)
                
                if not rcon_announced:
                    rcon_announced = True
                    rcon_msg = f"[{get_timestamp()} INFO] RCON server listening on {config.HOST}:{config.PORT}"
                    with output_buffer_lock:
                        output_buffer.append((now, rcon_msg))
                    if not client_command_flag.is_set():
                        print(mc_color_to_ansi(rcon_msg))
                
                if playit_log and server_port and not initial_check_done:
                    try:
                        initial_check_done = True
                        with open(playit_log.name, 'r') as f:
                            playit_content = f.read()
                        
                        tunnel_addr = parse_playit_tunnel(playit_content, server_port)
                        if tunnel_addr:
                            host, port = tunnel_addr.split(':')
                            
                            banner = f"[{get_timestamp()} INFO] =================== PUBLIC ADDRESS ===================" 
                            addr_msg = f"[{get_timestamp()} INFO] Server Address: {host}:{port} (🌐)"
                            
                            ip = resolve_domain(host)
                            ip_msg = f"[{get_timestamp()} INFO] Server IP: {ip}" if ip else None
                            
                            with output_buffer_lock:
                                output_buffer.append((now, banner))
                                output_buffer.append((now, addr_msg))
                                if ip_msg:
                                    output_buffer.append((now, ip_msg))
                                
                                if not client_command_flag.is_set():
                                    print(mc_color_to_ansi(banner))
                                    print(mc_color_to_ansi(addr_msg))
                                    if ip_msg:
                                        print(mc_color_to_ansi(ip_msg))
                                        

                            if playit_log:
                                playit_log.clear_contents()
                            
                    except Exception as e:
                        print(f"Error getting server address info: {e}")


def get_output_since(ts, timeout=1.0):
    time.sleep(timeout)
    now = time.time()
    lines = []
    with output_buffer_lock:
        for t, line in output_buffer:
            if t >= ts:
                lines.append(line)
    return '\n'.join(lines)

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
                client_command_flag.set()
                ts = time.time()
                input_queue.put(command_data)
                response = get_output_since(ts, timeout=1.0)
                
                if command_data.lower() in ['help', 'list', 'permission list']:
                    time.sleep(0.5)
                    additional = get_output_since(ts + 1.0, timeout=0.5)
                    if additional:
                        response = response + "\n" + additional

                send_packet(client_socket, RCON_PACKET_TYPE['SERVERDATA_RESPONSE_VALUE'], request_id, response)
                client_command_flag.clear()
            else:
                break

    except ConnectionResetError:
        print(f"Connection lost from {client_address}")
    except Exception as e:
        print(f"Error in client_handler: {e}")
    finally:
        client_socket.close()

def rcon_server(input_queue):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((config.HOST, config.PORT))
    server_socket.listen(5)
    try:
        while True:
            client_sock, client_addr = server_socket.accept()
            client_thread = threading.Thread(target=client_handler, args=(client_sock, client_addr, input_queue))
            client_thread.daemon = True
            client_thread.start()
    finally:
        server_socket.close()

def get_instance_id():
    """Generate unique instance ID based on folder name and path"""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    folder_name = os.path.basename(current_dir)
    parent_path = os.path.dirname(current_dir)
    import hashlib
    return hashlib.md5(f"{parent_path}_{folder_name}".encode()).hexdigest()[:8]

def clean_playit_output(line):
    line = re.sub(r'\x1b8', '', line)
    line = re.sub(r'\x1b\[[\d;]*[a-zA-Z]', '', line)
    line = re.sub(r'[\x00-\x1F\x7F-\x9F]', '', line)
    line = re.sub(r'^\s*\d+', '', line)
    line = line.strip()
    return line if line else ''

class PlayitLogHandler:
    def __init__(self):
        self.name = 'playit.log'
        self.log_file = None
        self.last_message = ''
        self.is_closed = False
        self.stop_logging = False
        self.open_file()
    
    def open_file(self):
        self.log_file = open(self.name, 'a+', encoding='utf-8', buffering=1)

        self.log_file.seek(0)
        last_lines = self.log_file.readlines()
        if last_lines:
            self.last_message = last_lines[-1].strip()

        self.log_file.truncate(0)
        self.is_closed = False
        self.stop_logging = False
    
    def write(self, data):
        if self.is_closed or self.stop_logging:
            return
        cleaned = clean_playit_output(data)
        if cleaned and cleaned != self.last_message:
            try:
                self.log_file.write(cleaned + '\n')
                self.log_file.flush()
                self.last_message = cleaned
            except ValueError:
                pass
    
    def clear_contents(self):
        """Clear log contents and stop logging"""
        if not self.is_closed and self.log_file:
            self.log_file.seek(0)
            self.log_file.truncate()
            self.log_file.flush()
            self.stop_logging = True
    
    def close(self):
        """Close the file handle"""
        if not self.is_closed and self.log_file:
            self.is_closed = True
            self.log_file.close()

def get_playit_dir():
    """Get dedicated playit.gg directory in user's temp folder"""
    temp_dir = os.path.join(os.environ.get('TEMP', os.getcwd()), 'mc_playit_data')
    os.makedirs(temp_dir, exist_ok=True)
    return temp_dir

def run_playit():
    try:
        server_port = get_server_port()
        if server_port is None:
            print("\033[91mCould not determine server port from server.properties\033[0m")
            return None, None
        
        if not os.path.exists("playit-windows-x86_64-signed.exe"):
            print("\033[93mplayit.gg not found, skipping playit.gg initialization\033[0m")
            return None, None
        
        log_handler = PlayitLogHandler()
        

        playit_process = subprocess.Popen(
            ["playit-windows-x86_64-signed.exe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS,
            universal_newlines=True,
            bufsize=1
        )
        
        def log_reader():
            for line in playit_process.stdout:
                log_handler.write(line)
        
        log_thread = threading.Thread(target=log_reader, daemon=True)
        log_thread.start()
        
        print("\033[93mAnalyzing playit.gg tunnels...\033[0m")
        public_ip, local_port = scan_playit_tunnel(log_handler, server_port)
        
        if public_ip:
            print("\033[92mplayit.gg tunnel verified - Found matching port for Minecraft server\033[0m")
            return playit_process, log_handler
        else:
            print(f"\033[91mError: Could not find matching tunnel for Minecraft port {server_port}")
            print("Terminating PlayIt\033[0m")
            playit_process.terminate()
            log_handler.close()
            return None, None
            
    except Exception as e:
        print(f"\033[91mError starting PlayIt: {e}\033[0m")
        return None, None

def run_server(input_queue):

    files_ok, message = check_required_files()
    if not files_ok:
        print(message)
        print("\n\033[93mPress ENTER to exit...\033[0m")
        if os.name == 'nt':
            import msvcrt
            msvcrt.getch()
        os._exit(1)
    
    server_running = threading.Event()
    server_running.set()
    

    server_port = get_server_port()
    if server_port:
        playit_process, playit_log = run_playit()
        if playit_process:
            print("Waiting for playit.gg to initialize (10 seconds)...")
            time.sleep(10)
    else:
        playit_process, playit_log = None, None
        print("\033[93mSkipping playit.gg initialization due to missing or invalid server.properties\033[0m")
    
    try:
        proc = subprocess.Popen(
            "bedrock_server.exe",
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
            encoding='utf-8',
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
        )
    except FileNotFoundError:
        print("\033[91mError: Could not start bedrock_server.exe\033[0m")
        if playit_process:
            playit_process.terminate()
        if playit_log:
            playit_log.close()
        print("\n\033[93mPress ENTER to exit...\033[0m")
        if os.name == 'nt':
            import msvcrt
            msvcrt.getch()
        os._exit(1)

    output_thread = threading.Thread(target=output_reader, args=(proc, playit_log))
    output_thread.daemon = True
    output_thread.start()
    
    while server_running.is_set():
        try:
            command = input_queue.get()
            if command is None or command.lower() == "stop":
                server_running.clear()
                proc.stdin.write("stop\n")
                proc.stdin.flush()
                

                while True:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    fixed_line = ftfy.fix_text(line.rstrip())
                    print(mc_color_to_ansi(fixed_line))
                    if "Quit correctly" in fixed_line:
                        break
                break
            
            if proc.poll() is not None:
                server_running.clear()
                if playit_process:
                    playit_process.terminate()
                if playit_log:
                    playit_log.close()
                break
                
            proc.stdin.write(command + "\n")
            proc.stdin.flush()
            
        except RuntimeError as e:
            print(f"Error while sending command: {e}")
            server_running.clear()
            break
            
        except Exception as e:
            if server_running.is_set():
                print(f"Unknown command: {command}. Please check that the command exists and that you have permission to use it.")
    

    if playit_process:
        playit_process.terminate()
        playit_log.close()
    
    print("\033[93mWaiting for server to close...\033[0m")
    proc.terminate()
    proc.wait()
    os._exit(0)

def stop_server(input_queue):
    input_queue.put("stop")

def start_server(input_queue):
    server_thread = threading.Thread(target=run_server, args=(input_queue,))
    server_thread.daemon = True
    server_thread.start()

def check_required_files():
    """Check for required files and return (success, message)"""
    required_files = {
        "server.properties": "Minecraft server configuration file",
        "bedrock_server.exe": "Bedrock server executable"
    }
    
    missing_files = []
    for file, description in required_files.items():
        if not os.path.exists(file):
            missing_files.append(f"\033[91m{file}\033[0m (\033[93m{description}\033[0m)")
    
    if missing_files:
        message = "Missing required files:\n" + "\n".join(f"- {f}" for f in missing_files)
        message += "\n\n\033[93mPlease ensure all required files are in the same directory as this script.\033[0m"
        return False, message
    
    return True, "All required files found."

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