# BDST-RCON (WINDOWS)

**BDST-RCON** (Bedrock Dedicated Server Tools - RCON) is a Python-based application designed to manage a Minecraft Bedrock Edition server using the RCON protocol. It provides a console interface to monitor and control the server, send commands, and receive output directly from the server console.

## Features

- **RCON Server:** A built-in RCON server that allows remote control of the Minecraft Bedrock server using RCON-compatible clients.
- **Console Interface:** A simple console interface that displays real-time server logs and allows you to send commands to the server.
- **Subprocess Management:** Automatically launches `bedrock_server.exe` and manages its lifecycle.
- **Unicode & Color Support:** Full support for Unicode (including emoji, Chinese, etc.) and Minecraft color codes in the console output.

## Installation

1. **Clone the repository:**
    ```bash
    git clone https://github.com/StievenW/BDST-RCON.git
    cd BDST-RCON
    ```

2. **Place `console.py` & `config.py` in the same folder as `bedrock_server.exe`:**
   Ensure that `console.py` is located in the directory where `bedrock_server.exe` is located.

3. **Install dependencies:**
    ```bash
    pip install ftfy
    ```

4. **Run the application:**
    ```bash
    python console.py
    ```

## Usage

1. **Launching the Application:**
   - Upon starting the application, it will launch `bedrock_server.exe` and start listening for incoming RCON connections.
   - The console will display the server's output in real-time.

2. **Sending Commands:**
   - Type commands directly into the console and press Enter.
   - Commands will be sent to the server, and their output will be displayed in the console.

3. **Remote Access:**
   - The RCON server listens on `127.0.0.1:25575` by default. You can connect using any RCON client with the configured password.


## Configuration

You can modify the following variables in the `config.py` file to suit your setup:
- **HOST:** The IP address on which the RCON server listens (default: `127.0.0.1`).
- **PORT:** The port on which the RCON server listens (default: `25575`).
- **PASSWORD:** The RCON password for authentication.

## Contribution

Feel free to contribute to the project by submitting issues or pull requests on GitHub.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.
