# BDST-RCON

**BDST-RCON** (Bedrock Dedicated Server Tools - RCON) is a Python-based application designed to manage a Minecraft Bedrock Edition server using the RCON protocol. It provides a graphical user interface (GUI) to monitor and control the server, send commands, and receive output directly from the server console.

## Features

- **RCON Server:** A built-in RCON server that allows remote control of the Minecraft Bedrock server using RCON-compatible clients.
- **GUI Console:** A user-friendly GUI that displays real-time server logs and allows you to send commands to the server.
- **Subprocess Management:** Automatically launches `bedrock_server.exe` and manages its lifecycle.
- **Multithreading:** Handles multiple client connections and commands concurrently using threading.

## Installation

1. **Clone the repository:**
    ```bash
    git clone https://github.com/StievenW/BDST-RCON.git
    cd BDST-RCON
    ```

2. **Run the application:**
    ```bash
    python main.py
    ```

## Usage

1. **Launching the Application:**
   - Upon starting the application, it will launch `bedrock_server.exe` and start listening for incoming RCON connections.
   - The GUI will display the server's console output in real-time.

2. **Sending Commands:**
   - Enter commands in the input field at the bottom of the GUI and press the "Send Command" button.
   - Commands will be sent to the server, and their output will be displayed in the console.

3. **Remote Access:**
   - The RCON server listens on `127.0.0.1:25575` by default. You can connect using any RCON client using the configured password.

## RCON Protocol and Limitations

### Limitations of RCON

The RCON protocol, as implemented in this project, has the following limitations:
- **No Response from Bedrock Server:** The Bedrock Edition server's RCON implementation does not provide responses for many commands. This is a limitation of the server software itself, not the RCON client or server in this project.

## Configuration

You can modify the following variables in the `main.py` file to suit your setup:
- **HOST:** The IP address on which the RCON server listens (default: `127.0.0.1`).
- **PORT:** The port on which the RCON server listens (default: `25575`).
- **PASSWORD:** The RCON password for authentication.

## Contribution

Feel free to contribute to the project by submitting issues or pull requests on GitHub.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.
