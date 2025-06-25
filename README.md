# BDST-RCON (WINDOWS) v2.0.2

**BDST-RCON** (Bedrock Dedicated Server Tools - RCON) is a Python-based application designed to manage a Minecraft Bedrock Edition server using the RCON protocol. It provides a console interface to monitor and control the server, send commands, and receive output directly from the server console.

## Quick Start

**Download the latest release:**
- [Download BDST-RCON v2.0.2](https://github.com/StievenW/BDST-RCON/blob/main/dist/console.exe)
- Place the downloaded `console.exe` in the same folder as your `bedrock_server.exe`
- Run `console.exe` to start the application

## Features

- **RCON Server:** A built-in RCON server that allows remote control of the Minecraft Bedrock server using RCON-compatible clients.
- **Console Interface:** A simple console interface that displays real-time server logs and allows you to send commands to the server.
- **Subprocess Management:** Automatically launches `bedrock_server.exe` and manages its lifecycle.
- **Unicode & Color Support:** Full support for Unicode (including emoji, Chinese, etc.) and Minecraft color codes in the console output.


## For Developers

If you want to run from source or contribute to development:

1. **Clone the repository:**
    ```bash
    git clone https://github.com/StievenW/BDST-RCON.git
    cd BDST-RCON
    ```

2. **Install dependencies:**
    ```bash
    pip install ftfy
    ```

3. **Run the application:**
    ```bash
    python console.py
    ```

## Usage

1. **Launching the Application:**
   - Simply double-click `console.exe` (or run `python console.py` if using source)
   - The application will automatically launch `bedrock_server.exe` and start listening for incoming RCON connections
   - The console will display the server's output in real-time

2. **Sending Commands:**
   - Type commands directly into the console and press Enter
   - Commands will be sent to the server, and their output will be displayed in the console

3. **Remote Access:**
   - The RCON server listens on `127.0.0.1:25575` by default
   - Connect using any RCON client with the configured password

## Configuration

You can modify the following variables in the `config.py` file to suit your setup:
- **HOST:** The IP address on which the RCON server listens (default: `127.0.0.1`)
- **PORT:** The port on which the RCON server listens (default: `25575`)
- **PASSWORD:** The RCON password for authentication

## What's New in v2.0.2
- **Seamless playit.gg Integration:** Enhanced server accessibility with built-in support for playit.gg, making it easier to host and share your Minecraft Bedrock server with friends worldwide

## Prerequisites

1. **Download BDST-RCON:** Get the latest version from the link above
2. **Download playit.gg:** 
   - Download the playit.gg client from [official website](https://playit.gg/download)
   - Save the `playit-windows-x86_64-signed.exe` file in the same directory as your `bedrock_server.exe`

## Installation Steps

1. Ensure both `console.exe` and `playit-windows-x86_64-signed.exe` are in the same folder as your `bedrock_server.exe`
2. Run `console.py` or `console.exe` to start the BDST-RCON application
3. Follow the playit.gg setup instructions that appear in the console to get your server accessible over the internet

## Contribution

Feel free to contribute to the project by submitting issues or pull requests on GitHub.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.
