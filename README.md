# GeneratePowershellLauncher.py

Generate a powershell dropper for any DLL or EXE. The shellcode of the payload is generated with [Donut](https://github.com/TheWover/donut). Two powershell script are generated, the first is an AMSI bypass (credit to rasta-mouse) the second is the injector (credit to [Metasploit](https://github.com/rapid7/metasploit-framework) web-delivery PSH). The output is store on ./web, the final command to launch on the victime host is display on the console.

![alt text](https://github.com/maxDcb/PowershellWebDelivery/blob/master/ressources/image1.png?raw=true)
