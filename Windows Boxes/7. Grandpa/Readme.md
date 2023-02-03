# Hack The Box - Grandpa Walkthrough

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Grandpa]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.14 -Pn                                 
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-03 06:37 EST
Nmap scan report for 10.10.10.14
Host is up (0.20s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
|_http-server-header: Microsoft-IIS/6.0
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
| http-webdav-scan: 
|   Server Type: Microsoft-IIS/6.0
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   Server Date: Fri, 03 Feb 2023 11:38:14 GMT
|_  WebDAV type: Unknown
|_http-title: Under Construction
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2003|2008|2000|XP (91%)
OS CPE: cpe:/o:microsoft:windows_server_2003::sp1 cpe:/o:microsoft:windows_server_2003::sp2 cpe:/o:microsoft:windows_server_2008::sp2 cpe:/o:microsoft:windows_2000::sp4 cpe:/o:microsoft:windows_xp::sp1:professional
Aggressive OS guesses: Microsoft Windows Server 2003 SP1 or SP2 (91%), Microsoft Windows Server 2008 Enterprise SP2 (91%), Microsoft Windows Server 2003 SP2 (91%), Microsoft Windows 2000 SP4 or Windows XP Professional SP1 (90%), Microsoft Windows 2003 SP2 (90%), Microsoft Windows XP SP3 (89%), Microsoft Windows 2000 SP4 (86%), Microsoft Windows XP (86%), Microsoft Windows Server 2003 SP1 - SP2 (85%), Microsoft Windows XP SP2 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.58 seconds
```
