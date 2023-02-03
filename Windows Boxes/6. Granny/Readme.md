# Hack The Box - Granny Walkthrough w/o Metasploit

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Granny]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.15 -Pn                                 
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-03 00:57 EST
Nmap scan report for 10.10.10.15
Host is up (0.37s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
|_http-title: Under Construction
| http-methods: 
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
| http-webdav-scan: 
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|   Server Date: Fri, 03 Feb 2023 05:58:30 GMT
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|_  Server Type: Microsoft-IIS/6.0
|_http-server-header: Microsoft-IIS/6.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2003|2008|XP|2000 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2003::sp1 cpe:/o:microsoft:windows_server_2003::sp2 cpe:/o:microsoft:windows_server_2008::sp2 cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_2000::sp4
Aggressive OS guesses: Microsoft Windows Server 2003 SP1 or SP2 (92%), Microsoft Windows Server 2008 Enterprise SP2 (92%), Microsoft Windows Server 2003 SP2 (91%), Microsoft Windows 2003 SP2 (91%), Microsoft Windows XP SP3 (90%), Microsoft Windows 2000 SP4 or Windows XP Professional SP1 (90%), Microsoft Windows XP (87%), Microsoft Windows Server 2003 SP1 - SP2 (86%), Microsoft Windows XP SP2 or Windows Server 2003 (86%), Microsoft Windows XP SP2 or SP3 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 46.25 seconds
```

We get back the following result showing that only 1 port was open:
- Port `80`: running `Microsoft IIS httpd 6.0`.

Before starting enumeration, I ran a more comprehensive scan in the background to make sure that I did not miss anything.

So I ran `Rustscan` that covers all ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Granny]
└─$ rustscan -a 10.10.10.15 --range 1-65535
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.10.15:80
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 80 10.10.10.15

Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-03 01:01 EST
Initiating Ping Scan at 01:01
Scanning 10.10.10.15 [2 ports]
Completed Ping Scan at 01:01, 0.23s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 01:01
Completed Parallel DNS resolution of 1 host. at 01:01, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 01:01
Scanning 10.10.10.15 [1 port]
Discovered open port 80/tcp on 10.10.10.15
Completed Connect Scan at 01:01, 0.32s elapsed (1 total ports)
Nmap scan report for 10.10.10.15
Host is up, received syn-ack (0.24s latency).
Scanned at 2023-02-03 01:01:24 EST for 0s

PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.66 seconds
```

Since, the version of `Microsoft IIS httpd` was too old, I decided to run `Nikto`, to check if there were any known kernel vulnerabilities in the version 6.0.

```

```

## Enumeration
While the `Nikto` scan was running I visited the web application in the browser.

gran-1

I looked for hidden message or button or some information and looked at the source-code too, but there was nothing. So, I decided to run `Gobuster` to enumerate directories.

```

```

On looking the directories that `gobuster` found, both `/images` and `/_private` were empty dirs.

So, I had to think about what else could I do. The nmap scan showed that the `HTTP PUT` method is allowed.

This could potentially give us the ability to save files on the web server. Since this is a `Microsoft IIS web server`, the type of files it executes are `ASP` and `ASPX`. So let’s check if we’re allowed to upload these file extensions. Now, as the `nmap` scan found a webDAV enabled web server, I used `davtest`, which is a tool that tests WebDAV enabled servers by uploading test executable files, and then (optionally) uploading files which allow for command execution or other actions directly on the target.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Granny]
└─$ davtest --url http://10.10.10.15
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://10.10.10.15
********************************************************
NOTE    Random string for this session: K6g0MYZEhXkkaim
********************************************************
 Creating directory
MKCOL           SUCCEED:                Created http://10.10.10.15/DavTestDir_K6g0MYZEhXkkaim
********************************************************
 Sending test files
PUT     jsp     SUCCEED:        http://10.10.10.15/DavTestDir_K6g0MYZEhXkkaim/davtest_K6g0MYZEhXkkaim.jsp
PUT     php     SUCCEED:        http://10.10.10.15/DavTestDir_K6g0MYZEhXkkaim/davtest_K6g0MYZEhXkkaim.php
PUT     cgi     FAIL
PUT     html    SUCCEED:        http://10.10.10.15/DavTestDir_K6g0MYZEhXkkaim/davtest_K6g0MYZEhXkkaim.html
PUT     pl      SUCCEED:        http://10.10.10.15/DavTestDir_K6g0MYZEhXkkaim/davtest_K6g0MYZEhXkkaim.pl
PUT     shtml   FAIL
PUT     cfm     SUCCEED:        http://10.10.10.15/DavTestDir_K6g0MYZEhXkkaim/davtest_K6g0MYZEhXkkaim.cfm
PUT     txt     SUCCEED:        http://10.10.10.15/DavTestDir_K6g0MYZEhXkkaim/davtest_K6g0MYZEhXkkaim.txt
PUT     jhtml   SUCCEED:        http://10.10.10.15/DavTestDir_K6g0MYZEhXkkaim/davtest_K6g0MYZEhXkkaim.jhtml
PUT     aspx    FAIL
PUT     asp     FAIL
********************************************************
 Checking for test file execution
EXEC    jsp     FAIL
EXEC    php     FAIL
EXEC    html    SUCCEED:        http://10.10.10.15/DavTestDir_K6g0MYZEhXkkaim/davtest_K6g0MYZEhXkkaim.html
EXEC    pl      FAIL
EXEC    cfm     FAIL
EXEC    txt     SUCCEED:        http://10.10.10.15/DavTestDir_K6g0MYZEhXkkaim/davtest_K6g0MYZEhXkkaim.txt
EXEC    jhtml   FAIL

********************************************************
/usr/bin/davtest Summary:
Created: http://10.10.10.15/DavTestDir_K6g0MYZEhXkkaim
PUT File: http://10.10.10.15/DavTestDir_K6g0MYZEhXkkaim/davtest_K6g0MYZEhXkkaim.jsp
PUT File: http://10.10.10.15/DavTestDir_K6g0MYZEhXkkaim/davtest_K6g0MYZEhXkkaim.php
PUT File: http://10.10.10.15/DavTestDir_K6g0MYZEhXkkaim/davtest_K6g0MYZEhXkkaim.html
PUT File: http://10.10.10.15/DavTestDir_K6g0MYZEhXkkaim/davtest_K6g0MYZEhXkkaim.pl
PUT File: http://10.10.10.15/DavTestDir_K6g0MYZEhXkkaim/davtest_K6g0MYZEhXkkaim.cfm
PUT File: http://10.10.10.15/DavTestDir_K6g0MYZEhXkkaim/davtest_K6g0MYZEhXkkaim.txt
PUT File: http://10.10.10.15/DavTestDir_K6g0MYZEhXkkaim/davtest_K6g0MYZEhXkkaim.jhtml
Executes: http://10.10.10.15/DavTestDir_K6g0MYZEhXkkaim/davtest_K6g0MYZEhXkkaim.html
Executes: http://10.10.10.15/DavTestDir_K6g0MYZEhXkkaim/davtest_K6g0MYZEhXkkaim.txt
```


