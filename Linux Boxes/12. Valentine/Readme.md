# Hack The Box - Valentine Walkthrough w/o Metasploit

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Valentine]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.79 
[sudo] password for darshan: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-03 07:41 EST
WARNING: RST from 10.10.10.79 port 22 -- is this port really open?
Nmap scan report for 10.10.10.79
Host is up (0.11s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 964c51423cba2249204d3eec90ccfd0e (DSA)
|   2048 46bf1fcc924f1da042b3d216a8583133 (RSA)
|_  256 e62b2519cb7e54cb0ab9ac1698c67da9 (ECDSA)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.2.22 (Ubuntu)
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_ssl-date: 2023-03-03T12:42:21+00:00; +4s from scanner time.
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=3/3%OT=22%CT=1%CU=32278%PV=Y%DS=2%DC=I%G=Y%TM=6401EB2A
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=103%TI=Z%CI=Z%II=I%TS=8)SEQ(
OS:SP=100%GCD=1%ISR=102%TI=Z%CI=Z%TS=8)OPS(O1=M53CST11NW4%O2=M53CST11NW4%O3
OS:=M53CNNT11NW4%O4=M53CST11NW4%O5=M53CST11NW4%O6=M53CST11)WIN(W1=3890%W2=3
OS:890%W3=3890%W4=3890%W5=3890%W6=3890)ECN(R=Y%DF=Y%T=40%W=3908%O=M53CNNSNW
OS:4%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T2(R=Y%DF=Y%T=40
OS:%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=40%W=3890%S=O%A=S+%F=AS%O=M53
OS:CST11NW4%RD=0%Q=)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y
OS:%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%R
OS:D=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IP
OS:L=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: 3s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.73 seconds
```

Before starting the enumeration, I wanted to check if any other ports were open, so I ran `rustscan` to quickly check if any other ports were open.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Valentine]
└─$ rustscan  10.10.10.79 --range 1-65535 
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
Faster Nmap scanning with Rust.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/kali/.config/rustscan/config.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.10.79:22
Open 10.10.10.79:80
Open 10.10.10.79:443
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,80,443 10.10.10.79

Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-03 07:43 EST
Initiating Ping Scan at 07:43
Scanning 10.10.10.79 [2 ports]
Completed Ping Scan at 07:43, 0.12s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 07:43
Completed Parallel DNS resolution of 1 host. at 07:43, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 07:43
Scanning 10.10.10.79 [3 ports]
Discovered open port 22/tcp on 10.10.10.79
Discovered open port 443/tcp on 10.10.10.79
Discovered open port 80/tcp on 10.10.10.79
Completed Connect Scan at 07:43, 0.12s elapsed (3 total ports)
Nmap scan report for 10.10.10.79
Host is up, received syn-ack (0.12s latency).
Scanned at 2023-03-03 07:43:05 EST for 0s

PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack
80/tcp  open  http    syn-ack
443/tcp open  https   syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.29 seconds
```

So, Rustscan & nmap both found `3` open ports and the results are: 

- Port `22`: running `OpenSSH 5.9p1`.
- Port `80`: running `Apache httpd 2.2.22`.
- Port `443`" running `Apache httpd 2.2.22`.

I also decided to run a UDP scan to check out all the UDP ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Valentine]
└─$ sudo nmap -sC -sV -sU -p 5353 -oA nmap/udp 10.10.10.79
[sudo] password for darshan: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-03 07:47 EST
Nmap scan report for 10.10.10.79
Host is up (0.21s latency).

PORT     STATE SERVICE VERSION
5353/udp open  mdns    DNS-based service discovery
| dns-service-discovery: 
|   9/tcp workstation
|     Address=10.10.10.79 dead:beef::250:56ff:feb9:13bf
|   22/tcp udisks-ssh
|_    Address=10.10.10.79 dead:beef::250:56ff:feb9:13bf

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.62 seconds
```

And I got one port open:
- port `5353`: running `mdns`


## Enumeration

Since the ssh version of `OpenSSH 5.9p1` looked old, I decided to start the enumeration by it.

On googling the version to find a launchpad site, it finds a [launchpad site](https://launchpad.net/ubuntu/+source/openssh/1:5.9p1-5ubuntu1.9) with the distro information.

![val-1](https://user-images.githubusercontent.com/87711310/222728161-fa54a8bd-053a-4158-b2b3-74a7caba2d8a.png)

So, now, on googling `Ubuntu releases precise` and visiting the `Releases` page on Wiki, I was able to look at all the releases. It can found here: [Ubuntu Releases](https://wiki.ubuntu.com/Releases)

![val-2](https://user-images.githubusercontent.com/87711310/222728786-2dc17424-707b-4d70-b11b-acc50869e186.png)

The Ubuntu wiki releases page shows that Precise Pangolin was Ubuntu 12.04, and went end of line by April 28, 2017.

Keeping this in mind, I visited the website and this was the home page.

![val-3](https://user-images.githubusercontent.com/87711310/222729105-dae4f60c-9f76-4870-adf5-ea377ecda430.png)

Both the http and https sites are just an image: `<center><img src="omg.jpg"/></center>`

On reverse searching the image, I found out that it was a `Heartbleed` logo. 

#### Now, what is heartbleed?
- Heartbleed is a logic error that allowed an attacker to grab chunks of random memory that they shouldn’t have had access to.

- There’s no better explanation of Heartbleed than [xkcd’s flyer](https://xkcd.com/1354/):

![val-4](https://user-images.githubusercontent.com/87711310/222729934-254ed138-5ff7-41c5-9ac6-4b2b0486360d.png)

So, now that I know how the vulnenrability works, I just had to search for the exploit and run it against the website.

I used `searchsploit` to find the exploit. You can also use google to find out the exploit.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Valentine]
└─$ searchsploit heartbleed
---------------------------------------------------------------------------------------------------------------------------------
 Exploit Title                                                                                       |  Path
---------------------------------------------------------------------------------------------------------------------------------
OpenSSL 1.0.1f TLS Heartbeat Extension - 'Heartbleed' Memory Disclosure (Multiple SSL/TLS Versions)  | multiple/remote/32764.py
OpenSSL TLS Heartbeat Extension - 'Heartbleed' Information Leak (1)                                  | multiple/remote/32791.c
OpenSSL TLS Heartbeat Extension - 'Heartbleed' Information Leak (2) (DTLS Support)                   | multiple/remote/32998.c
OpenSSL TLS Heartbeat Extension - 'Heartbleed' Memory Disclosure                                     | multiple/remote/32745.py
---------------------------------------------------------------------------------------------------------------------------------
Shellcodes: No Results

```

