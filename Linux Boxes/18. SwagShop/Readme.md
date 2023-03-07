# Hack The Box - SwagShop Walkthrough w/o Metasploit

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SwagShop]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.140
[sudo] password for darshan: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-07 02:26 EST
Nmap scan report for 10.10.10.140
Host is up (0.12s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b6552bd24e8fa3817261379a12f624ec (RSA)
|   256 2e30007a92f0893059c17756ad51c0ba (ECDSA)
|_  256 4c50d5f270c5fdc4b2f0bc4220326434 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Did not follow redirect to http://swagshop.htb/
|_http-server-header: Apache/2.4.18 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=3/7%OT=22%CT=1%CU=37662%PV=Y%DS=2%DC=I%G=Y%TM=6406E727
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=107%TI=Z%CI=I%II=I%TS=8)SEQ(
OS:SP=101%GCD=1%ISR=107%TI=Z%CI=I%TS=8)OPS(O1=M53CST11NW7%O2=M53CST11NW7%O3
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
Nmap done: 1 IP address (1 host up) scanned in 26.36 seconds
```

Before starting the enumeration, I wanted to check if any other ports were open, so I ran `rustscan` to quickly check if any other ports were open.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SwagShop]
└─$ rustscan -a 10.10.10.140 --range 1-65535
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.10.140:22
Open 10.10.10.140:80
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,80 10.10.10.140

Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-07 02:27 EST
Initiating Ping Scan at 02:27
Scanning 10.10.10.140 [2 ports]
Completed Ping Scan at 02:27, 0.22s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 02:27
Completed Parallel DNS resolution of 1 host. at 02:27, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 02:27
Scanning 10.10.10.140 [2 ports]
Discovered open port 22/tcp on 10.10.10.140
Discovered open port 80/tcp on 10.10.10.140
Completed Connect Scan at 02:27, 0.12s elapsed (2 total ports)
Nmap scan report for 10.10.10.140
Host is up, received syn-ack (0.20s latency).
Scanned at 2023-03-07 02:27:54 EST for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.38 seconds
```

So, `nmap` and `rustscan` both found `2` open ports on the system.
- port `22`: running `OpenSSH 7.2`
- port `80`: running `Apache httpd 2.4.29`

## Enumeration.
Since, the version of OpenSSH seemed to be very recent, it might be secure, so I decided to start the enumeration by visiting the website on port `80`.

As soon as I visited the website, the url turned into `http://swagshop.htb` indicating that I need to add the domain to the list of hosts in `/etc/hosts`

```
echo "10.10.10.140  swagshop.htb" >> /etc/hosts
```

Visiting the web application, I found a e-commerce website.

![swg-1](https://user-images.githubusercontent.com/87711310/223354518-0bff0c51-d2d1-4370-9991-51f40d80f6b2.png)

On looking at the website carefully, I found out that it was running `Magneto`, which is an open-source e-commerce platform written in PHP. Considering that it is an off the shelf software, I’ll probably find reported vulnerabilities that are associated to it. But first, I need to get a version number. 

I noticed that at the bottom of the page, it has a copyright detailing the year 2014, so it’s very likely to be vulnerable.

On googling about Magneto, I found out that, just like there is a scanner for WordPress applications (WPScan), there is one for Magento applications that is called `Mage Scan`.

But before running the Mage-Scan, I decided to run `gobuster`.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SwagShop]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -u 10.10.10.140 -t 100
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.140
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Timeout:                 10s
===============================================================
2023/03/07 02:40:01 Starting gobuster in directory enumeration mode
===============================================================
/media                (Status: 301) [Size: 312] [--> http://10.10.10.140/media/]
/includes             (Status: 301) [Size: 315] [--> http://10.10.10.140/includes/]
/lib                  (Status: 301) [Size: 310] [--> http://10.10.10.140/lib/]
/app                  (Status: 301) [Size: 310] [--> http://10.10.10.140/app/]
/js                   (Status: 301) [Size: 309] [--> http://10.10.10.140/js/]
/shell                (Status: 301) [Size: 312] [--> http://10.10.10.140/shell/]
/skin                 (Status: 301) [Size: 311] [--> http://10.10.10.140/skin/]
/var                  (Status: 301) [Size: 310] [--> http://10.10.10.140/var/]
/errors               (Status: 301) [Size: 313] [--> http://10.10.10.140/errors/]
/mage                 (Status: 200) [Size: 1319]
/server-status        (Status: 403) [Size: 300]
Progress: 207548 / 207644 (99.95%)
===============================================================
2023/03/07 02:44:27 Finished
===============================================================
```
