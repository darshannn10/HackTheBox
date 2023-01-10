# Shoppy (NoSQL Injection and Docker Vulnerability)

- Difficulty: `Easy`

- Points: `20`

## Reconnaissance
Kicking of the Recon phase with a good ol' simple Nmap scan.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Shoppy]
└─$ sudo nmap -sC -sV -O -oA nmap 10.10.11.180
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-10 03:20 EST
Nmap scan report for 10.10.11.180
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 9e:5e:83:51:d9:9f:89:ea:47:1a:12:eb:81:f9:22:c0 (RSA)
|   256 58:57:ee:eb:06:50:03:7c:84:63:d7:a3:41:5b:1a:d5 (ECDSA)
|_  256 3e:9d:0a:42:90:44:38:60:b3:b6:2c:e9:bd:9a:67:54 (ED25519)
80/tcp open  http    nginx 1.23.1
|_http-server-header: nginx/1.23.1
|_http-title: Did not follow redirect to http://shoppy.htb
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=1/10%OT=22%CT=1%CU=39987%PV=Y%DS=2%DC=I%G=Y%TM=63BD1FD
OS:4%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M539ST11NW7%O2=M539ST11NW7%O3=M539NNT11NW7%O4=M539ST11NW7%O5=M539ST1
OS:1NW7%O6=M539ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M539NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.21 seconds
                                                                   
```

The results show that there are two open ports:
- port `22`: OpenSSH 8.4p1 Debian
- port `80`: nginx 1.23.1

Before starting enumeration, I ran a more comprehensive nmap scan in the background to make sure that I did not miss anything

So I ran an Nmap scan that covers all ports.

```

```

## Enumeration

On visiting the web-page to check whats it all about, I noticed that the web-site coverted the IP address to `http://shoppy.htb/`, indicating that I need to write the ip address of the machine and `shoppy.htb`, for display, in `/etc/hosts`.

I did by executing following commands:
```
sudo nano /etc/hosts
Added this command in the /etc/host file: 10.10.11.180 shoppy.htb
Saved and exited the file
```

On reloading the site, we can see that there is a nice animation of a timer.

I tried clicking here and there to look if there's any hidden button or something but there was nothing of such sort. I, then, proceeded to look at the `source-code` of the web-site and found nothing there too.

So I decided to run `gobuster` to enumerate directories.

Since we've added a host to a IP address, I used `-vhost` tag in gobuster instead of using `dir` tag

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Shoppy]
└─$ gobuster vhost -w /usr/share/wordlists/SecLists-master/Discovery/DNS/bitquark-subdomains-top100000.txt -t 100 -u shoppy.htb 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://shoppy.htb
[+] Method:       GET
[+] Threads:      100
[+] Wordlist:     /usr/share/wordlists/SecLists-master/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/01/10 04:40:12 Starting gobuster in VHOST enumeration mode
===============================================================
Found: mattermost.shoppy.htb (Status: 200) [Size: 3122]
                                                       
===============================================================
2023/01/10 04:42:18 Finished
===============================================================
                              
```

So I found `mattermost.shoppy.htb` and was given a error as soon as i visited the page. I then remembered to add the `mattermost.shoppy.htb` host to the IP address in the `/etc/hosts` file

After adding the host, I refreshed the page, and there was nothing, just a blank white page, I checked out the source code and there was still nothing.

![shp-1](https://user-images.githubusercontent.com/87711310/211517922-47417a2b-e1ed-40f8-9a05-3823aa6624ab.png)

But after a few seconds when I visted the page again, there was a `login` form and I was in `/login` directory

![shp-2](https://user-images.githubusercontent.com/87711310/211517930-916bcbf5-7e5e-4edd-b292-de5813be1ce8.png)

