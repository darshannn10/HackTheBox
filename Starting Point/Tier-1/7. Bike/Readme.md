
## Reconnaissance

Kicking off with a simple Nmap scan...

__Nmap Scan__
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/three]
└─$ sudo nmap -sC -sV -oN nmap.txt 10.129.50.86  
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-21 02:00 EST
Nmap scan report for 10.129.37.72
Host is up (0.23s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE    VERSION
22/tcp open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  tcpwrapped
|_http-title:  Bike 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jan 21 02:00:12 2023 -- 1 IP address (1 host up) scanned in 63.42 seconds
                                                  
```

On visiting the web page on port 80, there was just one input box to input email and submit it.

bike-1

I used `wappalyzer` to scan the site for information. `Wappalyzer` is installed as a browser extension so we just reload the main page.

bike-2

`Node.js` and `Python` web backend servers often make use of a software called `Template Engines`

With `Node.js` websites there is a good possibility that a Template Engine is being used to reflect the email.

Since, this website was using Template Engines, the first thing I decided to try was `SSTI`, this is because most `Template Engines` are vulnerable to `SSTI`.

I used a basic `SSTI` payload to check if the site is vulnerable to `SSTI`

```
{{7*7}}
```
