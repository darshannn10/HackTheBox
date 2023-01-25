## Reconnaissance

Kicking off with a simple Nmap scan...

__Nmap Scan__
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/Ignition]
└─$ sudo nmap -sC -sV -O -oN nmap.txt 10.129.36.123
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-25 15:50 EST
Nmap scan report for 10.129.36.123
Host is up (0.57s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Did not follow redirect to http://ignition.htb/
Aggressive OS guesses: Linux 5.0 (94%), Linux 5.4 (94%), Linux 5.0 - 5.4 (94%), HP P2000 G3 NAS device (93%), Linux 4.15 - 5.6 (93%), Linux 5.3 - 5.4 (93%), Linux 2.6.32 (92%), Linux 2.6.32 - 3.1 (92%), Ubiquiti AirMax NanoStation WAP (Linux 2.6.32) (92%), Linux 3.7 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.86 seconds
 
```

Since port `80` was the only port open, I visited the website and got an error.

![ig-1](https://user-images.githubusercontent.com/87711310/214688139-4023337a-3137-4b93-b7d3-88164c35fef7.png)

__Note__: Even though we typed the IP address in the url bar, if you now look closely in the url bar, it has been replaced by `ignition.htb`

This usually happens when a server (10.129.36.123) is hosting several websites and we need specify to the server which website we want to visit. 

For that we need to edit our hosts file on our VM. Our hosts file can be found in the directory /etc of our machine. Let's open this file and edit it.

```
sudo nano /etc/hosts
```
 
Then, add the IP address along with `ignition.htb` on a new live, save and exit.

Now open your browser again and type the IP again in the url search bar. This time it should work:\

![ig-2](https://user-images.githubusercontent.com/87711310/214689800-6741e63a-cbbb-4d3c-8f55-08499979b8b0.png)

You can navigate the website but it doesn't look like anything is interesting for now. 

Let's use gobuster to enumerate any hidden directories:

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/Ignition]
└─$ gobuster dir -u http://ignition.htb -w /usr/share/dirb/wordlists/common.txt -x php,html
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://ignition.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              html,php
[+] Timeout:                 10s
===============================================================
2023/01/25 16:02:35 Starting gobuster in directory enumeration mode
===============================================================
Progress: 333 / 13845 (2.41%)[ERROR] 2023/01/25 16:03:20 [!] Get "http://ignition.htb/_vti_rpc.html": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2023/01/25 16:03:20 [!] Get "http://ignition.htb/_vti_script.html": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
/0                    (Status: 200) [Size: 25803]
/admin                (Status: 200) [Size: 7092] 
/catalog              (Status: 302) [Size: 0] [--> http://ignition.htb/]
/checkout             (Status: 302) [Size: 0] [--> http://ignition.htb/checkout/cart/]
/cms                  (Status: 200) [Size: 25817]                                     
/contact              (Status: 200) [Size: 28673] 
```

Gobuster will keep enumerating for a while, but it has already found something interesting at `http://ignition.htb/admin`

Visiting the `/admin` directory, we find an admin login page:

![ig-3](https://user-images.githubusercontent.com/87711310/214691739-fcd280e7-acb7-403b-aac9-b96318996b5c.png)

I tried using comman username and passwords to bypass the login mechanism and after a few tries, I finally managed to get in using the username `admin` and the  password `qwerty123`

![ig-4](https://user-images.githubusercontent.com/87711310/214692341-8efacc5a-6a8e-4486-8c36-a7aff402468e.png)

The flag is right there at the bottom!
