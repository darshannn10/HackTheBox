## Reconnaissance

Kicking off with a simple Nmap scan...

__Nmap Scan__
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/crocodile]
└─$ sudo nmap -sC -sV -oN nmap.txt 10.129.10.200  
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-17 09:02 EST
Nmap scan report for 10.129.10.200
Host is up (0.016s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp            33 Jun 08  2021 allowed.userlist
|_-rw-r--r--    1 ftp      ftp            62 Apr 20  2021 allowed.userlist.passwd
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.10.14.190
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-favicon: Unknown favicon MD5: 1248E68909EAE600881B8DB1AD07F356
|_http-title: Smash - Bootstrap Business Template
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Unix

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jan 17 21:18:36 2022 -- 1 IP address (1 host up) scanned in 19.01 seconds
```

We can connect `anonymously` to the `FTP` server and retrieve the two files:
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/crocodile]
└─$ ftp 10.129.85.38
Connected to 10.129.85.38.
220 (vsFTPd 3.0.3)
Name (10.129.85.38:noraj): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp            33 Jun 08  2021 allowed.userlist
-rw-r--r--    1 ftp      ftp            62 Apr 20  2021 allowed.userlist.passwd
226 Directory send OK.
ftp> get allowed.userlist
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for allowed.userlist (33 bytes).
226 Transfer complete.
33 bytes received in 7.6e-05 seconds (424 kbytes/s)
ftp> get allowed.userlist.passwd
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for allowed.userlist.passwd (62 bytes).
226 Transfer complete.
62 bytes received in 0.00109 seconds (55.3 kbytes/s)
ftp> quit
221 Goodbye.
```

Those are a list of users and a list of passwords:
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/crocodile]
└─$ cat allowed.userlist
aron
pwnmeow
egotisticalsw
admin
```

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/crocodile]
└─$ cat allowed.userlist.passwd
root
Supersecretpassword1
@BaASD&9032123sADS
rKXM59ESxesUFHAd
```

Since, there was a web-server running on port 80, I checked it out next.

I used Wappalyzer, to find out the technology stack the website was using since I didn't find anything useful from the web-site and it's source-code.

From the output of Wappalyzer, we can note some of the more interesting items, specifically the PHP programming language used to build the web page. However, nothing gives us a direct plan of attack for now.

Now, I decide to run gobuster to further enumerate directories.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/three]
└─$ sudo gobuster dir -u 10.129.10.200 -w dirbuster/directory-list-2.3-small.txt -x php,html
[sudo] password for mrdev:  
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart) 
===============================================================
[+] Url:                     http://10.129.10.200  
[+] Method:                  GET 
[+] Threads:                 10
[+] Wordlist:                dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              html,php 
[+] Timeout:                 10s
===============================================================
2021/12/24 16:44:16 Starting gobuster in directory enumeration mode
=============================================================== 
/index.html           (Status: 200) [Size: 58565]
/login.php            (Status: 200) [Size: 1577]
/assets               (Status: 301) [Size: 315] [--> http://10.129.57.249/assets/]
/css                  (Status: 301) [Size: 312] [--> http://10.129.57.249/css/] 
/js                   (Status: 301) [Size: 311] [--> http://10.129.57.249/js/]
/logout.php           (Status: 302) [Size: 0] [--> login.php] 
/config.php           (Status: 200) [Size: 0]
/fonts                (Status: 301) [Size: 314] [--> http://10.129.57.249/fonts/]
/dashboard            (Status: 301) [Size: 318] [--> http://10.129.57.249/dashboard/]
Progress: 41064 / 262995 (15.61%)                                                   ^C

[!] Keyboard interrupt detected, terminating. 
===============================================================
2021/12/24 17:05:00 Finished
===============================================================  

```

One of the most interesting files gobuster retrieved is the `/login.php` page. Navigating manually to the URL, in the form of `http://10.129.57.249/login.php`, we are met with a login page asking for a `username/password` combination.

![croc-1](https://user-images.githubusercontent.com/87711310/214600894-ff0948d9-0a0b-454c-8fb3-0f2be4730e6e.png)

After attempting several `username/password` combinations from the list of usernames and passwords given, I manage to log in and met with a Server Manager admin panel. Once here, an attacker could manipulate the website in whichever way they desired, causing havoc for the userbase and owners, or extracting more information that would assist them with gaining a foothold on the servers hosting the web page.

However, for me, I was displayed the flag to complete this challenge.
