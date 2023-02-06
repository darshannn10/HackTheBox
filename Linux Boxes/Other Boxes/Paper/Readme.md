
Nmap

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Paper]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.11.143
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-06 12:30 EST
Nmap scan report for 10.10.11.143
Host is up (0.35s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE   VERSION
22/tcp  open  ssh       OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   2048 10:05:ea:50:56:a6:00:cb:1c:9c:93:df:5f:83:e0:64 (RSA)
|   256 58:8c:82:1c:c6:63:2a:83:87:5c:2f:2b:4f:4d:c3:79 (ECDSA)
|_  256 31:78:af:d1:3b:c4:2e:9d:60:4e:eb:5d:03:ec:a0:22 (ED25519)
80/tcp  open  http      Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
|_http-title: HTTP Server Test Page powered by CentOS
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
443/tcp open  ssl/https
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
|_http-title: HTTP Server Test Page powered by CentOS
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US
| Subject Alternative Name: DNS:localhost.localdomain
| Not valid before: 2021-07-03T08:52:34
|_Not valid after:  2022-07-08T10:32:34
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
Aggressive OS guesses: Android 4.1.1 (99%), Android 4.1.2 (99%), Linux 3.13 (99%), Linux 3.2 - 4.9 (99%), Android 4.2.2 (Linux 3.4) (99%), Adtran 424RG FTTH gateway (98%), AVM FRITZ!Box (FritzOS 6.03) (98%), Check Point SBox-200 firewall (98%), CyanogenMod 11 (Android 4.4.4) (98%), Dell Networking Operating System 6.2 (Linux 3.6) (98%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 73.37 seconds

```




Rustscan

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Paper]
└─$ rustscan -a 10.10.11.143 --range 1-65535                                                                  
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.11.143:22
Open 10.10.11.143:80
Open 10.10.11.143:443
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,80,443 10.10.11.143

Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-06 13:23 EST
Initiating Ping Scan at 13:23
Scanning 10.10.11.143 [2 ports]
Completed Ping Scan at 13:23, 0.18s elapsed (1 total hosts)
Initiating Connect Scan at 13:23
Scanning office.paper (10.10.11.143) [3 ports]
Discovered open port 443/tcp on 10.10.11.143
Discovered open port 22/tcp on 10.10.11.143
Discovered open port 80/tcp on 10.10.11.143
Completed Connect Scan at 13:23, 0.38s elapsed (3 total ports)
Nmap scan report for office.paper (10.10.11.143)
Host is up, received syn-ack (0.24s latency).
Scanned at 2023-02-06 13:23:20 EST for 0s

PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack
80/tcp  open  http    syn-ack
443/tcp open  https   syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.65 seconds

```


Nmap vuln scan

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Paper]
└─$ sudo nmap --script vuln 10.10.11.143 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-06 12:32 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.11.143
Host is up (0.23s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-enum: 
|   /icons/: Potentially interesting folder w/ directory listing
|_  /manual/: Potentially interesting folder
|_http-trace: TRACE is enabled
|_http-dombased-xss: Couldn't find any DOM based XSS.
443/tcp open  https
|_http-trace: TRACE is enabled
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /icons/: Potentially interesting folder w/ directory listing
|_  /manual/: Potentially interesting folder
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.

Nmap done: 1 IP address (1 host up) scanned in 78.07 seconds
                                                                    
```


wierd `Burp` request
```
HTTP/1.1 403 Forbidden
Date: Mon, 06 Feb 2023 17:47:38 GMT
Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
X-Backend-Server: office.paper
Last-Modified: Sun, 27 Jun 2021 23:47:13 GMT
ETag: "30c0b-5c5c7fdeec240"
Accept-Ranges: bytes
Content-Length: 199691
Connection: close
Content-Type: text/html; charset=UTF-8
```


gobuster didnt work, so used wfuzz

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Paper]
└─$ wfuzz -u http://office.paper -H "Host: FUZZ.office.paper" -w /usr/share/wordlists/SecLists-master/Discovery/DNS/subdomains-top1million-5000.txt
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://office.paper/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                                                                                                    
=====================================================================

000000003:   403        70 L     2438 W     199691 Ch   "ftp"                                                                                                                                                                                                                                                      
000000001:   403        70 L     2438 W     199691 Ch   "www"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     
000000158:   403        70 L     2438 W     199691 Ch   "av"                                                                                                                                                                                                                                                       
[...snip..]
000000157:   403        70 L     2438 W     199691 Ch   "cs"                                                                                                                                                                                                                                                       
000000152:   403        70 L     2438 W     199691 Ch   "ad"                                                                                                                                                                                                                                                       
000000151:   403        70 L     2438 W     199691 Ch   "c-n7k-n04-01.rz"                                                                                                                                                                                                                                          
000000150:   403        70 L     2438 W     199691 Ch   "docs"                                                                                                                                                                                                                                                     
000000149:   403        70 L     2438 W     199691 Ch   "data"                                                                                                                                                                                                                                                     
^C /usr/lib/python3/dist-packages/wfuzz/wfuzz.py:80: UserWarning:Finishing pending requests...

Total time: 0
Processed Requests: 162
Filtered Requests: 0
Requests/sec.: 0

```



Decided to use -hh

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Paper]
└─$ wfuzz -u http://office.paper -H "Host: FUZZ.office.paper" -w /usr/share/wordlists/SecLists-master/Discovery/DNS/subdomains-top1million-5000.txt --hh 199691
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://office.paper/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                                                                                                    
=====================================================================

000000070:   200        507 L    13015 W    223163 Ch   "chat"                                                                                                                                                                                                                                                     
^C /usr/lib/python3/dist-packages/wfuzz/wfuzz.py:80: UserWarning:Finishing pending requests...

Total time: 0
Processed Requests: 1086
Filtered Requests: 1085
Requests/sec.: 0

```
