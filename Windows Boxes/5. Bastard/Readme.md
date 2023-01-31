# Hack The Box - Bastard Walkthrough without Metasploit

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Bastard]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.9 -Pn                                  
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-31 03:59 EST
Nmap scan report for 10.10.10.9
Host is up (0.39s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Welcome to Bastard | Bastard
|_http-generator: Drupal 7 (http://drupal.org)
|_http-server-header: Microsoft-IIS/7.5
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%), Microsoft Windows Vista SP2 (91%), Microsoft Windows Vista SP2, Windows 7 SP1, or Windows Server 2008 (90%), Microsoft Windows 8.1 Update 1 (90%), Microsoft Windows Phone 7.5 or 8.0 (90%), Microsoft Windows 7 or Windows Server 2008 R2 (90%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 101.86 seconds

```

We get back the following result showing that 3 ports are open:
- Port `80`: running `Microsoft IIS httpd 7.5`.
- Port `135`: running `Microsoft Windows RPC`
- Port `49154`: running `Microsoft Windows RPC`

Before starting enumeration, I ran a more comprehensive scan in the background to make sure that I did not miss anything.

So I ran `Rustscan` that covers all ports.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Bastard]
└─$ rustscan -a 10.10.10.9 --range 1-65535
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.10.9:80
Open 10.10.10.9:135
Open 10.10.10.9:49154
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 80,135,49154 10.10.10.9

Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-31 04:14 EST
Initiating Ping Scan at 04:14
Scanning 10.10.10.9 [2 ports]
Completed Ping Scan at 04:14, 0.12s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 04:14
Completed Parallel DNS resolution of 1 host. at 04:14, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 04:14
Scanning 10.10.10.9 [3 ports]
Discovered open port 135/tcp on 10.10.10.9
Discovered open port 49154/tcp on 10.10.10.9
Discovered open port 80/tcp on 10.10.10.9
Completed Connect Scan at 04:14, 0.43s elapsed (3 total ports)
Nmap scan report for 10.10.10.9
Host is up, received syn-ack (0.22s latency).
Scanned at 2023-01-31 04:14:46 EST for 0s

PORT      STATE SERVICE REASON
80/tcp    open  http    syn-ack
135/tcp   open  msrpc   syn-ack
49154/tcp open  unknown syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.62 seconds

```

## Enumeration
Now that port `80` was open, I visited the web-page on port `80`, and found out a `Drupal` page without any content and a login form.

