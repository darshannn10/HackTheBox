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

