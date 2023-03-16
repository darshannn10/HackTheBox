# Hack The Box - SwagShop Walkthrough w/o Metasploit

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Investigation]
└─$ nmap -Pn -T4 -p- --min-rate=1000 -sV 10.10.11.197
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-16 10:38 EDT
Warning: 10.10.11.197 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.11.197
Host is up (0.12s latency).
Not shown: 65479 closed tcp ports (conn-refused), 54 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41
Service Info: Host: eforenzics.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 91.49 seconds
```


Before starting the enumeration, I wanted to check if any other ports were open, so I ran `rustscan` to quickly check if any other ports were open.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Investigation]
└─$ rustscan -a 10.10.11.197 --range 1-65535
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.11.197:22
Open 10.10.11.197:80
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,80 10.10.11.197

Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-16 10:40 EDT
Initiating Ping Scan at 10:40
Scanning 10.10.11.197 [2 ports]
Completed Ping Scan at 10:40, 0.13s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 10:40
Completed Parallel DNS resolution of 1 host. at 10:40, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 10:40
Scanning 10.10.11.197 [2 ports]
Discovered open port 22/tcp on 10.10.11.197
Discovered open port 80/tcp on 10.10.11.197
Completed Connect Scan at 10:40, 0.12s elapsed (2 total ports)
Nmap scan report for 10.10.11.197
Host is up, received syn-ack (0.13s latency).
Scanned at 2023-03-16 10:40:47 EDT for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.29 seconds
```

So, `nmap` & `rustscan`, both, found `2` open ports:
- port `22`: running `OpenSSH 8.2p1`
- port `80`: running `Apache httpd 2.4.41`

## Enumeration
I started the enumeration by visiting the web portal on port `80`. Before visiting the portal I added the host to my `/etc/hosts` file. 

```
sudo echo `10.10.11.197 eforenzics.htb` >> /etc/hosts
```

The portal allowed users to upload a `JPG` file and provide analytical information.

![image](https://user-images.githubusercontent.com/87711310/225653950-d92f3ab8-8c30-4113-9992-40ee8eb46e30.png)

I uploaded an image and clicked the link it provided, there was a text file that contained `Exiftool` output details and the version of `Exiftool` was also given, which was `12.37`

![image](https://user-images.githubusercontent.com/87711310/225654341-6aa794bb-a18f-4265-9cd5-9d13b1ef2561.png)

So, i googled about `Exiftool 12.37` and I found out that it was vulnerable to [CVE-2022-23935](https://gist.github.com/ert-plus/1414276e4cb5d56dd431c2f0429e4429)

In a nutshell, if the attacker provides a file with a name ending with | character, the tool will treat it as a pipe and execute it as an OS command.

So, I decided to start `BurpSuite` to intercept the packet, and changed the `filename` parameter to a `ping` command to verify the vulnerability/



