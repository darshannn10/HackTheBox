# Hack The Box - BroScience Walkthrough

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/BroScience]
└─$ sudo nmap -sC -sV -oA nmap/tcp -p- --min-rate 1500 10.10.11.195
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-22 09:49 EDT
Nmap scan report for 10.10.11.195
Host is up (0.19s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 df17c6bab18222d91db5ebff5d3d2cb7 (RSA)
|   256 3f8a56f8958faeafe3ae7eb880f679d2 (ECDSA)
|_  256 3c6575274ae2ef9391374cfdd9d46341 (ED25519)
80/tcp  open  http     Apache httpd 2.4.54
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: Did not follow redirect to https://broscience.htb/
443/tcp open  ssl/http Apache httpd 2.4.54 ((Debian))
|_http-server-header: Apache/2.4.54 (Debian)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=broscience.htb/organizationName=BroScience/countryName=AT
| Not valid before: 2022-07-14T19:48:36
|_Not valid after:  2023-07-14T19:48:36
| tls-alpn: 
|_  http/1.1
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: BroScience : Home
Service Info: Host: broscience.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 71.66 seconds
```

Before starting the enumeration, I wanted to check if any other ports were open, so I ran `rustscan` to quickly check if any other ports were open.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/BroScience]
└─$ rustscan -a 10.10.11.195 --range 1-65535
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.11.195:22
Open 10.10.11.195:80
Open 10.10.11.195:443
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,80,443 10.10.11.195

Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-22 09:51 EDT
Initiating Ping Scan at 09:51
Scanning 10.10.11.195 [2 ports]
Completed Ping Scan at 09:51, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 09:51
Completed Parallel DNS resolution of 1 host. at 09:51, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 09:51
Scanning 10.10.11.195 [3 ports]
Discovered open port 80/tcp on 10.10.11.195
Discovered open port 22/tcp on 10.10.11.195
Discovered open port 443/tcp on 10.10.11.195
Completed Connect Scan at 09:51, 0.19s elapsed (3 total ports)
Nmap scan report for 10.10.11.195
Host is up, received syn-ack (0.19s latency).
Scanned at 2023-03-22 09:51:09 EDT for 0s

PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack
80/tcp  open  http    syn-ack
443/tcp open  https   syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.42 seconds
```

Both `Nmap` & `rustscan` reported `3` ports to be open:
- port `22`: running `OpenSSH 8.4p1`
- port `80`: running `Apache httpd 2.4.54`
- port `445`: running `Apache httpd 2.4.54`

`Nmap` scan also showed the host name as `broscience.htb` on port `80`. So I added the host to my `/etc/hosts` file.

```
sudo echo '10.10.11.195  broscience.htb' >> /etc/hosts
```

## Enumeration
Visiting the website on port `80`, I saw that I was redirected to port `443` i.e `https` 

![image](https://user-images.githubusercontent.com/87711310/226926885-765b3836-3733-4dc5-80d1-f23d6127c02b.png)

Viewing the SSL certificate, I found an email address that the website contains.

![image](https://user-images.githubusercontent.com/87711310/226927356-ce3aeaa2-f626-48a0-a995-a95a820a0751.png)

On clicking one of the articles written by admin, I was redirected to another page and found out this info

![image](https://user-images.githubusercontent.com/87711310/226935305-38e4b9f2-84b2-42c6-917b-b28d8e2f5750.png)

Using the `id` parameter, I was able to view the users with different ids.

![image](https://user-images.githubusercontent.com/87711310/226935643-985b33bb-4f54-48cf-b597-20c560b7c70e.png)

![image](https://user-images.githubusercontent.com/87711310/226935735-e0d8875f-42f4-4cd4-a2bc-051494eb01c9.png)

So, the list of user's on the web page were: 
- administrator
- bill
- micheal
- john
- dmytro

So, next obvious step was to try and brute-force the credentials with `hydra`.

```
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -s 443 broscience.htb https-post-form "/login.php:username=^USER^&password=^PASS^:danger"
```

But, it didn't work.

On further enumerating the website, I found out that the images were not referenced directly but rather fetched using a potential LFI in PHP, i.e. `/includes/img.php?path=bench.png`

So, I started with basic LFI payloads, trying anything with `../` displays `Error: Attack deected.`




