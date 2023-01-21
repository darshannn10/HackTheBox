# Preignition

## Questionnaire

##### What is considered to be one of the most essential skills to possess as a Penetration Tester?

```
dir busting
```

##### What switch do we use for nmap’s scan to specify that we want to perform version detection

```
-sV
```

##### What service type is identified as running on port 80/tcp in our nmap scan?

```
http
```

##### What service name and version of service is running on port 80/tcp in our nmap scan?

```
nginx 1.14.2
```

##### What is a popular directory busting tool we can use to explore hidden web directories and resources?

```
gobuster
```

##### What switch do we use to specify to gobuster we want to perform dir busting specifically?

```
dir
```

##### What page is found during our dir busting activities?

```
admin.php
```

##### What is the status code reported by gobuster upon finding a successful page?

```
200
```

##### Submit root flag

```
HTB{6483bee07c1c1d57f14e5b0717503c73}
```

## Commands

### Scan

```
┌──(darshan㉿kali)-[~]
└─$ sudo nmap -sC -sV -O -T4 10.129.37.125 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-21 09:20 EST
Nmap scan report for 10.129.37.125
Host is up (0.19s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Welcome to nginx!
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=1/21%OT=80%CT=1%CU=30184%PV=Y%DS=2%DC=I%G=Y%TM=63CBF4D
OS:E%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=108%GCD=1%ISR=108%TI=Z%CI=Z%TS=A)OPS(O1=M537ST11NW7%O2=M537ST11NW7%O
OS:3=M537NNT11NW7%O4=M537ST11NW7%O5=M537ST11NW7%O6=M537ST11)WIN(W1=FE88%W2=
OS:FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M537NNSN
OS:W7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%D
OS:F=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O
OS:=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.90 seconds

```

## Visiting the web-page

![pre-1](https://user-images.githubusercontent.com/87711310/213871156-b37a5587-a092-450c-9ce6-2d5b1013aa90.png)

## Brute-forcing directories

```
┌──(darshan㉿kali)-[~]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.129.37.125
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.37.125
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/01/21 09:21:06 Starting gobuster in directory enumeration mode
===============================================================
admin.php
```

## Visiting Adming page and retrieving flag

![pre-2](https://user-images.githubusercontent.com/87711310/213871161-4b9d9c03-f6ac-483f-b5b1-8aed27f94c69.png)

