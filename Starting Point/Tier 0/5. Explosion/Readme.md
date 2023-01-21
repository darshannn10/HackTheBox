# Explosion

## Questionnaire

##### What does the 3-Letter acronym RDP stand for?

```
Remote Desktop Protocol
```

##### What is a 3-letter acronym that refers to the interaction with the host through a command line interface?

```
CLI
```

##### What about a graphical user interface interactions?

```
GUI
```

##### What is the name of an old remote access tool that came without encryption by default?

```
telnet
```

##### What is the concept used to verify the identity of the remote host with SSH connections?

```
public
```

##### What is the name of the tool that we can use to initiate a desktop projection to our host using the terminal?

```
xfreerdp
```

##### What is the name of the service running on port 3389 TCP?

```
ms-wbt-server
```

##### What us the switch used to specify the target host’s IP address when using xfreerdp?

```
/v:
```

##### Submit root flag:

```
HTB{951fa96d7830c451b536be5a6be008a0}
```

## Commands

### Scan

```
┌──(darshan㉿kali)-[~]
└─$ sudo nmap -sC -sV -O -T4 10.129.37.122 
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-21 09:13 EST
Nmap scan report for 10.129.37.122
Host is up (0.27s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: EXPLOSION
|   NetBIOS_Domain_Name: EXPLOSION
|   NetBIOS_Computer_Name: EXPLOSION
|   DNS_Domain_Name: Explosion
|   DNS_Computer_Name: Explosion
|   Product_Version: 10.0.17763
|_  System_Time: 2023-01-21T14:14:10+00:00
| ssl-cert: Subject: commonName=Explosion
| Not valid before: 2023-01-20T14:12:09
|_Not valid after:  2023-07-22T14:12:09
|_ssl-date: 2023-01-21T14:14:18+00:00; +1s from scanner time.
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=1/21%OT=135%CT=1%CU=43280%PV=Y%DS=2%DC=I%G=Y%TM=63CBF3
OS:39%P=x86_64-pc-linux-gnu)SEQ(SP=FB%GCD=1%ISR=10F%TI=I%CI=I%II=I%TS=U)SEQ
OS:(SP=F5%GCD=1%ISR=111%CI=I%TS=U)SEQ(SP=F1%GCD=1%ISR=111%CI=I%II=I%TS=U)OP
OS:S(O1=M537NW8NNS%O2=M537NW8NNS%O3=M537NW8%O4=M537NW8NNS%O5=M537NW8NNS%O6=
OS:M537NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%DF=Y
OS:%T=80%W=FFFF%O=M537NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=
OS:)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T
OS:=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=
OS:0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RU
OS:D=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-01-21T14:14:13
|_  start_date: N/A

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.39 seconds

```


## XfreeRDP

```
┌──(darshan㉿kali)-[~]
└─$ xfreerdp /v:10.129.37.122 /u:Administrator
...
Do you trust the above certificate? (Y/T/N) Y
Password: 

```

![explosion](https://user-images.githubusercontent.com/87711310/213870888-d79e8240-353a-44ea-b422-0a9fff5653d6.png)
