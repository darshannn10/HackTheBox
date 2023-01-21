# Synced

## Questions

##### What is the default port for rsync?

```
873
```

##### How many TCP ports are open on the remote host?

```
1
```

##### What is the protocol version used by rsync on the remote machine?

```
31
```

##### What is the most common command name on Linux to interact with rsync?

```
rsync
```

##### What credentials do you have to pass to rsync in order to use anonymous authentication? anonymous:anonymous, anonymous, None, rsync:rsync

```
None
```

##### What is the option to only list shares and files on rsync? (No need to include the leading -- characters)

```
list-only
```

##### Submit root flag

```
72eaf5344ebb84908ae543a719830519
```

## Command

### Scan

```
┌──(darshan㉿kali)-[~]
└─$ nmap -v -p- 10.129.228.37 --min-rate 5000
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-04 11:01 CET
Initiating Ping Scan at 11:01
Scanning 10.129.228.37 [2 ports]
Completed Ping Scan at 11:01, 0.12s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:01
Completed Parallel DNS resolution of 1 host. at 11:01, 0.03s elapsed
Initiating Connect Scan at 11:01
Scanning 10.129.228.37 [65535 ports]
...
Discovered open port 873/tcp on 10.129.228.37
...
PORT    STATE SERVICE VERSION
873/tcp open  rsync   (protocol version 31)

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.47 seconds
```

```
rsync rsync://10.129.228.37
public         	Anonymous Share
```

```
rsync rsync://10.129.228.37/public
drwxr-xr-x          4.096 2022/10/25 00:02:23 .
-rw-r--r--             33 2022/10/24 23:32:03 flag.txt
```

```
cat flag.txt
72eaXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```
