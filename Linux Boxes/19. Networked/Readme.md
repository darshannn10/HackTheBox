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
