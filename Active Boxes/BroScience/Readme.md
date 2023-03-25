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

Analyzing the code, I found a name of the function that is responsible for generating the activation code: `generate_Activation_code`.
