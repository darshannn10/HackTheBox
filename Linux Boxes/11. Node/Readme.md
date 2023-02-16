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

```

