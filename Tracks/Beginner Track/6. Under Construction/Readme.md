# Challenge Description
A company that specialises in web development is creating a new site that is currently under construction. Can you obtain the flag?

# Enumeration
Visiting the web page, we are presented with a `login` form with 2 input fields.

If we try to register, it will throw an error `username not registered` kind of thing. So we can follow the normal flow by registering and then signing in.

![uc-1](https://user-images.githubusercontent.com/87711310/211182771-b415cb39-8413-4981-acd3-e4195e805833.png)

Once we're done with registering, we can login using the same credentials and are redirected to `home` page of the website.

There's nothing special about the flow, just a simple flow. To be honest, I suspected this challenge will be about SQL injection (because of the login and register page)

I then realised that i forgot to perform some basic checks such as running nmap, gobuster, and nikto to gather more information about the website

Running Nmap on default ports didn't yield any fruitful results
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Beginner-Path/Under-Construction]
└─$ nmap -sC -sV -A -oA nmap 138.68.182.130 -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-08 01:04 EST
Nmap scan report for 138.68.182.130
Host is up (0.17s latency).
All 1000 scanned ports on 138.68.182.130 are in ignored states.
Not shown: 905 filtered tcp ports (no-response), 95 closed tcp ports (conn-refused)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.46 seconds
```

Running `gobuster` also revealed the data we already knew, so its of no use
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Beginner-Path/Under-Construction]
└─$ gobuster dir -u http://138.68.182.130:31787 -w /usr/share/wordlists/SecLists-master/Discovery/Web-Content/common.txt -t 200
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://138.68.182.130:31787
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/wordlists/SecLists-master/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/01/08 01:05:32 Starting gobuster in directory enumeration mode
===============================================================
/auth                 (Status: 200) [Size: 2149]
/logout               (Status: 302) [Size: 27] [--> /auth]
                                                          
===============================================================
2023/01/08 01:05:38 Finished
===============================================================
                                                                
```

And... running `nikto` also didnt reveal any useful data 
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Beginner-Path/Under-Construction]
└─$ nikto -h 138.68.182.130:31787
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          138.68.182.130
+ Target Hostname:    138.68.182.130
+ Target Port:        31787
+ Start Time:         2023-01-08 01:09:28 (GMT-5)
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ Retrieved x-powered-by header: Express
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Root page / redirects to: /auth
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: GET, HEAD 
+ OSVDB-3092: /auth/: This might be interesting...
+ ERROR: Error limit (20) reached for host, giving up. Last error: opening stream: can't connect (connect error): Network is unreachable
+ Scan terminated:  9 error(s) and 6 item(s) reported on remote host
+ End Time:           2023-01-08 01:46:15 (GMT-5) (2207 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

So i further examined the developer tools to check if there's any information about anything. I saw the `dynamic` welcome message therefore, I suspected that this might be a `JWT` challenge as well. So I opened the developer tools and go to the application tab and cookies section.

![uc-3](https://user-images.githubusercontent.com/87711310/211183335-fabc596a-aec1-448a-8cb6-ea1a787cc4f3.png)

If we see at the cookies stored under the session variable, it is a type of the JWT token (it starts with ey….. and has 3 separation dots). We can examine the JWT by using [jwt.io](https://jwt.io/).

![uc-4](https://user-images.githubusercontent.com/87711310/211183339-d1dfd5bc-781a-41c5-952e-8a0bc6d13c09.png)

From the JWT examination, we can see that this is an `asymmetric` JWT that is using `private` and `public` keys instead of a `secret` key like in `symmetric` JWT.


After googling a few stuff, I suspected that it can be a [JWT key confusion attack](https://portswigger.net/web-security/jwt/algorithm-confusion), although I was not exactly sure about it.

But before that, I looked at the source code files provided to us

## Source Code Analysis
When we open the source code, we immediately recognize that it is `node.js` with the `express` framework. Before I start even further, I want to tell you that by this point, I never build anything using express.js. Basically, all the knowledge I know is by googling it (and maybe a little intuition).

I first started by looking at the `index.js` file

 We can also see an endpoint to `./routes`. There's nothing much in the code apart from the rules related to the listening ports and how the request shoud be handled.
 
```javascript
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const routes = require('./routes');
const nunjucks = require('nunjucks');

app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

nunjucks.configure('views', {
    autoescape: true,
    express: app
});
app.set('views','./views');

app.use(routes);

app.all('*', (req, res) => {
    return res.status(404).send('404 page not found');
});

app.listen(1337, () => console.log('Listening on port 1337'));                                                                                                                                                                                                                                                                                                                            

```

I then inspected the `./routes/index.js` file.

```javascript
const express = require('express');
const router = express.Router();
const path = require('path');
const AuthMiddleware = require('../middleware/AuthMiddleware');
const JWTHelper = require('../helpers/JWTHelper');
const DBHelper = require('../helpers/DBHelper');

router.get('/', AuthMiddleware, async (req, res, next) => {
    try{
        let user = await DBHelper.getUser(req.data.username);
        if (user === undefined) {
            return res.send(`user ${req.data.username} doesn't exist in our database.`);
        }
        return res.render('index.html', { user });
    }catch (err){
        return next(err);
    }
});

router.get('/auth', (req, res) => 
    res.render('auth.html', { query: req.query }));

router.get('/logout', (req, res) => {
    res.clearCookie('session');
    return res.redirect('/auth');
});

router.post('/auth', async (req, res) => {
    const { username, password } = req.body;
    if((username !== undefined && username.trim().length === 0) 
        || (password !== undefined && password.trim().length === 0)){
        return res.redirect('/auth');
    }
    if(req.body.register !== undefined){
        let canRegister = await DBHelper.checkUser(username);
        if(!canRegister){
            return res.redirect('/auth?error=Username already exists');
        }
        DBHelper.createUser(username, password);
        return res.redirect('/auth?error=Registered successfully&type=success');
    }

    // login user
    let canLogin = await DBHelper.attemptLogin(username, password);
    if(!canLogin){
        return res.redirect('/auth?error=Invalid username or password');
    }
    let token = await JWTHelper.sign({
        username: username.replace(/'/g, "\'\'").replace(/"/g, "\"\"")
    })
    res.cookie('session', token, { maxAge: 900000 });
    return res.redirect('/');
});

module.exports = router;                                                                                                                                                                                                                                                                                                                            
```

After carefully looking at the code, we find several endpoints. 
1. `/` with GET method
2. `/auth` with GET method
3. `/logout` with GET method
4. `/auth` with POST method

Along with the endpoints, I also noticed that the `/auth` is used for both login and registeration, which is then sent to the database for authenticating the user credentials.

`/` with the first landing endpoint, and `/logout` is to clear session or to redirect to auth. I was interested in `/` endpoint, so I examined it further.

```javascript
router.get('/', AuthMiddleware, async (req, res, next) => {
    try{
        let user = await DBHelper.getUser(req.data.username);
        if (user === undefined) {
            return res.send(`user ${req.data.username} doesn't exist in our database.`);
        }
        return res.render('index.html', { user });
    }catch (err){
        return next(err);
    }
});

```

This code is from `./route/index.js` and I found it pretty challenging because I did not understand about middleware, and helper , so i just tried to guess. 

My guess was that every time the `/` route is called, the `router.get("/"…..)` is triggered, but before it executes its code (starts from try{ … ) it calls the `AuthMiddleware` first, and maybe in AuthMiddleware, it'll produce a true or false value that will decide whether we are allowed to continue or not.

Say that we are allowed to continue then it will crosscheck the username to the database, if the user does not exist, display the error message, and display the index.html otherwise.

By looking at the `/middleware/AuthMiddleware.js` file, I think that it's just checking the JWT to verify whether it's expired or if it can be modified or not.

If it passes all the check and the JWT is valid then take the username and check to the database. If the user exists, display the homepage otherwise display the error message.

```javascript
const JWTHelper = require('../helpers/JWTHelper');

module.exports = async (req, res, next) => {
    try{
        if (req.cookies.session === undefined) return res.redirect('/auth');
        let data = await JWTHelper.decode(req.cookies.session);
        req.data = {
            username: data.username
        }
        next();
    } catch(e) {
        console.log(e);
        return res.status(500).send('Internal server error');
    }
}                                                                                                                                                                                                                                                                                                                            
```
So, if the application will redirect to the `/auth` if the cookie doesn't exist, put to req.data if the decoding valid, and send the `internal server error` message if it fails to decode the JWT.

Just to be sure, I'll look at the `/helpers/JWTHelper.js` file too.

```javascript
const fs = require('fs');
const jwt = require('jsonwebtoken');

const privateKey = fs.readFileSync('./private.key', 'utf8');
const publicKey  = fs.readFileSync('./public.key', 'utf8');

module.exports = {
    async sign(data) {
        data = Object.assign(data, {pk:publicKey});
        return (await jwt.sign(data, privateKey, { algorithm:'RS256' }))
    },
    async decode(token) {
        return (await jwt.verify(token, publicKey, { algorithms: ['RS256', 'HS256'] }));
    }
}                                                                                                                                                                                                                                                                                                                            
```
Again, I'm not really sure about what is going but, I think the `decode` function is allowed to decode the JWT `asymmetrically` and `symmetrically` because it allows us to use `RS256` algorithm (Asym) and `HS256` (Sym). I think it is the `JWT key confusion` exploit.

Now, I looked at the `/helpers/DBHelper.js` file. 

The `getUser()` function is called to check whether the user exists or not

Apart from `getUser()`, I also saw few other functions such as `checkUser()`, `createUser()` and `attemptLogin()` which basically helps the web page in `Login` and `Register` aspects.

However, if we see the detail, we know that `getUser()` is vulnerable to SQL injection because it takes the username and directly appends to the existing query.


### Going back to the `JWT Key Confusion` part
```
-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA95oTm9DNzcHr8gLhjZaY\nktsbj1KxxUOozw0trP93BgIpXv6WipQRB5lqofPlU6FB99Jc5QZ0459t73ggVDQi\nXuCMI2hoUfJ1VmjNeWCrSrDUhokIFZEuCumehwwtUNuEv0ezC54ZTdEC5YSTAOzg\njIWalsHj/ga5ZEDx3Ext0Mh5AEwbAD73+qXS/uCvhfajgpzHGd9OgNQU60LMf2mH\n+FynNsjNNwo5nRe7tR12Wb2YOCxw2vdamO1n1kf/SMypSKKvOgj5y0LGiU3jeXMx\nV8WS+YiYCU5OBAmTcz2w2kzBhZFlH6RK4mquexJHra23IGv5UJ5GVPEXpdCqK3Tr\n0wIDAQAB\n-----END PUBLIC KEY-----\n
```

So after using [jwt.io](https://jwt.io) for decoding the `JWT`, I copied the `Public Key` and tried to make it in the correct format (i.e replacing all the “\n” with “enter / new line”)

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA95oTm9DNzcHr8gLhjZaY
ktsbj1KxxUOozw0trP93BgIpXv6WipQRB5lqofPlU6FB99Jc5QZ0459t73ggVDQi
XuCMI2hoUfJ1VmjNeWCrSrDUhokIFZEuCumehwwtUNuEv0ezC54ZTdEC5YSTAOzg
jIWalsHj/ga5ZEDx3Ext0Mh5AEwbAD73+qXS/uCvhfajgpzHGd9OgNQU60LMf2mH
+FynNsjNNwo5nRe7tR12Wb2YOCxw2vdamO1n1kf/SMypSKKvOgj5y0LGiU3jeXMx
V8WS+YiYCU5OBAmTcz2w2kzBhZFlH6RK4mquexJHra23IGv5UJ5GVPEXpdCqK3Tr
0wIDAQAB
-----END PUBLIC KEY-----
```


![uc-5](https://user-images.githubusercontent.com/87711310/211186464-65bd5768-58c9-41cb-bac2-eb6932221d5b.png)

You can see that the `blue part` of the JWT, which is the signature does not change and it indicates the signature is verified which means the JWT is authentic.

## A Little JWT Key Confusion Exploit Explanation

JWT key confusion attack is simply using the public key as our new signing secret key. How this vulnerability exists? When an application using asymmetric JWT, it will craft the header and payload and sign them with the application’s private key. The JWT is sent out to the public. Whenever somebody (including the application itself) wants to check if this token is authentic or not, they can use the application’s public key (which is normal when the key is in public) to verify whether the JWT is authentic or not. For example, in this challenge, we can check whether the JWT is authentic or not.

Back to the topic explaining the vulnerability. So, we understand about the asymmetric JWT signing. There is another style of signing which is the symmetric signing. Symmetric signing uses 1 symmetric key to sign and to verify the token. For example, I have this token

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImhlbGxvIn0.AQ_ocqPfoEN5bt0w-B95wLbtPAh0H3QK8YEhuOpHlnI
```

You can open again the same platform and decode the token.

![uc-6](https://user-images.githubusercontent.com/87711310/211186617-5db0e228-ff3e-4832-acc6-649386dc377f.png)

Now to verify it, we need the secret string that signs our token beforehand, and of course, we do not know because it is only the application authority to verify whether the JWT is valid or not, we are not meant to verify or even check the validity of the token.

Okay, do you get the flaw?

The asymmetric signing requires the application’s public key to verify the signature that is signed by the application’s private key, which is really hard to tamper with because the private key remains private. On the other hand, the symmetric signing requires a secret string to verify the signature that is signed by the application’s same secret string.

Wait… hold on…. it is interesting. When the private key is produced, the public key is also been produced. So of course the application knows and public key. We also know the public key, then why we do not treat this public key as the “secret string” and use the symmetric procedure instead?

This is the JWT key confusion exploit comes. If we can change the algorithm of signing from RSxxx to HSxxx and the library that handles this JWT is still buggy, we can trick the application into verifying the signature as symmetric signing using the public key because the application thinks that the public key is the “secret string”!

What is the advantage? The advantage is, we can modify the payload, sign them with the public key they sent to us and send to the system and force them to verify the signature using the same public key and our payload will be considered as valid or authentic.

So, I guess, what we really need to do is: ```To modify the JWT and somehow bypass the JWT validation check and use SQL Injection to get the information we need```

## Attack Preparation
So basically we need 2 things.
```
1. A tool that can modify JWT
2. SQLite 3 knowledge to SQL injection
```

### 1. A Tool that can Modify JWT
After long research, I finally found a tool that is referenced from several blogs, which is [jwt_tool.py](https://github.com/ticarpi/jwt_tool). 

All the documentation and installation can be read on its GitHub page.

For the usage, you can reade at its [attack book](https://github.com/ticarpi/jwt_tool/wiki).

### 2. SQLite 3 Knowledge to SQL Injection
I need several queries to do the attack

- How to get the tables name
- How to get the columns name

And using few writeups, I finally wrote the query which i think might work

```
#Get Tables
’ union select name,1 from sqlite_master where type='table' and name not like 'sqlite_%'--; 
#Get Columns
' union select sql,1 from sqlite_master where tbl_name = 'users' and type = 'table';--
```

We are using the `union` exploit here hence, keep in mind that the union query needs the count of selected columns from both queries is equal. So we will identify the columns count first later.

## Attacking
I used `Burp Suite` additionally to make the requesting process easier and faster. The page that will be injected is the page after login, we send the request to the repeater.

![uc-7](https://user-images.githubusercontent.com/87711310/211187043-9a0aee8f-7f26-43b4-b2bd-ab9de2e5a577.png)

Using the `JWT tool` to modify the toke and use the exploit for key confusion


---
Will come back later
---
