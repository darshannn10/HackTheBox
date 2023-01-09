## Challenge Description
You've just received an invitation to a party. Authorities have reported that the party is cursed, and the guests are trapped in a never-ending unsolvable murder mystery party. Can you investigate further and try to save everyone?

## Solution
Downloading the provided files and unzipping them, we have the source code of an application built with `Express.js`.

In `routes/index.js`, we see that there are two routes `/api/submit` and `/admin.`

```javascript
┌──(darshan㉿kali)-[~/…/HacktheBoo-ctf-2022/Cursed-secret-party/web_cursed_party/challenge]
└─$ cat routes/index.js      
const express = require('express');
const router = express.Router({ caseSensitive: true });
const AuthMiddleware = require('../middleware/AuthMiddleware');
const bot = require('../bot');

let db;

const response = data => ({ message: data });

router.get('/', (req, res) => {
    return res.render('index.html');
});

router.post('/api/submit', (req, res) => {
    const { halloween_name, email, costume_type, trick_or_treat } = req.body;

    if (halloween_name && email && costume_type && trick_or_treat) {

        return db.party_request_add(halloween_name, email, costume_type, trick_or_treat)
            .then(() => {
                res.send(response('Your request will be reviewed by our team!'));

                bot.visit();
            })
            .catch(() => res.send(response('Something Went Wrong!')));
    }

    return res.status(401).send(response('Please fill out all the required fields!'));
});

router.get('/admin', AuthMiddleware, (req, res) => {
    if (req.user.user_role !== 'admin') {
        return res.status(401).send(response('Unautorized!'));
    }

    return db.get_party_requests()
        .then((data) => {
            res.render('admin.html', { requests: data });
        });
});

router.get('/admin/delete_all', AuthMiddleware, (req, res) => {
    if (req.user.user_role !== 'admin') {
        return res.status(401).send(response('Unautorized!'));
    }
    
    return db.remove_requests()
            .then(() => res.send(response('All records are deleted!')));
})

module.exports = database => {
    db = database;
    return router;
};  
```

And this is what the web application looks like.

![cps-2](https://user-images.githubusercontent.com/87711310/211354800-c5d19cf0-0a2c-4dcc-846e-a7f671d671e1.png)

We can submit the details on the web page and it issues the following HTTP request.

```BurpSuite
POST /api/submit HTTP/1.1
Host: 167.71.138.188:32102
Content-Length: 190
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://167.71.138.188:32102
Referer: http://167.71.138.188:32102/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
 
{
    "halloween_name": "test",
    "email": "test@test.com",
    "costume_type": "monster",
    "trick_or_treat": "tricks"
}

```

Once the request is submitted, we get the following message.
```
Your request will be reviewed by our team! 
```

So it seems like, there's a `bot` running in the background which would visit the `/admin` route and view our submitted data. The `/admin` endpoint pulls all the submitted requests from the database and then renders them in the `admin.html` template.

```javascript
router.get('/admin', AuthMiddleware, (req, res) => {
    if (req.user.user_role !== 'admin') {
        return res.status(401).send(response('Unautorized!'));
    }

    return db.get_party_requests()
        .then((data) => {
            res.render('admin.html', { requests: data });
        });
});
```

However, in `admin.html`, we see a problem.

![cps-3](https://user-images.githubusercontent.com/87711310/211361076-d4ba1cf9-fefb-4902-bdc0-baccb0b03606.png)

When it outputs the `halloween_name` input parameter, it marks it as safe. Which means that it would not escape it to prevent `Cross-Site scripting` attacks.

So, now we have a stored `Cross-Site scripting` vulnerability, and a bot would view it with the permissions of an `admin` user. Let's see what this bot is and how it works.

![cps-4](https://user-images.githubusercontent.com/87711310/211361436-11d06367-eb9d-438a-8613-551d15b06e32.png)

We see that the bot authenticates as an administrator by setting an `admin JWT token` in the cookie. And the payload of this JWT token has the `flag`. Then it visits the endpoint `/admin` to view all the submitted requests and then it deletes them all by visiting the `/admin/delete_all` endpoint.

All we need to do is steal the cookies of the bot user by exploiting the stored `Cross-Site scripting` vulnerability to get the flag. This is fairly easy. Or is it?

Reviewing the `index.js` file I found one catch. The application sets a strict `Content-Security-Policy` header.

```javascript
app.use(function (req, res, next) {
    res.setHeader(
        "Content-Security-Policy",
        "script-src 'self' https://cdn.jsdelivr.net ; style-src 'self' https://fonts.googleapis.com; img-src 'self'; font-src 'self' https://fonts.gstatic.com; child-src 'self'; frame-src 'self'; worker-src 'self'; frame-ancestors 'self'; form-action 'self'; base-uri 'self'; manifest-src 'self'"
    );
    next();
});

```










