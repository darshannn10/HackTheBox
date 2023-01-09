## Challenge Description
An organization seems to possess knowledge of the true nature of pumpkins. Can you find out what they honestly know and uncover this centuries-long secret once and for all?

Downloading the provided files and unzipping them, there was a `entrypoint.sh`. We have the source code of a PHP application. The challenge name suggests that this would be a [type juggling](https://medium.com/swlh/php-type-juggling-vulnerabilities-3e28c4ed5c09https://medium.com/swlh/php-type-juggling-vulnerabilities-3e28c4ed5c09) vulnerability. 

I didnt know much about __PHP type juggling Vulnerabilities__, so I had to read a few articles about it before diving into the challenge.

In the file `entrypoint.sh` on line # `100`, we see that the `flag` is stored in the database table `facts`.

```php
INSERT INTO facts(fact, fact_type) VALUES
...
...
...
(
    'HTB{f4k3_fl4g_f0r_t3st1ng}',
    'secrets'
);
```

And it's stored as `fact_type` of secrets.

In file `/challenge/index.php`, we see an `API route` to `getfacts` which points to getfacts method in `IndexController`.

![tj-1](https://user-images.githubusercontent.com/87711310/211289766-96d77e67-8f38-47d9-928f-a8db2e64e793.png)

If we visit the web application, this is what it looks like.

![tj-2](https://user-images.githubusercontent.com/87711310/211290106-51a47589-fb68-4107-9bce-76c832b63d52.png)

And it issues the following HTTP request

```
POST /api/getfacts HTTP/1.1
Host: 167.71.137.174:30671
Content-Length: 17
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://167.71.137.174:30671
Referer: http://167.71.137.174:30671/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
 
{"type":"spooky"}
```

Which returns all the facts having `fact_type` of `spooky`. So ideally, we should be able to change this request and specify type `secrets` to get the flag, unless the application doesn't let us. Let's take a look at the `getfacts` method in `IndexController`.

![tj-3](https://user-images.githubusercontent.com/87711310/211291472-7145f7bf-36a9-48c8-bd90-a3c3396a5bb9.png)

There are quite a few checks here which would prevent us to enter type `secrets`.

First, the `type` JSON key cannot be empty. Second, If we're specifying the type `secrets`, the request has to be issued from the localhost `127.0.0.1`. And this is a strict comparison with `===`.

So one thing is for sure, that to bypass these two checks, we cannot send an empty type or a type with a value of `secrets`.

Let's see what happens if we do not send the type of `secrets`. In that case, the code lands on a `switch case` block. Which looks interesting. Because in PHP, `switch case` performs a `loose comparison` as mentioned in the PHP docs. Which makes it vulnerable to `type juggling` attacks.

So the comparison would look like:
```
$jsondata['type'] == 'secrets'
```

Now, we cannot supply a type `secrets` as input because of the above if condition with localhost restriction. However, we can supply a value which is not `secrets` but still passes this loose comparison.

To figure out what input value we should use, let's take a look at the [PHP type comparison documentation](https://www.php.net/manual/en/types.comparisons.php).

It says `true` compared with any string (php in this example) should always return `true`.

So what if we supply a `type` with a Boolean value of `true`. This is what our payload would look like.

```
POST /api/getfacts HTTP/1.1
Host: 167.71.137.174:30671
Content-Length: 13
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://167.71.137.174:30671
Referer: http://167.71.137.174:30671/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
 
{"type":true}
```

It works and we get our flag.

![tj-4](https://user-images.githubusercontent.com/87711310/211293053-ccad2beb-e853-43f9-b03b-3f3a781847af.png)
