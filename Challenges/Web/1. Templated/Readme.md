# Hack The Box Challenges - Web - Templated

### Files provided
There are no files provided which is pretty rare for an challenges in HackTheBox

## Enumeration
Since it's a web challenge, I directly visited the web-site to look at its working and found something useful

![tem-1](https://user-images.githubusercontent.com/87711310/214386057-413a0b50-678e-4981-a3f8-60624fba20fe.png)

I tried to look at the source code by inspecting elements but there is nothing interesting in the HTML source code that provided any hint. Neither were any cookies given by the website. 
![temp-2](https://user-images.githubusercontent.com/87711310/214386060-7b610545-68a9-4ad7-8e09-ef7eca096b6d.png)

Therefore, I decided to take a look at the HTTP response header in the Network Tab of Firefox and noticed something interesting. The website uses `Werkzeug`.

![tem-3](https://user-images.githubusercontent.com/87711310/214386936-45f3fa66-ec0e-40cc-8799-8987b933ac99.png)

If we Google for `Werkzeug’s exploit`, we find about `Werkzeug’s common Remote Code Execution (RCE)` method, it depends on the debugger by Werkzeug. Usually, the console is stored at `http://www.web-site.com/console`. You can even find scripts to search for the debugger online. However, when I manually input, it did not store the console and the default location. But since it is a `metasploit` exploit, I'll not be using this approach.

If we Google for `flask jinja 2 exploit`, we get an interesting way to exploit the web-site.

![tem-4](https://user-images.githubusercontent.com/87711310/214492456-dd6f960f-9ef1-4dfe-b335-c548be715327.png)

Now that I know that Flask's Jinja2 is vulnerable to `SSTI`, I checked out whether `SSTI` actually works on this web-site. So i entered a basic `SSTI` payload to check it out.

```
{{7*7}}
```

And it did work!!!

![tem-5](https://user-images.githubusercontent.com/87711310/214493672-8b0e6dd7-003a-475d-a429-6603506955c2.png)


So now all we need is a payload that could give us a `Remote Code Execution (RCE)` and luckily I found this [blog](https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/) by OnSecurity.

The payload I used was as following

```python
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

So I got an error shown by the website but the results were still displayed by the web-site, so, I guess we can pretty much leverage this vulnerabilty to obtain the flag

![tem-6](https://user-images.githubusercontent.com/87711310/214496914-ba9005d5-334f-4851-871e-e1683623a9d2.png)

Now, I simply used the `ls` command to list out the contents of the directory and found out that the flag is in the same directory.

![tem-7](https://user-images.githubusercontent.com/87711310/214496916-5c90e052-dd6b-43d7-ab6e-db0c09e2b90e.png)

So, I simply used the `cat flag.txt` to get the flag and submitted it!!

![tem-8](https://user-images.githubusercontent.com/87711310/214496921-96e0df39-08ac-4bd2-ba6b-926ec551e140.png)

