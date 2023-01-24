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

If we Google for `Werkzeug’s exploit`, we find about `Werkzeug’s common Remote Code Execution (RCE)` method, it depends on the debugger by Werkzeug. Usually, the console is stored at `http://www.xxxxxx.com/console`. You can even find scripts to search for the debugger online. However, when I manually input, it did not store the console and the default location. However, it shouldn’t be a `dirbuster` challenge.
