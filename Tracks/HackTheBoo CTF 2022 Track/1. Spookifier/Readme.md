## Challenge Description
There's a new trend of an application that generates a spooky name for you. Users of that application later discovered that their real names were also magically changed, causing havoc in their life. Could you help bring down this application?

# Solution

Navigating to website, we are presented with the following page.

![spk-1](https://user-images.githubusercontent.com/87711310/211197353-15ef535d-d778-42b2-ab59-e52d695fc741.png)

Looking into the source code reveals that it’s a `flask` app and using mako template engine for rendering. On line 11, the user input is passed into the spoofiky function and it’s output is passed into the template.

```javascript
┌──(darshan㉿kali)-[~/…/web_spookifier/challenge/application/blueprints]
└─$ cat routes.py           
from flask import Blueprint, request
from flask_mako import render_template
from application.util import spookify

web = Blueprint('web', __name__)

@web.route('/')
def index():
    text = request.args.get('text')
    if(text):
        converted = spookify(text)
        return render_template('index.html',output=converted)
    
    return render_template('index.html',output='')
```
