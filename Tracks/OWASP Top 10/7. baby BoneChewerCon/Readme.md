# Challenge Description
Due to heavy workload for the upcoming baby BoneChewerCon event, the website is under maintenance and it errors out, but the debugger is still enabled in production!! I think the devil is enticing us to go and check out the secret key.

## Analysis
We are given an URL. This leads us to a website calling for the registration to its upcoming event. We see we have a few graphics and most noteably and input field. So naturally we want to go ahead and try to XSS this. 
After trying multiple XSS payloads, nothing happens and i'm pretty much sure that this site is not vulnerable to XSS.

![bon-1](https://user-images.githubusercontent.com/87711310/211152793-df7c13fa-5d2a-4562-9ad9-eee884a491f6.png)

After this, I just a random word `test` in the input field to see what happens and we see a misconfiguration error.

![bon-2](https://user-images.githubusercontent.com/87711310/211152796-489f6fca-dd2d-4487-a43a-cb43ce8782af.png)

Scrolling a lil' bit reveals the flag

![baby-bonechewercon-1](https://user-images.githubusercontent.com/87711310/211152799-15431b95-9f84-440f-8029-8a0e23821fc7.png)
