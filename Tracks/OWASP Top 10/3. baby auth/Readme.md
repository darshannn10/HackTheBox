# CHALLENGE DESCRIPTION
Who needs session integrity these days?

## Analysis
We are first greeted by a login page. Let's, once again, try `admin` with password `admin`:
```
Invalid username or password
```
Looks like we'll have to create an account - let's try those credentials.
```
this user already exists
```
This is great, because now we know we need a user called admin. Let's create another user - I'll use username and password yes, because I doubt that'll be used.

![b-a-1](https://user-images.githubusercontent.com/87711310/211149124-7d9ace19-1a87-414c-bf0a-4f906fa2546c.png)

We're redirected to the login, which makes it seem like it worked. Let's log in with the credentials we just created:
![b-a-2](https://user-images.githubusercontent.com/87711310/211149125-1d0f5931-5bbf-40ba-aa63-dedf727058ec.png)

Whoops, guess we're `not an admin`!
When it comes to accounts, one very common thing to check is __cookies__. Cookies allow, among other things, for users to [authenticate without logging in every time](https://stackoverflow.com/questions/17769011/how-does-cookie-based-authentication-work). To check cookies, we can right-click and hit __Inspect Element__ and then move to the __Console__ tab and type `document.cookie`.

![b-a-3](https://user-images.githubusercontent.com/87711310/211149127-86e4caa7-bba4-43f4-8ce1-0feb38cb29aa.png)

Well, we have a cookie called __PHPSESSID__ and the value `eyJ1c2VybmFtZSI6InllcyJ9`. Cookies are often base64 encoded, so we'll use a tool called [CyberChef](https://gchq.github.io/CyberChef/) to decode it.

![b-a-4](https://user-images.githubusercontent.com/87711310/211149128-147d8b2a-5d98-46dd-bb61-2b3261a68dd7.png)

Once we decode the `base64`, we see that the contents are simply 
```
{"username":"yes"}
```

## Exploitation
So, the website knows our identity due to our cookie - but what's to stop us from forging a cookie? Since we control the cookies we send, we can just edit them. Let's create a `fake cookie`!

![b-a-5](https://user-images.githubusercontent.com/87711310/211149129-d37a3402-555d-4ebe-9760-c1d6ac354cb8.png)

Note that we're URL encoding it as it ends in the special character =, which usually has to be URL encoded in cookies. Let's change our cookie to `eyJ1c2VybmFtZSI6ImFkbWluIn0%3D`.

![b-a-6](https://user-images.githubusercontent.com/87711310/211149123-53cccd7e-a18d-4f52-92f2-f5867642bf67.png)

Ignore the warning, but we've now set document.cookie. Refresh the page to let it send the cookies again.
And there you go - we successfully authenticated as an admin!
