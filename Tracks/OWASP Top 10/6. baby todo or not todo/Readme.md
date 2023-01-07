# Challenge Description
I'm so done with these bloody HR solutions coming from those bloody HR specialists, I don't need anyone monitoring my thoughts, or do I... ?

## Analysis
- __Browsing the Website__
Browsing the website, we come to a conclusion that there doesn’t seem to be a whole lot of functionality packed into this application. It looks like a simple ‘to-do list’ that allows you to add and delete tasks. If we take a moment to do some critical thinking we conclude that there must be some mechanism in the background that is enabling the application to keep track of each ‘to-do list’ on a per client basis. This suspicion is confirmed if we browse the website from another browser or private window because we are presented with a fresh ‘to-do list’ every time. Our next step is to take a look at the web page source in our browser to see if we can glean more information about the page.

![btd-1](https://user-images.githubusercontent.com/87711310/211152082-c4a922d8-7245-4a8d-b407-fb31044edb2c.png)

![btd-2](https://user-images.githubusercontent.com/87711310/211152083-c60819c7-bd93-4205-887f-27ec311e69df.png)

Looking at the page source, we find a script that contains the following code:
``` javascript
// don't use getstatus('all') until we get the verify_integrity() patched
const update = () => getTasks('user4f375000')
update()
setInterval(update, 3000)
```

- __Command breakdown__

1. The first line defines an update function that will get the tasks for the specified user, which we can assume is a randomly generated user name for each client that connects to the web page. We can confirm this by connecting to the page from another browser or private window and view the user value defined in this script.
```javascript
const update = () => getTasks('user4f375000')
```

2. The second line calls the update function previously defined. Once this function is called it will retrieve all the tasks for the defined user.
```
update()
```

3. The last line will define an update interval. In this case, the update function will be called every 3 seconds (3000 milliseconds).
```javascript
setInterval(update, 3000)
```

The comment at the beginning of the script is quite interesting. It seems to imply that there is a vulnerability in the `verify_integrity()` function that will allow a user to retrieve more information than they should be allowed to. For now, we will keep that comment in the back of our mind and explore the `main.js` script to understand the inner workings of the `getTasks()` function.

Looking at the source of this function, we can confirm that ‘getTasks’ is making a request to the API at ‘/api/list/${endpoint}/’ to retrieve our tasks. The request also passes a secret which is used to verify the integrity of the request.
```javascript
...
const getTasks = endpoint => {
  fetch(`/api/list/${endpoint}/?secret=${secret}`).then(res => {
    if (res.ok) {
      res.json().then(data => {
        ul.innerHTML = ''
        data.map(task => {
          create_list(task)
        })
      })
    } else {
      window.location.reload(true)
    }
  })
}
...
```

## Solution
Let’s spin up Burp Suite and capture the update request that happens every 3 seconds.

If we dig through our memory and think about the `getTasks` function for one moment we remember the following notation.
```javascript
fetch(`/api/list/${endpoint}/?secret=${secret}`)
```
The `${endpoint}` portion of the URL seems to imply that there are other endpoints that can be used. This is similar to the end of the request where we know the `${secret}` portion means that the secret will change per user. Why not guess and see what other endpoints are available? `Wfuzz` is the perfect tool for this because we can guess the `${endpoint}` portion of the request (while leaving everything else in the request the same) to see if there are any other endpoints that we can access with our secret. When we intercepted our request in `Burp Suite` we noticed that there was a cookie bundled with the request. We should make sure to include that `cookie` when we make a request with `Wfuzz`.

```
wfuzz -w /usr/share/wordlists/SecLists/Discovery/Web-Content/api/objects.txt -u http://<IP-address>:<port>/api/list/FUZZ/?secret=d0daC83Aa4B4719 -H "Cookie: session=<your-cookie-value>" --hh 24
```

> Command breakdown:

- A wordlist of common API names from SecLists to use for guessing.
```
-w /usr/share/wordlists/SecLists/Discovery/Web-Content/api/objects.txt
```
- The URL we want to use for our requests. The ‘FUZZ’ portion of the URL will be replaced with the API names from the wordlist we chose. We include our secret just like the request we captured from burp.
```
-u http://206.189.113.236:32119/api/list/FUZZ/?secret=d0daC83Aa4B4719
```
- We need to add our cookie to ensure the webserver doesn’t deny our requests.
```
-H "Cookie: session=eyJhdXRoZW50aWNhdGlvbiI6InVzZXJBRWViMTE2RiJ9.YUuLGg.8hb4Rle7WzIlDcAQzwrJKgVauzY"
```
- A normal failed response contains 24 characters. We can verify this by omitting the –hh flag the first time we run the command. We will see that every failed request has 24 characters. This flag will hide every request that contains 24 characters in the response. Alternatively, we could have hidden every response that returned an HTTP status code 403 (not allowed/forbidden) with the –hc flag. By eliminating all of the failed API requests we are left only with endpoints we can successfully access.
```
--hh 24
```

Looking at the results we see two endpoints available to us.

Adding the `/all` to the Burp request we captured previously reveals all the notes stoored by us as well as all the other users who might have saved the some notes (including the `flag` which we are looking for)

Sending the request, we see that all the notes are displayed in the `response` tab along with the `flag`.

![baby-td-1](https://user-images.githubusercontent.com/87711310/211152516-c24d8d5d-f793-4dc9-a7c5-890bcb7ed670.png)
