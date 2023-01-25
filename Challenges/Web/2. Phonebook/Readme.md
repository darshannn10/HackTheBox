# Hack The Box Challenges - Web - Phonebook

### Files provided
There are no files provided which is pretty rare for an challenges in HackTheBox

## Enumeration
Visiting the web-site, I was presented a login page, and the URL of the website consisted of `/login`

![pb-1](https://user-images.githubusercontent.com/87711310/214499214-49cdfaee-895d-41b7-a9a8-c320f5509e32.png)

I looked at the source-code of the web-site but couldn't find anything, so I went back to the website.

![pb-2](https://user-images.githubusercontent.com/87711310/214499218-688935e1-5db9-47e9-9df8-6e3c47b36c15.png)

Now, I tried using common credentials (admin:admin, admin:password, admin:password123) but none of them worked and I got an `authentication failed` error. But I found something interesting in the URL. The URL was also displaying the same message with a `message` parameter.

![pb-3](https://user-images.githubusercontent.com/87711310/214499222-a9d9abad-e04b-4172-8100-f672c2022ce7.png)

Then, i tried gobuster but got the same results

```
┌──(darshan㉿kali)-[~]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://165.227.230.220:30246      
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://165.227.230.220:30246
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/01/25 02:17:31 Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 200) [Size: 2214]
===============================================================
```


I also tried `sqlmap` but it didn't give any results.

```
sqlmap -u http://165.227.230.220:30246/login 
```

Therefore, looking at the login page for hints, I see that note from Reese stated that we can login using the workstation’s username and password. After searching for a while and looking at few blogs, I found out that the website was using `LDAP authentication` and I probably had to perform `LDAP Injection` to bypass the login form



