# Challenge Description
Can you decrypt the message and get the flag?

## Solution
Download the necessary `Weak Rsa.zip` files and uzip it.
```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Beginner-Path/Weak-RSA]
└─$ unzip Weak\ RSA.zip                     
Archive:  Weak RSA.zip
[Weak RSA.zip] flag.enc password: 
  inflating: flag.enc                
  inflating: key.pub 
```

Well, so we have a two files. Let’s try to open them.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Beginner-Path/Weak-RSA]
└─$ cat key.pub 
-----BEGIN PUBLIC KEY-----
MIIBHzANBgkqhkiG9w0BAQEFAAOCAQwAMIIBBwKBgQMwO3kPsUnaNAbUlaubn7ip
4pNEXjvUOxjvLwUhtybr6Ng4undLtSQPCPf7ygoUKh1KYeqXMpTmhKjRos3xioTy
23CZuOl3WIsLiRKSVYyqBc9d8rxjNMXuUIOiNO38ealcR4p44zfHI66INPuKmTG3
RQP/6p5hv1PYcWmErEeDewKBgGEXxgRIsTlFGrW2C2JXoSvakMCWD60eAH0W2PpD
qlqqOFD8JA5UFK0roQkOjhLWSVu8c6DLpWJQQlXHPqP702qIg/gx2o0bm4EzrCEJ
4gYo6Ax+U7q6TOWhQpiBHnC0ojE8kUoqMhfALpUaruTJ6zmj8IA1e1M6bMqVF8sr
lb/N
-----END PUBLIC KEY-----
                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Beginner-Path/Weak-RSA]
└─$ cat flag.enc 
�_�vc[��~�kZ�1�Ĩ�4�I�9V��^G���(�+3Lu"�T$���F0�VP�־j@������|j▒�������{¾�,�����YE������Xx��,��c�N&Hl2�Ӎ��[o�� 
```
Looks like we have a public key which was used to produce the encrypted gibberish. Let’s learn more about [RSA](https://www.geeksforgeeks.org/rsa-algorithm-cryptography/).

We can derive from the reading that if the `p` and `q` values are smaller primes, we can break the RSA algorithm! That might be the case in this challenge (I hope!).

A little Google Fu got me this tool. We can leverage it to try and decrypt the `flag.enc` file contents.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Beginner-Path/Weak-RSA]
└─$ python /opt/RsaCtfTool/RsaCtfTool.py --publickey key.pub --uncipherfile flag.enc
private argument is not set, the private key will not be displayed, even if recovered.

[*] Testing key key.pub.
attack initialized...
[*] Performing factordb attack on key.pub.
[*] Attack success with factordb method !

Results for key.pub:

Unciphered data :
HEX : 0x0221cfb29883b06f409a679a58a4e97b446e28b244bbcd0687d178a8ab8722bf86da06a62e042c892d2921b336571e9ff7ac9d89ba90512bac4cfb8d7e4a3901bbccf5dfac01b27bddd35f1ca55344a75943df9a18eadb344cf7cf55fa0baa7005bfe32f41004854427b73316d706c335f5769336e3372735f34747434636b7d
INT (big endian) : 1497194306832430076266314478305730170974165912795150306640063107539292495904192020114449824357438113183764256783752233913408135242464239912689425668318419718061442061010640167802145162377597484106658670422900749326253337728846324798012274989739031662527650589811318528908253458824763561374522387177140349821
INT (little endian) : 88072555727442581906733819159067155697935911281144218615701455765307172880720320635323713584599918143771491506717753835756287620091394177323854379763656327463368952228869334584829987719054100173777641056621175603973323216296201097722843393696547323416050555734978260588354260747823940515336870113457552171266
STR : b'\x02!\xcf\xb2\x98\x83\xb0o@\x9ag\x9aX\xa4\xe9{Dn(\xb2D\xbb\xcd\x06\x87\xd1x\xa8\xab\x87"\xbf\x86\xda\x06\xa6.\x04,\x89-)!\xb36W\x1e\x9f\xf7\xac\x9d\x89\xba\x90Q+\xacL\xfb\x8d~J9\x01\xbb\xcc\xf5\xdf\xac\x01\xb2{\xdd\xd3_\x1c\xa5SD\xa7YC\xdf\x9a\x18\xea\xdb4L\xf7\xcfU\xfa\x0b\xaap\x05\xbf\xe3/A\x00HTB{s1mpl3_Wi3n3rs_4tt4ck}'
HEX : 0x000221cfb29883b06f409a679a58a4e97b446e28b244bbcd0687d178a8ab8722bf86da06a62e042c892d2921b336571e9ff7ac9d89ba90512bac4cfb8d7e4a3901bbccf5dfac01b27bddd35f1ca55344a75943df9a18eadb344cf7cf55fa0baa7005bfe32f41004854427b73316d706c335f5769336e3372735f34747434636b7d
INT (big endian) : 1497194306832430076266314478305730170974165912795150306640063107539292495904192020114449824357438113183764256783752233913408135242464239912689425668318419718061442061010640167802145162377597484106658670422900749326253337728846324798012274989739031662527650589811318528908253458824763561374522387177140349821
INT (little endian) : 22546574266225300968123857704721191858671593287972919965619572675918636257464402082642870677657579044805501825719744981953609630743396909394906721219496019830622451770590549653716476856077849644487076110495020954617170743371827481017047908786316114794508942268154434710618690751442928771926238749045133355844096
STR : b'\x00\x02!\xcf\xb2\x98\x83\xb0o@\x9ag\x9aX\xa4\xe9{Dn(\xb2D\xbb\xcd\x06\x87\xd1x\xa8\xab\x87"\xbf\x86\xda\x06\xa6.\x04,\x89-)!\xb36W\x1e\x9f\xf7\xac\x9d\x89\xba\x90Q+\xacL\xfb\x8d~J9\x01\xbb\xcc\xf5\xdf\xac\x01\xb2{\xdd\xd3_\x1c\xa5SD\xa7YC\xdf\x9a\x18\xea\xdb4L\xf7\xcfU\xfa\x0b\xaap\x05\xbf\xe3/A\x00HTB{s1mpl3_Wi3n3rs_4tt4ck}'

PKCS#1.5 padding decoded!
HEX : 0x004854427b73316d706c335f5769336e3372735f34747434636b7d
INT (big endian) : 116228445871869252378692588205079217110932931184359462733572989
INT (little endian) : 51594582506285564025554597946778804341308607376857173453085886464
utf-8 : HTB{REDACTED}
STR : b'\x00HTB{REDACTED}'

```

Voila! We have the FLAG and we can use this to gain out points on HackTheBox. Just copy paste it on the HackTheBox portal.
