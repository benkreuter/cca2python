# Author: Benjamin Kreuter
#
# A simple CPA secure public-key encryption system that is meant to
# be easy to audit.
#
# WARNING: This code is a proof-of-concept only, meant to demonstrate
# that cryptosystems *can* be implemented in a high-level language
# and using only provably secure constructions.  This code has not
# been thoroughly reviewed and SHOULD NOT BE USED in any
# security-sensitive application.
#
# This code is only secure against chosen plaintext attacks.  This
# does not meet the more stringent security requirements of
# real-world cryptosystems, which should be secure against adaptive
# chosen ciphertext attacks.
#
# The security of this system reduces to the hardness of the
# decisional Diffie-Hellman problem.  This is a hybrid encryption
# system that uses ElGamal to encrypt a secret key for the PRG of
# Sidorenko et al.  This PRG was chosen because the seed and
# parameter sizes only need to be slightly larger than the sizes
# required for secure ElGamal encryption; this allows us to set the
# ElGamal sizes larger than necessary and operate in only one group.
# The PRG is seeded by an element of Z/qZ with q prime, where q is
# the size of the QR group of (Z/pZ) for a prime p.  Hence, if the QR
# group of Z/pZ is the message space for ElGamal, we can simply
# encrypt the seed and then use the seed to encrypt the message by
# XORing with the PRG output.

def logfloor(x, n):
    ret = 0
    while(x >= 1):
        ret = ret + 1
        x = x / n
    return ret

def expsq(x, n, modulus):
    ret = 1
    while(n > 0):
        if (n % 2) == 1:
            ret = (x * ret) % modulus
            n = n - 1
        else:
            x = (x * x) % modulus
            n = n / 2
    return ret

def findset(x, n, bts):
    while(x >= n):
        if (bts % 2) == 0:
            n = n * 2
            bts = bts / 2
        elif (bts % 2) == 1:
            x = x - n
            n = n * 2
            bts = bts / 2
    if n == 1:
        return None
    else:
        return x

def Zqtobits(x, q):
    return findset(x, 1, q)

class ddhparams:
    def __init__(self, p, q, x, y):
        self.p = p
        self.q = q
        self.x = x
        self.y = y

    def check(self):
        assert(self.p == (1 + (self.q * 2)))
        assert(1 == expsq(self.x, self.q, self.p))
        assert(1 == expsq(self.y, self.q, self.p))

def readparams(fname):
    inf = open(fname, 'r')
    p = int(inf.readline())
    q = int(inf.readline())
    x = int(inf.readline())
    y = int(inf.readline())
    return ddhparams(p,q,x,y)

import struct

def urandom(randf, modulus):
    inf = open(randf, "rb")
    nbytes = logfloor(modulus, 256)
    res = modulus
    while res >= modulus:
        res = 0
        for i in range(0, nbytes):
            res = (res * 256) + struct.unpack("B", inf.read(1))[0]
    inf.close()
    return res

def ddhprgseed(params, randf):
    return urandom(randf, params.q)

class ddhprg:
    def __init__(self, seed, params):
        self.iseed = seed
        self.s = seed
        self.p = params.p
        self.q = params.q
        self.x = params.x
        self.y = params.y
        self.out = seed

    def enum(self, x):
        if x <= self.q:
            return x
        else:
            return self.p - x

    def nextval(self):
        ns = self.enum(expsq(self.x, self.s, self.p))
        no = self.enum(expsq(self.y, self.s, self.p))
        self.s = ns
        self.out = no
        return self.out

    def bitstream(self, n):
        keystream = 0
        while(logfloor(keystream, 2) < n):
            nk = Zqtobits(self.nextval(), self.q)
            keystream = (keystream * 2**(logfloor(nk,2))) + nk
        keystream = keystream & (2**n - 1)
        return keystream

    def reset(self):
        self.s = self.iseed
        self.out = self.iseed

def stringtooctets(string):
    ret = []
    for ch in string:
        ret.append(struct.unpack('B', ch)[0])
    return ret

def octetstostring(octets):
    ret = ""
    for oc in octets:
        ret = ret + struct.pack('B', oc)[0]
    return ret

def ddhprgstream(prg, params, message):
    keystream = []
    while(len(keystream) < len(message)):
        nk = Zqtobits(prg.nextval(), params.q)
        while(logfloor(nk, 2) >= 8):
            keystream.append(nk % 256)
            nk = nk >> 8
    
    ctext = []
    for i in range(0, len(message)):
        ch = message[i]
        k = keystream[i]
        ctext.append(ch ^ k)
    return ctext

class elglkeypair:
    def __init__(self, p, g, x):
        self.gen = g
        self.pk  = expsq(g, x, p)
        self.sk  = x

def elglkeygen(params, randf):
    g = urandom(randf, params.p)
    while(expsq(g, params.q, params.p) != 1):
        g = urandom(randf, params.p)

    x = urandom(randf, params.q)

    return elglkeypair(params.p, g, x)

def elglencrypt(message, pubkey, gen, params, randf):
    r = urandom(randf, params.q)
    c1 = expsq(gen, r, params.p)
    s = expsq(pubkey, r, params.p)
    rkey = urandom(randf, params.q)
    rkeyenc = expsq(rkey+1, 2, params.p)
    prg = ddhprg(rkey, params)

    return (c1, (rkeyenc * s) % params.p, ddhprgstream(prg, params, stringtooctets(message)))

def elgldecrypt(ciphertext, seckey, params):
    c1 = ciphertext[0]
    c2 = ciphertext[1]
    s = expsq(c1, seckey, params.p)
    rkeyenc = (c2 * expsq(s, params.p - 2, params.p)) % params.p
    rkey = expsq(rkeyenc, (params.p + 1) / 4, params.p)
    if rkey > params.q:
        rkey = params.p - rkey

    rkey = rkey-1

    prg = ddhprg(rkey, params)

    return octetstostring(ddhprgstream(prg, params, ciphertext[2]))
