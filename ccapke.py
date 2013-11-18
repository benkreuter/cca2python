## Extension of cpa-pke.py for CCA2 security

from cpapke import *
import copy

def padoctets(msg, n):
    ldiff = (n / 8) - (len(msg) % (n / 8))
    msg.extend([0 for x in range(0, ldiff)])
    assert(len(msg) % (n / 8) == 0)
    return msg

def ccakeygen(params, prg):
    return prg.nextval()

def ccaenc(msg, macn, key, params, macfn, randf):
    prg = ddhprg(key, params)
    r = urandom(randf, 2**macn)
    
    fkeys = nrmackey(params, macn, prg)

    prg2 = ddhprg(nrprf(r, macn, fkeys, params), params)

    ctext = ddhprgstream(prg2, params, msg)
    mac = macfn(copy.deepcopy(ctext), macn, prg.nextval(), params)
    return (r, ctext, mac)

def ccadec(ctext, macn, key, params, macfn):
    prg = ddhprg(key, params)
    r = ctext[0]
    fkeys = nrmackey(params, macn, prg)
    prg2 = ddhprg(nrprf(r, macn, fkeys, params), params)
    msg = ddhprgstream(prg2, params, ctext[1])
    mac = macfn(copy.deepcopy(ctext[1]), macn, prg.nextval(), params)
    if mac == ctext[2]:
        return msg
    else:
        return []

## The Naor-Reingold PRF
##
## This has somewhat better security compared to the above, and also
## is more efficient -- we do *n* PRG invocations up front, then just
## one exponentiation for each invocation of the PRF (compared to *n*
## PRG invocations per PRF invocation for GGM).

def nrprf(msg, n, keys, params):
    ## params.x is a generator for the group
    g = params.x
    e = keys[0]
    for i in range(1, n+1):
        if ((msg >> (i - 1)) & 1) == 1:
            e = (e * keys[i]) % params.q
    return expsq(g, e, params.p)

def nrprfmac(msg, n, key, params):
    prg = ddhprg(key, params)
    keys = nrmackey(params, n, prg)

    rval = 0
    block = len(msg)
    rvalZq = nrprf(block, n, keys, params)
    prg = ddhprg(rvalZq, params)
    rval = prg.bitstream(n)
    padoctets(msg, n)
    for i in range(0, len(msg)*8 / n):
        block = 0
        for j in range(0, n / 8):
            block = (block << 8) + msg[(n / 8)*i + j]
        rvalZq = nrprf(block ^ rval, n, keys, params)
        prg = ddhprg(rvalZq, params)
        rval = prg.bitstream(n)
    return rval

def nrmackey(params, n, prg):
    keys = []
    for i in range(0, n+1):
        keys.append(prg.nextval())

    return keys

## The Cramer-Shoup public key encryption system
##
## We use the hash-free variant here, to keep things simpler.  See the
## paper by Cramer on how to build this.  Note that by using safe
## primes, we make out lives even easier, avoiding the need for the
## "chop" function.
##
## Cite: "Design and Analysis of Practical Public Key..." by
## Cramer/Shoup

def cskeygen(params, randf):
    x1 = urandom(randf, params.q)

    x2 = urandom(randf, params.q)

    ys = [0,0,0,0,0,0]
    for i in range(0,6):
        ys[i] = urandom(randf, params.q)
            
    g1 = urandom(randf, params.p)
    while(expsq(g1, params.q, params.p) != 1):
        g1 = urandom(randf, params.p)

    g2 = urandom(randf, params.p)
    while(expsq(g2, params.q, params.p) != 1):
        g2 = urandom(randf, params.p)

    z = urandom(randf, params.q)

    ds = [0,0,0]
    for i in range(0,3):
        ds[i] = (expsq(g1, ys[2*i], params.p) * expsq(g2, ys[2*i+1], params.p)) % params.p

    sk = (x1,x2,ys,z)
    pk = (g1, g2, (expsq(g1, x1, params.p) * expsq(g2, x2, params.p)) % params.p, 
          ds, expsq(g1, z, params.p))
    return (pk, sk)

def qrmap(params, x):
    if x < params.q:
        return x
    else:
        return params.p - x

def csenc(params, pk, msg, randf):
    g1 = pk[0]
    g2 = pk[1]
    c = pk[2]
    ds = pk[3]
    h = pk[4]
    r = urandom(randf, params.q)
    c1 = expsq(g1, r, params.p)
    c2 = expsq(g2, r, params.p)
    e = (expsq(h, r, params.p) * msg) % params.p

# Now we use the injective map from QR(p) to Zq that just happens to
# work for safe primes.
    c1q = qrmap(params, c1)
    c2q = qrmap(params, c2)
    eq = qrmap(params, e)

    v = (expsq(c, r, params.p) * 
         expsq(ds[0], c1q * r, params.p) *
         expsq(ds[1], c2q * r, params.p) *
         expsq(ds[2], eq * r, params.p)) % params.p
    return (c1, c2, e, v)

def csdec(params, sk, ctext):
    x1 = sk[0]
    x2 = sk[1]
    ys = sk[2]
    z = sk[3]

    c1q = qrmap(params, ctext[0])
    c2q = qrmap(params, ctext[1])
    eq = qrmap(params, ctext[2])

    v = (expsq(ctext[0], 
               x1 +
               ys[0] * c1q +
               ys[2] * c2q +
               ys[4] * eq, params.p) *
         expsq(ctext[1],
               x2 +
               ys[1] * c1q +
               ys[3] * c2q +
               ys[5] * eq, params.p)) % params.p
    assert(v == ctext[3])
    return (ctext[2] * expsq(expsq(ctext[0], z, params.p), params.p - 2, params.p)) % params.p

## Hybrid encryption for CS
def cshybridenc(params, pk, msg, macn, randf):
    rkey = urandom(randf, params.q)
    rkeyenc = expsq(rkey+1, 2, params.p)

    c1 = csenc(params, pk, rkeyenc, randf)
    c2 = ccaenc(msg, macn, rkey, params, nrprfmac, randf)
    return (c1, c2)

def cshybriddec(params, sk, ctext, macn):
    rkeyenc = csdec(params, sk, ctext[0])
    rkey = expsq(rkeyenc, (params.p + 1) / 4, params.p)
    if rkey > params.q:
        rkey = params.p - rkey
    rkey = rkey - 1
    return ccadec(ctext[1], macn, rkey, params, nrprfmac)
