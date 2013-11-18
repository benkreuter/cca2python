#!/usr/bin/python -OOOO

## Front end for a very basic implementation of Cramer-Shoup
## encryption.  Please do not use this for anything that requires
## serious security -- really, I am reading untrusted inputs with
## eval().  If someone wants to do this better, let me know...

## Usage:  
## ./main.py keygen ddh-prg-params.keysize /dev/urandom pkfile skfile
## ./main.py encrypt ddh-prg-params.keysize /dev/urandom pkfile messagefile ciphertextfile
## ./main.py decrypt ddh-prg-params.keysize skfile ciphertextfile messagefile

from cpapke import *
from ccapke import *
import sys
import yaml

if len(sys.argv) < 3:
    print "Usage:\n./main.py keygen paramsfile randomfile pkfile skfile\n\
./main.py encrypt paramsfile randomfile pkfile messagefile ciphertextfile\n\
./main.py decrypt paramsfile randomfile skfile ciphertextfile messagefile"
elif sys.argv[1] == "keygen":
    params = readparams(sys.argv[2])
    randf = sys.argv[3]
    kp = cskeygen(params, randf)
    pkfile = open(sys.argv[4], 'w')
    yaml.safe_dump(kp[0], pkfile)
    pkfile.close()

    skfile = open(sys.argv[5], 'w')
    yaml.safe_dump(kp[1], skfile)
    skfile.close()
elif sys.argv[1] == "encrypt":
    params = readparams(sys.argv[2])
    randf = sys.argv[3]
    pkfile = open(sys.argv[4], 'r')
    pk = yaml.safe_load(pkfile.read())
    pkfile.close()
    
    txtfile = open(sys.argv[5], 'r')
    txt = txtfile.read()
    ctext = cshybridenc(params, pk, stringtooctets(txt), 128, randf)
    txtfile.close()

    ctxtfile = open(sys.argv[6], 'w')
    yaml.safe_dump(ctext, ctxtfile)
    ctxtfile.close()
elif sys.argv[1] == "decrypt":
    params = readparams(sys.argv[2])
    skfile = open(sys.argv[3], 'r')
    sk = yaml.safe_load(skfile.read())
    skfile.close()

    ctxtfile = open(sys.argv[4], 'r')
    ctxt = yaml.safe_load(ctxtfile.read())
    ctxtfile.close()
    msg = cshybriddec(params, sk, ctxt, 128)

    txtfile = open(sys.argv[5], 'w')
    txtfile.write(octetstostring(msg))
    txtfile.close()
else:
    print "Bad command"
