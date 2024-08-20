#!/usr/bin/sage
from sage.all import *
from Crypto.Hash import SHA256
import json

def ecdsa_init():
    # Elliptic curve SECP256K1
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    E = EllipticCurve(GF(p), [0, 7])
    G = E.gens()[0] # generator
    n = G.order() # order of G
    d = randrange(n)  # private key
    Q = d * G # public key
    return p,GF(p),E,n,G,d,Q

def ecdsa_verify(r, s, m, G, d, Q):
    Zn = Zmod(G.order())
    h = int(SHA256.new(m.encode()).hexdigest(), 16)
    w = inverse_mod(s, G.order())
    u1 = int(Zn(h * w))
    u2 = int(Zn(r * w))
    P = u1 * G + u2 * Q
    return r == int(Zn(P.xy()[0]))

def ecdsa_sign(m, d, G):
    Zn = Zmod(G.order())
    n = G.order()
    h = int(SHA256.new(m.encode()).hexdigest(), 16)
    k = randrange(n)

    r = int(Zn((k * G).xy()[0]))
    assert r != 0
    s = int(Zn(inverse_mod(k, n) * (h + r * d)))
    assert s != 0

    return r, s

def leaky_ecdsa_sign(m, d, G, type, leak_size, Q):
    Zn = Zmod(G.order())
    n = G.order()
    h = int(SHA256.new(m.encode()).hexdigest(), 16)
    k = randrange(n)
    assert(k > 0 and k < n)
    r = int(Zn((k * G).xy()[0]))
    assert r != 0
    s = int(Zn(inverse_mod(k, n) * (h + r * d)))
    assert s != 0

    assert ecdsa_verify(r, s, m, G, d, d*G)
    return r, s, k

def generate_signatures(G, d, num_signatures, type, m, leak_size, Q):
    signatures = []
    for i in range(num_signatures):
        r,s,k = leaky_ecdsa_sign(m, d, G, type, leak_size, Q)
        if type == 'MSB':
            leak = k >> (256 - leak_size)
        else:  # LSB
            leak = k % (2^leak_size)
        signatures.append({"r": r,"s": s, "k": k, "leak": leak, "h": int(SHA256.new(m.encode()).hexdigest(), 16)})
    return signatures

def construct_lattice(sigs, n, leak_size, type):
    m = len(sigs)
    Zn = Zmod(n)
    factor = 2^(leak_size+1)
    shifter = 2^(256-leak_size)
    if type == 'MSB':
        B = matrix(ZZ, m+2, m+2)
        for i in range(m):
            r = Zn(sigs[i]["r"])
            s_inv = inverse_mod(sigs[i]["s"], n)
            h = sigs[i]["h"]
            leak = sigs[i]["leak"]
            B[i, i] = factor*n
            B[m, i] = factor*(int(r*s_inv))
            #assert(int(Zn(r*inverse_mod(sigs[i]["s"], n)))  == int(Zn(sigs[i]["r"]*inverse_mod(sigs[i]["s"], n))))
            B[m+1, i] = factor*(leak*shifter - h*s_inv) + n
        B[m, m] = 1
        B[m+1, m+1] = n
    else:  # LSB
        pass

    return B

def reduce_lattice(B, block_size):
    if block_size is None:
        print("Using LLL")
        return B.LLL()
    print("BKZ with block size {}".format(block_size))
    return B.BKZ(block_size=block_size,  auto_abort = True)

def get_key(B, Q, n, G):
    Zn = Zmod(n)
    print("Official public key: {}".format(Q))  
    for row in B:
        potential_key = int(row[-2]) % n
        if potential_key > 0:
            if Q == potential_key*G:
                return potential_key
            elif Q == Zn(-potential_key)*G:
                return Zn(-potential_key)   
    return 0
def attack():
    p, F ,E, n, G, d, Q = ecdsa_init()
    priv_key = d
    print("Elliptic curve SECP256K1")
    print("Order of G n = {}".format(hex(n)))
    print("Private Key d = {}".format(hex(d)))

    assert(E.is_on_curve(Q[0],Q[1])) # sanity check
    assert(G.order() == n) # sanity check
    assert (d*G == Q) # sanity check
    message = "Do electric sheep dream of androids?"

    type = "MSB"
    leak_size = 4
    print(f"{leak_size} most significant bits of every signature's nonce are leaked")

    num_signatures = int(1.03 * (4/3) * (256/leak_size))
    signatures = generate_signatures(G, d, num_signatures, type, message, leak_size, Q)

    print("Generated {} signatures".format(num_signatures))
    B = construct_lattice(signatures, n, leak_size, type)

    block_sizes = [None, 15, 25, 40, 50, 60]

    for block_size in block_sizes:
        reduced = reduce_lattice(B, block_size)
        found = get_key(reduced, Q, n, G)
        if found :
            print("private key recovered: ", hex(found))
            r, s = ecdsa_sign("I find your lack of faith disturbing", found, G)
            assert(ecdsa_verify(r, s, "I find your lack of faith disturbing", G, found, Q))
            print("SUCCESS")
            break
        else:
            print("FAILED")

attack()                            
    