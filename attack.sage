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

def leaky_ecdsa_sign(m, d, G):
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
    h = int(SHA256.new(m.encode()).hexdigest(), 16)
    if type == "Middle":
        leak_beginning = leak_size[0]
        leak_end = leak_size[1]
        for i in range(2):
            r,s,k = leaky_ecdsa_sign(m, d, G)
            leak = int(bin(k)[2:].ljust(256, '0')[leak_beginning:leak_end+1], 2)
            signatures.append({"r": r,"s": s, "k": k, "leak": leak, "h": h})
    else:
        for i in range(num_signatures):
            r,s,k = leaky_ecdsa_sign(m, d, G)
            if type == 'MSB':
                leak = k >> (256 - leak_size)
            else:  # LSB
                leak = k % (2^leak_size)
            signatures.append({"r": r,"s": s, "k": k, "leak": leak, "h": h})
    return signatures

def construct_lattice(sigs, n, leak_size, type):
    m = len(sigs)
    Zn = Zmod(n)
    factor = 2^(leak_size+1)
    if type == 'MSB':
        shifter = 2^(256-leak_size)
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
    elif type == "LSB":  # LSB
        B = matrix(ZZ, m+2, m+2)
        shifter = inverse_mod(2^leak_size,n)
        for i in range(m):
            r = Zn(sigs[i]["r"])
            s_inv = inverse_mod(sigs[i]["s"], n)
            h = sigs[i]["h"]
            leak = sigs[i]["leak"]
            B[i, i] = factor*n
            B[m, i] = factor*(int(shifter*r*s_inv))
            B[m+1, i] = factor*int(shifter*(leak - h*s_inv)) + n
        B[m, m] = 1
        B[m+1, m+1] = n
    elif type == "Middle bits":
        r1 = Zn(sigs[0]["r"])
        s1 = Zn(sigs[0]["s"])
        r2 = Zn(sigs[1]["r"])
        s2 = Zn(sigs[1]["s"])
        h1 = sigs[0]["h"]
        h2 = sigs[1]["h"]
        leak1 = sigs[0]["leak"] << (256-leak_size[1])
        leak2 = sigs[1]["leak"] << (256-leak_size[1])
        leak_beginning = leak_size[0]
        leak_end = leak_size[1]
        l = 256 - leak_beginning
        K = 2^(max(leak_beginning, 256-leak_end))

        t = -inverse_mod(s1, n)*s2*r1*inverse_mod(r2, n)
        u = inverse_mod(s1, n)*r1*h2*inverse_mod(r2, n) - inverse_mod(s1, n)*h1
        u_new = leak1 + t*leak2 + u

        B = matrix(ZZ, 5, 5)
        B[0] = vector(ZZ, [K, K * 2^l, K * t, K * t * 2^l, u_new])
        for i in range(1,4):
            B[i] = vector(ZZ, [0]*i + [K*n] + [0]*(4-i))
        B[4] = vector(ZZ, [0, 0, 0, 0, n])

    else:
        print("Invalid leak type")
        exit()
    return B

def reduce_lattice(B, block_size):
    if block_size is None:
        print("Using LLL")
        return B.LLL()
    print("BKZ with block size {}".format(block_size))
    return B.BKZ(block_size=block_size,  auto_abort = True)

def get_key_msb_lsb(B, Q, n, G, K):
    Zn = Zmod(n)
    #print("Official public key: {}".format(Q))  
    for v in B:
        potential_key = int(v[-2]) % n
        if potential_key > 0:
            if Q == potential_key*G:
                return potential_key
            elif Q == Zn(-potential_key)*G:
                return Zn(-potential_key)   
    return 0

def solve_system(B, signatures, leak_size, n, G):
    Zn = Zmod(n)
    r1, s1 = signatures[0]["r"], signatures[0]["s"]
    r2, s2 = signatures[1]["r"], signatures[1]["s"]
    h1, h2 = signatures[0]["h"], signatures[1]["h"]

    leak_beginning = leak_size[0]
    leak_end = leak_size[1]
    leak1 = signatures[0]["leak"] << (256-leak_size[1])
    leak2 = signatures[1]["leak"] << (256-leak_size[1])
    l = 256 - leak_beginning
    K = 2^(max(leak_beginning, 256-leak_end))

    t = -inverse_mod(s1, n)*s2*r1*inverse_mod(r2, n)
    u = inverse_mod(s1, n)*r1*h2*inverse_mod(r2, n) - inverse_mod(s1, n)*h1
    u_new = leak1 + t*leak2 + u

    eq_system = Matrix(ZZ, 4, 4)
    b = []
    equation_index = 0
    for v in B[:-1]:
        eq_system[equation_index] = [x//K for x in v[:4]]
        b.append(-v[4])

    assert(len(b) == 4)
    """
    x -> LSB recovered
    y -> MSB recovered
    """
    x1, y1, x2, y2 = eq_system.solve_right(vector(ZZ, b))
    assert(Zn(x1 + 2^l*y1 + t*x2 + t*2^l*y2 + u_new) == 0)

    k1 = y1*(2^l) + leak1 + x1
    k2 = y2*(2^l) + leak2 + x2
    print("k1: ", k1)
    print("k2: ", k2)

    priv_key1 = Zn(inverse_mod(r1, n)*(s1*k1 - h1))
    priv_key2 = Zn(inverse_mod(r2, n)*(s2*k2 - h2))

    assert(priv_key1 == priv_key2)
    return int(priv_key1)


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

    type = "Middle"
    leak_size = [10,246]

    if(type == "Middle"):
        num_signatures = 2
        assert(isinstance(leak_size, list))
        assert(leak_size[1]<256 and leak_size[0] >= 0)  
        assert(leak_size[0] < leak_size[1])
        K = 2^(max(leak_size[0], 256-leak_size[1]))
    else:
        num_signatures = int(1.5 * (4/3) * (256/leak_size))
        K = None
    #num_signatures = int(2 * (4/3) * (256/leak_size))
    signatures = generate_signatures(G, d, num_signatures, type, message, leak_size, Q)

    print(f"{leak_size} {type} of every signature's nonce are leaked")
    print("Generated {} signatures".format(num_signatures))

    B = construct_lattice(signatures, n, leak_size, type)

    block_sizes = [None, 15, 20, 25, 30, 40, 50, 60, num_signatures]

    for block_size in block_sizes:
        reduced = reduce_lattice(B, block_size)
        if type == "Middle":
            found = solve_system(reduced, signatures, leak_size, n, G)
        else: # LSB or MSB
            found = get_key_msb_lsb(reduced, Q, n, G)

        if found :
            print("private key recovered: ", hex(found))
            r, s = ecdsa_sign("I find your lack of faith disturbing", found, G)
            assert(ecdsa_verify(r, s, "I find your lack of faith disturbing", G, found, Q))
            print("SUCCESS")
            break
        else:
            print("FAILED")

attack()                            
    