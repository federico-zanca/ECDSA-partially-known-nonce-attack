from sage.all import *
from Crypto.Hash import SHA256

def ecdsa_init():
    # Elliptic curve SECP256K1
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    E = EllipticCurve(GF(p), [0, 7])
    G = E.gens()[0] # generator
    n = G.order() # order of G
    d = randrange(n)  # private key
    Q = d * G # public key
    return p,GF(p),E,n,G,d,Q

def leaky_ecdsa_sign(m, d, G, type, leak_size):
    Zn = Zmod(G.order())
    n = G.order()
    h = int(SHA256.new(m.encode()).hexdigest(), 16)
    k = randint(1, 2^128-1)
    r = Zn((k * G).xy()[0])
    assert r != 0
    s = int(Zn(inverse_mod(k, n) * (h + r * d)))
    assert s != 0

    if type == 'MSB': #4 MSB of number, represented in 256 bits
        leak = int(k) >> (256-leak_size)
    return r, s, k

def generate_signatures(G, d, num_signatures, type, m, leak_size):
    signatures = []
    for i in range(num_signatures):
        r,s,k = leaky_ecdsa_sign(m, d, G, type, leak_size)
        if type == 'MSB':
            leak = k >> (256 - leak_size)
        else:  # LSB
            leak = k % (2^leak_size)
        signatures.append({"r": r,"s": s, "k": k, "leak": leak, "h": int(SHA256.new(m.encode()).hexdigest(), 16)})
    return signatures

def construct_lattice(sigs, n, leak_size, type, message):
    m = len(sigs)
    Zn = Zmod(n)
    #h = int(SHA256.new(message.encode()).hexdigest(), 16)
    factor = 2^leak_size
    shifter = 2^(256-leak_size)
    #B = matrix(ZZ, m+2, m+2)
    if type == 'MSB':
        B = [[0]*i + [factor*n] + [0]*(m-i+1) for i in range(m)]  # matrix m x m+2 all zeros except for the diagonal
        t = [int(Zn(factor*sigs[i]["r"]/sigs[i]["s"])) for i in range(m)] + [1, 0]
        u = [int(Zn(factor*(sigs[i]["leak"]*shifter)*sigs[i]["h"]/sigs[i]["s"])) for i in range(m)] + [0, n]
        B.append(t)
        B.append(u)

        print("\n\nLunghezze   ")
        for row in B:
            print(len(row))
    else:  # LSB
        pass

    return Matrix(B)

def reduce_lattice(B, block_size):
    if block_size is None:
        print("Using LLL")
        return B.LLL()
    print("BKZ with block size {}".format(block_size))
    return B.BKZ(block_size=block_size,  auto_abort = True)

def test_result(B, Q, n, d, G):
    Zn = Zmod(n)
    for row in B:
        candidate = Zn(row[-2])
        if candidate > 0:
            alternative = n - candidate
            if Q == candidate*G:
                print("Found private key: {}".format(hex(candidate)))
                return candidate
            elif Q == alternative*G:
                print("Found private key: {}".format(hex(alternative)))
                return alternative
    return 0
def attack():
    p, F ,E, n, G, d, Q = ecdsa_init()
    print("Elliptic curve SECP256K1")
    print("Order of G n = {}".format(hex(n)))
    print("Private Key d = {}".format(hex(d)))

    assert(E.is_on_curve(Q[0],Q[1])) # sanity check
    assert(G.order() == n) # sanity check

    message = "Do electric sheep dream of androids?"

    type = "MSB"
    leak_size = 6
    print("{leak_size} most significant bits of every signature's nonce are leaked")

    num_signatures = ceil((1.03 * (4/3) * (256/leak_size)) + 1)
    signatures = generate_signatures(G, d, num_signatures, type, message, leak_size)
    print("Generated {} signatures".format(num_signatures))

    B = construct_lattice(signatures, n, leak_size, type, message)

    recovery = [None, 15, 25, 40, 50, 60]
    for effort in recovery:
        reduced = reduce_lattice(B, effort)
        res = test_result(reduced, Q, n, d, G)
        if res :
            print("SUCCESS")
            print(res)
            break
        else:
            print("FAILED")

attack()                            
    