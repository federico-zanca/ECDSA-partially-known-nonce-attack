from sage.all import *
# import hash from crypto
from Crypto.Hash import SHA256

# Elliptic curve SECP256K1
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
E = EllipticCurve(GF(p), [0, 7])
G = E.gens()[0] # generator
n = G.order() # order of G
d = 0xfedefedefedefedefedefedefedefedefedefedefedefedefedefedefedead0  # private key
Q = d * G # public key


def leaky_ecdsa_sign(m, d, G, type, leak_size):
    h = int(SHA256.new(m.encode()).hexdigest(), 16)
    k = randint(1, n-1)
    r = mod((k * G).xy()[0], n)
    assert r != 0
    s = int(mod(inverse_mod(k, n) * (h + r * d), n))
    assert s != 0

    if type == 'MSB': #MSB
        leak = int(k) >> (256 - leak_size)
    elif type == 'LSB': #LSB
        leak = int(k) % (2^leak_size)
    else: #Middle bits
        leak_beginning = leak_size[0]
        leak_end = leak_size[1]
        leak = (k >> (256-leak_end)) % (2^(leak_end - leak_beginning))
    return r, s, leak
    
def ecdsa_sign(m, d, G):
    h = int(SHA256.new(m.encode()).hexdigest(), 16)
    k = randint(1, n-1)
    r = mod((k * G).xy()[0] , n)
    assert r != 0
    s = int(inverse_mod(k, n) * (h + r * d) % n)
    assert s != 0
    return r, s

def ecdsa_verify(m, Q, r, s, G):
    h = int(SHA256.new(m.encode()).hexdigest(), 16)
    assert 1 < r < n-1
    assert 1 < s < n-1
    w = inverse_mod(s, n)
    u1 = (h * w) % n
    u2 = (r * w) % n
    xy = u1 * G + u2 * Q
    R = mod(xy.xy()[0] , n)
    return R == r


menu = """
1. Sign message (leaky!)
2. Verify signature
3. Sign with your private key ;P
"""

options = """
1. Most significant bits
2. Least significant bits
3. Middle bits
"""

print("ECDSA lattice attack playground")
print("Curve: SECP256K1")
print(f"Generator: {G}")
print(f"Order n = {hex(n)}")
print(f"Public key: {Q}")

if __name__ == '__main__':
    while True:
        
        choice = input(menu)
        if choice == '1':
            type = input(options + "\nWhat do you want to know about the nonce? ")
            m = input("Message: ")
            sig = leaky_ecdsa_sign(m, d, G, type)
            print(f"Signature: {sig}")
        elif choice == '2':
            m = input("Message: ")
            r = int(input("r: "), 16)
            s = int(input("s: "), 16)
            if ecdsa_verify(m, Q, r, s, G):
                print("Signature verified")
            else:
                print("Invalid signature")
        elif choice == '3':
            m = input("Message: ")
            priv = input("Private key: ")
            if(priv[0:2]=="0x"):
                priv = int(priv[2:], 16)
            else:
                priv = int(priv)
            
            sig = ecdsa_sign(m, priv, G)
            print(f"Signature: {sig}")
        else:
            break
    