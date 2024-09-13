#!/usr/bin/sage
from sage.all import *
from Crypto.Hash import SHA256  
import json
curves = {
        "secp256k1": EllipticCurve(GF(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F), [0, 7]),
        "secp256r1": EllipticCurve(GF(0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF), [0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC, 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B]),
        "secp192k1": EllipticCurve(GF(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37), [0, 3]),
        "secp224k1": EllipticCurve(GF(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D), [0, 5]), 
    }

def choose_curve():
    print("Choose an elliptic curve:")
    for i, name in enumerate(curves.keys()):
        print(f"{i + 1}. {name}")
    
    choice = int(input("> ")) - 1
    curve_name = list(curves.keys())[choice]
    print(f"Selected curve: {curve_name}")
    return curve_name
    

def ecdsa_init(curve_name):
    N = int(curve_name[4:7])
    E = curves[curve_name]
    return E, N

def ec_get_info(E):
    G = E.gens()[0] # generator
    n = G.order() # order of G
    p = E.base_ring().order() # characteristic of the field
    return p, E.base_ring(), E, n, G

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
            leak = (k >> (N-leak_end)) % (2^(leak_end - leak_beginning))
            signatures.append({"r": int(r),"s": int(s), "k": int(k), "leak": int(leak), "h": int(h)})
    else:
        for i in range(num_signatures):
            r,s,k = leaky_ecdsa_sign(m, d, G)
            if type == 'MSB':
                leak = k >> (N - leak_size)
            else:  # LSB
                leak = k % (2^leak_size)
            signatures.append({"r": int(r),"s": int(s), "k": int(k), "leak": int(leak), "h": int(h)})
    return signatures

def construct_lattice(sigs, n, leak_size, type, N):
    m = len(sigs)
    Zn = Zmod(n)
    
    if type == 'MSB':
        factor = 2^(leak_size+1)
        shifter = 2^(N-leak_size)
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
        """
        if type == "MSB":
            shifter = 2^(256-leak_size)
            rm = Zn(sigs[m-1]["r"])
            rm_inv = inverse_mod(int(rm), n)
            sm = Zn(sigs[m-1]["s"])
            sm_inv = inverse_mod(int(sm), n)
            leak_m = sigs[m-1]["leak"]
            hm = sigs[m-1]["h"]
            B = matrix(ZZ, m+1, m+1)
            for i in range(m):
                r = Zn(sigs[i]["r"])
                s_inv = inverse_mod(sigs[i]["s"], n)
                h = sigs[i]["h"]
                leak = sigs[i]["leak"]
                t = int(-s_inv*sm*r*rm_inv)
                u = int(s_inv*r*hm*rm_inv - s_inv*h)
                B[i ,i] = n 
                B[m-1, i] = t
                B[m, i] = u + t*(shifter*leak_m) + shifter*                               leak
            B[m-1, m-1] = 1
            B[m, m] = n
        """   
    elif type == "LSB":  # LSB
        factor = 2^(leak_size+1)
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
    elif type == "Middle":
        r1 = int(sigs[0]["r"])
        s1 = int(sigs[0]["s"])
        r2 = int(sigs[1]["r"])
        s2 = int(sigs[1]["s"])
        h1 = sigs[0]["h"]
        h2 = sigs[1]["h"]
        leak1 = sigs[0]["leak"] << (N-leak_size[1])
        leak2 = sigs[1]["leak"] << (N-leak_size[1])
        leak_beginning = leak_size[0]
        leak_end = leak_size[1]
        l = N - leak_beginning
        K = 2^(max(leak_beginning, N-leak_end))

        t = -int(inverse_mod(s1, n)*s2*r1*inverse_mod(r2, n))
        u = int(inverse_mod(s1, n)*r1*h2*inverse_mod(r2, n) - inverse_mod(s1, n)*h1)
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
        print("Running LLL")
        return B.LLL()
    print("Running BKZ with block size {}".format(block_size))
    return B.BKZ(block_size=block_size,  auto_abort = True)

def get_key_msb_lsb(B, Q, n, G):
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

def alternative_system_solver_middle_bits(B, signatures, leak_size, n, G, X, N): # Not better than the other implementation
    #print(B)
    r1, s1, h1 = signatures[0]["r"], signatures[0]["s"], signatures[0]["h"]
    r2, s2, h2 = signatures[1]["r"], signatures[1]["s"], signatures[1]["h"]

    Zn = Zmod(n)
    leak_beginning = leak_size[0]
    leak_end = leak_size[1]
    t = -inverse_mod(s1, n)*s2*r1*inverse_mod(r2, n)
    u = inverse_mod(s1, n)*r1*h2*inverse_mod(r2, n) - inverse_mod(s1, n)*h1
    leak1 = signatures[0]["leak"] << (N-leak_size[1])
    leak2 = signatures[1]["leak"] << (N-leak_size[1])
    u_new = leak1 + t*leak2 + u
    l = N - leak_beginning

    R.<x1,y1,x2,y2> = ZZ[]
    
    def getf(M,i):
        return M[i,0]/X*x1+M[i,1]/X*y1+M[i,2]/X*x2+M[i,3]/X*y2+M[i,4]

    I = ideal(getf(B,i) for i in range(4))
    groebner_basis = I.groebner_basis()
    print(groebner_basis)
    # Extract the constant values from each polynomial in the Groebner basis
    values = [-poly.constant_coefficient() for poly in groebner_basis]    
    x1 = values[0]
    y1 = values[1]
    x2 = values[2]
    y2 = values[3]

    assert(Zn(x1 + 2^l*y1 + t*x2 + t*2^l*y2 + u_new) == 0)

    k1 = y1*(2^l) + leak1 + x1
    k2 = y2*(2^l) + leak2 + x2
    print("k1: ", hex(k1))
    print("k2: ", hex(k2))

    priv_key1 = Zn(inverse_mod(r1, n)*(s1*k1 - h1))
    priv_key2 = Zn(inverse_mod(r2, n)*(s2*k2 - h2))

    assert(priv_key1 == priv_key2)
    return int(priv_key1)


def solve_system_for_middle_bits(B, signatures, leak_size, n, G, X, N):
    Zn = Zmod(n)
    r1, s1 = signatures[0]["r"], signatures[0]["s"]
    r2, s2 = signatures[1]["r"], signatures[1]["s"]
    h1, h2 = signatures[0]["h"], signatures[1]["h"]

    leak_beginning = leak_size[0]
    leak_end = leak_size[1]
    leak1 = signatures[0]["leak"] << (N-leak_size[1])
    leak2 = signatures[1]["leak"] << (N-leak_size[1])
    l = N - leak_beginning
    K = 2^(max(leak_beginning, N-leak_end))
    
    t = -inverse_mod(s1, n)*s2*r1*inverse_mod(r2, n)
    u = inverse_mod(s1, n)*r1*h2*inverse_mod(r2, n) - inverse_mod(s1, n)*h1
    u_new = leak1 + t*leak2 + u

    eq_system = Matrix(ZZ, 4, 4)
    b = []
    equation_index = 0
    for v in B[:-1]:
        if not v.is_zero():
            eq_system[equation_index] = [x//K for x in v[:4]]
            b.append(-v[4])
            equation_index += 1

    """
    x -> LSB recovered
    y -> MSB recovered
    """

    x1, y1, x2, y2 = eq_system.solve_right(vector(ZZ, b))
    assert(Zn(x1 + 2^l*y1 + t*x2 + t*2^l*y2 + u_new) == 0)

    k1 = y1*(2^l) + leak1 + x1
    k2 = y2*(2^l) + leak2 + x2
    print("k1: ", hex(k1))
    print("k2: ", hex(k2))

    priv_key1 = Zn(inverse_mod(r1, n)*(s1*k1 - h1))
    priv_key2 = Zn(inverse_mod(r2, n)*(s2*k2 - h2))

    assert(priv_key1 == priv_key2)
    return int(priv_key1)


def choose_atk_params(N):
    while(True):
        print("Choose what you want to be leaked")
        print("1. MSB")
        print("2. LSB")
        print("3. Middle bits")
        print("Q. Quit")
        choice = input("> ")
        if choice == 'Q' or choice == 'q':
            exit()
        if int(choice) == 1:
            type = "MSB"
            break
        elif int(choice) == 2:
            type = "LSB"
            break
        elif int(choice) == 3:
            type = "Middle"
            break
        else:
            print("Invalid choice")
        
    if type == "Middle":
        print(f"Beginning of the leak (0-{N-1})")
        leak_beginning = int(input("> "))
        print(f"End of the leak ({leak_beginning}-{N-1})")
        leak_end = int(input("> "))
        leak_size = [leak_beginning, leak_end]
    else:
        while(True):
            leak_size = int(input(f"Number of {type} to be leaked\n> "))
            
            if(leak_size >= N):
                print("Seriously?")
            else:   
                break
    return type, leak_size

def msb_experimental(B, Q, n, G, signatures, leak_size, N):
    Zn = Zmod(n)
    for i in range(len(signatures)):
        s = int(signatures[i]["s"])
        r = int(signatures[i]["r"])
        h = int(signatures[i]["h"])
        k = abs(B[-1][i]) + signatures[i]["leak"]*(2^(N-leak_size))
        if(int(k)==int(signatures[i]["k"])):
            return int(Zn((s*k-h)*inverse_mod(r, n)))                 
    return 0
    
    

def attack(type, leak_size, dumpsigs, data, show_lattice, show_sigs, E, N, curve_name):
    p, F ,E, n, G = ec_get_info(E)
    
    print(f"\nElliptic curve {curve_name}")
    print("Order of G n = {}\n".format(hex(n)))

    message = "Do electric sheep dream of androids?"
    
    if(data is not None): # Load signatures and keys from file if --load
        Q = E(data.get("public_key"))
        signatures = data.get("signatures")
        num_signatures = len(signatures)
        d = data.get("private_key") 
        print("Loaded {} signatures".format(num_signatures))
    else: # Generate new signatures and keys
        d = randrange(n)
        Q = d * G

        if(type == "Middle"):
            num_signatures = 2
            assert(isinstance(leak_size, list))
            assert(leak_size[1]<=N and leak_size[0] >= 0)  
            assert(leak_size[0] < leak_size[1])
        else:
            num_signatures = int(1.3 * (4/3) * (N/leak_size))
            num_signatures = int(2 * (N/leak_size))

        signatures = generate_signatures(G, d, num_signatures, type, message, leak_size, Q)
        print("Generated {} signatures".format(num_signatures))

    assert(len(signatures) == num_signatures) # sanity check
    assert(E.is_on_curve(Q[0],Q[1])) # sanity check
    assert(G.order() == n) # sanity check

    # Print signatures if --showsigs
    if(show_sigs):
        print("\nSignatures:")
        for i in range(num_signatures):
            print(f"{i}: r = {hex(signatures[i]['r'])}, s = {hex(signatures[i]['s'])}, k = {hex(signatures[i]['k'])}, leak = {signatures[i]['leak']}")

    # Print keys
    print("\nPublic Key Q = {}".format(hex(Q.xy()[0]), hex(Q.xy()[1])))
    print("Private Key d = {}\n".format(hex(d)))
    
    # Dump signatures, keys, leak size and type of leak to a file for later use if --dump
    if(dumpsigs): 
        with open("signatures.json", "w") as f:
            json.dump({"signatures": signatures, "private_key": d, "leak_size": leak_size, "type": type, "public_key": [int(Q.xy()[0]), int(Q.xy()[1])], "curve_name": curve_name}, f)

    #print("LEAK_SIZE = ",leak_size)
    print(f"\n{leak_size} {type} of every signature's nonce are leaked\n")
  
    B = construct_lattice(signatures, n, leak_size, type, N)

    # Print lattice if --showlattice
    if(show_lattice):
        print("\nConstructed lattice:")
        for row in B:
            print("[", end=" ")
            for elem in row:
                print(hex(elem), end=" ")
            print("]")

    if(type == "Middle"):
        reduced = reduce_lattice(B, None)
        K = 2^(max(leak_size[0], N-leak_size[1]))
        try:
            found = solve_system_for_middle_bits(reduced, signatures, leak_size, n, G, K, N)
            if found:
                print("private key recovered: ", hex(found))
                r, s = ecdsa_sign("I find your lack of faith disturbing", found, G)
                assert(ecdsa_verify(r, s, "I find your lack of faith disturbing", G, found, Q))
                print("SUCCESS")
            else:
                print("FAILED") 
        except:
            print("System has no solution\nFAILED")
    else:  # LSB or MSB
        block_sizes = [None, 15, 20, 25, 30, 40, 50, 60, num_signatures]
        for block_size in block_sizes:
            reduced = reduce_lattice(B, block_size)
            found = get_key_msb_lsb(reduced, Q, n, G)

            if found :
                print("private key recovered: ", hex(found))
                r, s = ecdsa_sign("I find your lack of faith disturbing", found, G)
                assert(ecdsa_verify(r, s, "I find your lack of faith disturbing", G, found, Q))
                print("SUCCESS")
                break
            else:
                print("FAILED")
    """
    elif type=="MSB":
        block_sizes = [None, 15, 20, 25, 30, 40, 50, 60, num_signatures]
        for block_size in block_sizes:
            reduced = reduce_lattice(B, block_size)
            found = msb_experimental(reduced, Q, n, G, signatures, leak_size, N)
            if found :
                print("private key recovered: ", hex(found))
                r, s = ecdsa_sign("I find your lack of faith disturbing", found, G)
                assert(ecdsa_verify(r, s, "I find your lack of faith disturbing", G, found, Q))
                print("SUCCESS")
                break
            else:
                print("FAILED")
    """

if __name__ == "__main__":
    print("ECDSA Lattice attacks playground")
    dumpsigs = False
    data = None
    loadsigs = False
    show_sigs = False
    show_lattice = False
    curve = None
    if("--help" in sys.argv):
        print("Usage: sage attack.sage [--options]")
        print("Options:")
        print("--load: Load data (signatures, keys, message) from signatures.json")
        print()
        print("--dump: Dump data (signatures, keys, message) to signatures.json")
        print("--showsigs: Print signatures")
        print("--showlattice: Print constructed lattice")
        print("--help: Display this message")
    if("--load" in sys.argv):
        print("Signatures will be loaded from signatures.json")
        loadsigs = True
        with open("signatures.json", "r") as f:
            
            data = json.load(f)
        type = data.get("type")
        leak_size = data.get("leak_size")
        
        
    if("--dump" in sys.argv):
        dumpsigs = True
        print("Signatures will be dumped to signatures.json")
    if("--showsigs" in sys.argv):
        show_sigs = True
    if("--showlattice" in sys.argv):
        show_lattice = True

    if(not loadsigs):
        curve = {}
        curve_name = choose_curve()
        E, N = ecdsa_init(curve_name)
        type, leak_size = choose_atk_params(N)
    else:
        type = data.get("type")
        leak_size = data.get("leak_size")
        curve_name = data.get("curve_name")
        E, N = ecdsa_init(data.get("curve_name"))
    attack(type, leak_size, dumpsigs, data, show_lattice, show_sigs, E, N, curve_name) 
    print("\n\n\n")        
        

