# ECDSA Partially Known Nonce Attack

## Overview

This repository contains a SageMath script that implements a lattice attack on the ECDSA (Elliptic Curve Digital Signature Algorithm) based on the principles described in Sections 5.2.1, 5.2.2, 5.2.3 of the paper "[Survey: Recovering cryptographic keys from partial information](https://cic.iacr.org/p/1/1/28/pdf)." The attack allows reconstructing the entire nonce used in ECDSA signatures by exploiting a partial leak of its bits, which can lead to the recovery of the private key.

### Contents

- **`attack.sage`**: A SageMath script that performs the lattice-based attack on ECDSA, allowing you to test different scenarios where partial information about the nonce is leaked.
  
- **CTF folder**: Contains an example of a Capture The Flag (CTF) challenge based on ECDSA attacks:
  - **`vuln.sage`**: The challenge script.
  - **`exploit.sage`**: The exploit script to solve the challenge. The exploit script requires `pwntools` to run.

- **Presentation**: A PowerPoint presentation explaining the attack, the math behind it, and how the script works.

## Requirements

To run the attack and the CTF scripts, the following software needs to be installed:

- **SageMath**: The primary tool for running the lattice reduction and performing elliptic curve operations.
- **Python 3.x**: Required for executing the script, along with the following Python libraries:
  - `Crypto` (from PyCryptodome): For hashing functions.
  - `json`: For loading and saving signatures, keys, and other data.
- **Pwntools** (optional): Required to run the exploit in the CTF challenge. Install it using `pip install pwntools`.

## Usage

The attack script can be executed with various options:

- **`--load`**: Load existing signatures and keys from `signatures.json`.
- **`--dump`**: Save generated signatures and keys to `signatures.json`.
- **`--showsigs`**: Print the generated or loaded signatures.
- **`--showlattice`**: Display the constructed lattice used in the attack.
- **`--help`**: Display the help message.

Running the script without the `--load` option will randomly generate signatures (the smaller the leak, the bigger the number of needed signatures).

### Example

Running the script without `--load` will prompt the user to enter the desired type of leak (MSB, LSB or middle bits chunk) and its size (or range in the middle bits case).
Then it will pick a random private key, derive the public key, generate signatures providing a leak accoding to the previous choice.

```bash
sage attack.sage
```

Running it with `--load` will recover such data from a json file, that was previously produced running the same script with the `--dump` flag.

## Limits
### BKZ Block size reduction  
The attacks implemented rely on lattice reduction algorithms: by default the attack starts reducing the lattice basis using LLL, and if it fails to recover the key it uses BKZ gradually increasing the block size used for block reduction.
These algorithms may require a lot of computational power if the dimensions of the basis are large enough or with a large block size factor for BKZ, so computation might take a very long time to terminate. 
The smaller the leak, the bigger will be the block size used by BKZ to recover the key.
On AMD Ryzen 7 4800H leaks of 3 bits require a block size >= 50 and it takes hours to recover the key.
Anything above 3 bits is instead solved in less than a minute.
### Middle bits leak
Due to the nature of the attack with middle bits leakage (which is different from MSB and LSB in the lattice construction), some ranges (initial position - final position of the bits leaked) perform better than others, meaning that in some cases the solution to the system of equations obtained after running LLL does not exist.

## References
The following papers were studied and used as references to implement the ECDSA lattice attack:
1. [Survey: Recovering cryptographic keys from partial information](https://cic.iacr.org/p/1/1/28/pdf)
2. [Biased Nonce Sense: Lattice Attacks against Weak ECDSA Signatures in Cryptocurrencies](https://eprint.iacr.org/2019/023.pdf)
3. [Return of the Hidden Number Problem](https://tches.iacr.org/index.php/TCHES/article/download/7337/6509/)
4. [Improved Attacks on (EC)DSA with Nonce Leakage by by Lattice Sieving](https://tches.iacr.org/index.php/TCHES/article/view/10294/9744)
5. [A Gentle Tutorial for Lattice-Based Cryptanalysis](https://eprint.iacr.org/2023/032.pdf)


