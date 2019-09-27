#!/usr/bin/env python3

import sys

import rsa_methods as rsa

def main():
    print("Testing Rivest-Shamir-Adelson methods...\n")
    print("Square-and-Multiply modular exponentiation test: 11^13 mod(19) =", rsa.mod_exp_sam(11, 13, 19))
    print("Rabin-Miller Primality Test: Is 59 prime?", rsa.miller_rabin_test(59, 40))
    a, b = 23, 59
    s, t = rsa.eea_prime(a, b)
    print("Extended Euclidean Algorithm Test: The Bézout coefficients for a =", a, "and b =", b, "are s =", s,
          "and t =", t)
    print("\tVerification:", s, "*", a, "+", t, "*", b, "=", s * a + t * b)
    inv_a = rsa.mul_inv(a, b)
    print("Modular Multiplicative Inverse Test: The modular multiplicative inverse for a =", a, "mod n =", b, " is inv_a =", inv_a )
    print("\tVerification:", a, "+", inv_a, "=", a * inv_a, "=", int((a * inv_a - 1) / b), "*", b,"+ 1")
    print("\nTesting Rivest-Shamir-Adelson probabilistic public-key encryption scheme using 1024-bit prime numbers...")
    test_public_key, test_private_key = rsa.rsa_key_generation(1024)
    test_message = "The real treasure was the friends we made along the way!"
    print("\nTest Public Key:\n", test_public_key)
    print("\nTest Private Key:\n", test_private_key)
    print("\nTest Plaintext Input:\n", test_message)
    test_rsa_encryption = rsa.rsa_encryption(test_message, test_public_key)
    print("\nTest of Rivest-Shamir-Adelson Encryption:\n", test_rsa_encryption)
    test_rsa_decryption = rsa.rsa_fast_decryption(test_rsa_encryption, test_private_key)
    print("\nTest of Rivest-Shamir-Adelson Decryption:\n", test_rsa_decryption)
    test_rsa_signature = rsa.rsa_fast_sign(test_message, test_private_key)
    print("\nTest of Rivest-Shamir-Adelson Signature:\n", test_rsa_signature)
    test_rsa_verification = rsa.rsa_verify(test_message, test_rsa_signature, test_public_key)
    print("\nTest of Rivest-Shamir-Adelson Verifcation:\nThe digital signature is valid: ", test_rsa_verification)
    print("\nRivest-Shamir-Adelson testing successfully completed!")
    sys.exit(0)

if __name__ == "__main__":
    main()
