import hashlib
import math
import secrets


# Implementation of Square-and-Multiply fast modular exponentiation function.
# Make sure that every argument passed to this function is an integer to avoid floating-point errors.
def mod_exp_sam(base, exponent, modulus):
    k = bin(exponent)
    b = 1
    if exponent == 0:
        return b
    a = base
    if k[-1] == '1':
        b = a
    i = -2
    while k[i] != 'b':
        a = a**2 % modulus
        if k[i] == '1':
            b = a * b % modulus
        i -= 1
    return b


# Implementation of the Miller-Rabin primality test.
# The recommended number of rounds for the security parameter is 40.
def miller_rabin_test(num, security_parameter):
    r = num - 1
    s = 0
    # equivalent to r % 2 == 0
    while r & 1 == 0:
        # equivalent to r //= 2
        r >>= 1
        s += 1
    for i in range(security_parameter):
        a = secrets.randbelow(num - 1)
        while a <= 2:
            a = secrets.randbelow(num - 1)
        y = mod_exp_sam(a, r, num)
        if y != 1 and y != num - 1:
            j = 1
            while j <= s - 1 and y != num - 1:
                # since Square-and-Multiply fast modular exponentiation contains the line "a = a**2 % modulus"
                # for an exponent of 2 it would be slower to call than just calculating y**2 % num
                y = y**2 % num
                y = mod_exp_sam(y, 2, num)
                if y == 1:
                    return False
                j += 1
            if y != num - 1:
                return False
    return True


# Generates random integers of a specified bit length until the Miller-Rabin primality test returns true.
def get_large_prime(bit_length):
    bit_length = int(bit_length)
    while True:
        rand_num = secrets.randbits(bit_length)
        if rand_num % 3 == 0 or rand_num % 5 == 0 or rand_num % 7 == 0 or rand_num % 11 == 0\
                or miller_rabin_test(rand_num, 40) is False:
            continue
        return rand_num


# Performs the Extended Euclidean Algorithm to get the Bézout coefficients for two prime numbers.
# Because the two integers passed to this function will always be prime, GCD(p, q) will always be 1.
def eea_prime(p, q):
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = q, p
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_s, old_t


# Performs the Extended Euclidean Algorithm to obtain the multiplicative inverse
def mul_inv(e, phi):
    # e was selected such that it is guaranteed to be relatively prime to phi
    if math.gcd(e,phi) == 1:
        s, t = eea_prime(e,phi)
        d = s % phi
        return d

# Generates the public key tuple and private key for the Rivest-Shamir-Adelman encryption scheme.
def rsa_key_generation(bit_length):
    bit_length = int(bit_length)
    p = get_large_prime(bit_length)
    q = get_large_prime(bit_length)
    phi = (p - 1) * (q - 1)
    n = p * q
    while True:
        e = secrets.randbelow(phi - 1)
        if math.gcd(e, phi) == 1:
            break
        else:
            continue
    d = mul_inv(e, phi)
    rsa_public_key = (n, e)
    rsa_private_key = (p, q, d)
    return rsa_public_key, rsa_private_key


# Encrypts ASCII plaintext using the Rivest-Shamir-Adelson public-key encryption scheme.
def rsa_encryption(message, rsa_public_key):
    m_list = list(bytearray(message, encoding='ascii'))
    m_len = len(m_list)
    n, e = rsa_public_key
    ciphertext = []
    for i in range(m_len):
        ciphertext.append(mod_exp_sam(m_list[i], e, n))
    return ciphertext


# Decrypts ASCII ciphertext that was encrypted using the Rivest-Shamir-Adelson public-key encryption scheme.
def rsa_slow_decryption(ciphertext, rsa_public_key, rsa_private_key):
    c_list = ciphertext
    c_len = len(c_list)
    n, e = rsa_public_key
    p, q, d = rsa_private_key
    m_list = []
    for i in range(c_len):
        m_list.append(mod_exp_sam(c_list[i], d, n))
    m_len = len(m_list)
    message = ""
    for j in range(m_len):
        current_char = chr(m_list[j])
        message += current_char
    return message


# Decrypts ASCII ciphertext that was encrypted using the Rivest-Shamir-Adelson public-key encryption scheme.
# Decryption accelerated using the Chinese Remainder Theorem.
def rsa_fast_decryption(ciphertext, rsa_private_key):
    c_list = ciphertext
    c_len = len(c_list)
    p, q, d = rsa_private_key
    m_list = []
    for i in range(c_len):
        a = mod_exp_sam(c_list[i], d, p)
        b = mod_exp_sam(c_list[i], d, q)
        u, v = eea_prime(p, q)
        tp = v * q
        tq = u * p
        m_list.append(a * tp + b * tq)
    m_len = len(m_list)
    message = ""
    for j in range(m_len):
        current_char = chr(m_list[j])
        message += current_char
    return message


# Cryptographically signs Rivest-Shamir-Adelson public-key encryption scheme.
def rsa_slow_sign(message, rsa_public_key, rsa_private_key):
    n, e = rsa_public_key
    p, q, d = rsa_private_key
    h = hashlib.sha256(message.encode()).hexdigest()
    h_int = int(h, 16)
    s = mod_exp_sam(h_int, d, n)
    s_hex = hex(s)
    return s_hex


# Cryptographically sign a message using Rivest-Shamir-Adelson public-key encryption scheme.
# Signing accelerated using the Chinese Remainder Theorem.
def rsa_fast_sign(message, rsa_private_key):
    p, q, d = rsa_private_key
    h = hashlib.sha256(message.encode()).hexdigest()
    h_int = int(h, 16)
    a = mod_exp_sam(h_int, d, p)
    b = mod_exp_sam(h_int, d, q)
    u, v = eea_prime(p, q)
    tp = v * q
    tq = u * p
    s = a * tp + b * tq
    s_hex = hex(s)
    return s_hex


# Verifies a digital signature using Rivest-Shamir-Adelson public-key encryption scheme.
def rsa_verify(message, signature, rsa_public_key):
    n, e = rsa_public_key
    h = hashlib.sha256(message.encode()).hexdigest()
    h_int = int(h, 16)
    s_int = int(signature, 16)
    se_int = mod_exp_sam(s_int, e, n)
    if se_int == h_int:
        return True
    else:
        return False
