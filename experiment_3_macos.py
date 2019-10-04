#!/usr/bin/env python3

import secrets
import time

import matplotlib.pyplot as plt

import experiment_methods as exp
import rsa_methods as rsa


def main():
    print()
    print("Experiment 3: Rivest-Shamir-Adelson Decryption Timing Attack\n", sep="")

    key_bits = 1024
    message_length = 256
    random_int = secrets.randbelow(256)
    public_key, private_key = rsa.rsa_key_generation(key_bits)
    n, e = public_key
    p, q, d = private_key
    message = exp.generate_random_string(message_length)
    ciphertext = rsa.rsa_encryption(message, public_key)

    key_list = [1]*2048
    key = int.from_bytes(bytes(key_list), "big")
    num_of_trials = 2048

    print("Testing Square-and-Multiply Modular Exponentiation Timing for True Key Value...", sep="")
    current_start_time = time.time()
    rsa.mod_exp_sam(ciphertext[random_int], d, n)
    current_end_time = time.time()
    true_time = current_end_time - current_start_time
    print("True Key Decryption Time = ", true_time, sep="")

    print("Testing Square-and-Multiply Modular Exponentiation Timing for Different Key Values...", sep="")
    mod_exp_sam_timings = []
    for i in range(num_of_trials - 1):
        current_start_time = time.time()
        rsa.mod_exp_sam(ciphertext[random_int], key, n)
        current_end_time = time.time()
        current_time = current_end_time - current_start_time
        mod_exp_sam_timings.append(current_time)
        print("Trial ", i+1, " = ", current_time, " seconds", sep="")
        key_list[i+1] = 0
        key = int.from_bytes(bytes(key_list), "big")
    print()

    print("Experiment Results:")
    print(mod_exp_sam_timings)
    x = range(1, len(mod_exp_sam_timings) + 1, 1)
    mod_exp_sam_timings.reverse()
    y = mod_exp_sam_timings
    plt.scatter(x, y)
    plt.xlabel("Number of 1's in d")
    plt.ylabel("Time to perform mod exp s-a-m in seconds")
    plt.title("Experiment 3: RSA Timing Attack")
    plt.show()


if __name__ == "__main__":
    main()
