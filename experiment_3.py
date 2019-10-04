#!/usr/bin/env python3

import secrets
import sys
import time

import matplotlib.pyplot as plt
import numpy as np
from scipy import stats

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
    ns_conversion = 10**9

    print("Testing Square-and-Multiply Modular Exponentiation Timing for True Key Value...", sep="")
    current_start_time_ns = time.time_ns()
    rsa.mod_exp_sam(ciphertext[random_int], d, n)
    current_end_time_ns = time.time_ns()
    true_time_ns = current_end_time_ns - current_start_time_ns
    true_time_s = true_time_ns / ns_conversion
    print("True Key Decryption Time = ", true_time_s, sep="")

    print("Testing Square-and-Multiply Modular Exponentiation Timing for Different Key Values...", sep="")
    mod_exp_sam_timings_ns = []
    mod_exp_sam_timings_s = []
    for i in range(num_of_trials - 1):
        current_start_time_ns = time.time_ns()
        rsa.mod_exp_sam(ciphertext[random_int], key, n)
        current_end_time_ns = time.time_ns()
        current_time_ns = current_end_time_ns - current_start_time_ns
        mod_exp_sam_timings_ns.append(current_time_ns)
        current_time_s = current_time_ns / ns_conversion
        mod_exp_sam_timings_s.append(current_time_s)
        print("Trial ", i+1, " = ", current_time_s, " seconds", sep="")
        key_list[i+1] = 0
        key = int.from_bytes(bytes(key_list), "big")
    print()

    print("Experiment Results:")
    print(mod_exp_sam_timings_s)
    x = range(1, len(mod_exp_sam_timings_s) + 1, 1)
    mod_exp_sam_timings_s.reverse()
    y = mod_exp_sam_timings_s
    plt.scatter(x, y)
    plt.xlabel("Number of 1's in d")
    plt.ylabel("Time to perform mod exp s-a-m in seconds")
    plt.title("Experiment 3: RSA Timing Attack")
    plt.show()


if __name__ == "__main__":
    main()
