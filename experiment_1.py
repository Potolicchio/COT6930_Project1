#!/usr/bin/env python3

import sys
import time

from scipy import stats

import experiment_methods as exp
import rsa_methods as rsa


def main():
    print()
    print("Experiment 1: Rivest-Shamir-Adelson Decryption Acceleration with Chinese Remainder Theorem\n", sep="")

    key_bits = 1024
    message_length = 256
    num_of_trials = 10
    ns_conversion = 10**9

    print("Generating random ", key_bits, " bit RSA keys...", sep="")
    public_key, private_key = rsa.rsa_key_generation(key_bits)
    n, e = public_key
    p, q, d = private_key
    print("Public key = ", public_key, sep="")
    print("Private key = ", private_key, "\n", sep="")

    print("Generating a random string to be encrypted using RSA...", sep="")
    message = exp.generate_random_string(message_length)
    print("Test Phrase =" , message, "\n", sep="")

    print("Encrypting test phrase using RSA...", sep="")
    ciphertext = rsa.rsa_encryption(message, public_key)
    print("Ciphertext = ", ciphertext, "\n", sep="")

    print("Testing RSA decryption time without using CRT...", sep="")
    no_crt_decrypt_timings_ns = []
    no_crt_decrypt_timings_s = []
    for i in range(num_of_trials):
        current_start_time_ns = time.time_ns()
        current_decrypted_message = rsa.rsa_no_crt_decryption(ciphertext, public_key, private_key)
        if current_decrypted_message == message:
            current_end_time_ns = time.time_ns()
            current_time_ns = current_end_time_ns - current_start_time_ns
            no_crt_decrypt_timings_ns.append(current_time_ns)
            current_time_s = current_time_ns / ns_conversion
            no_crt_decrypt_timings_s.append(current_time_s)
            print("Trial ", i+1, " = ", current_time_s, " seconds", sep="")
        else:
            print("ERROR: decrypted ciphertext does not match original message", sep="")
            sys.exit(0)
    print()

    print("Testing RSA decryption time using CRT acceleration...", sep="")
    crt_decrypt_timings_ns = []
    crt_decrypt_timings_s = []
    for i in range(num_of_trials):
        current_start_time_ns = time.time_ns()
        current_decrypted_message = rsa.rsa_crt_decryption(ciphertext, private_key)
        if current_decrypted_message == message:
            current_end_time_ns = time.time_ns()
            current_time_ns = current_end_time_ns - current_start_time_ns
            crt_decrypt_timings_ns.append(current_time_ns)
            current_time_s = current_time_ns / ns_conversion
            crt_decrypt_timings_s.append(current_time_s)
            print("Trial ", i + 1, " = ", current_time_s, " seconds", sep="")
        else:
            print("ERROR: decrypted ciphertext does not match original message", sep="")
            sys.exit(0)
    print()

    print("Experiment Results:")
    print("RSA decryption times without CRT acceleration (in seconds): ", no_crt_decrypt_timings_s, sep="")
    print("RSA decryption times with CRT acceleration (in seconds): ", crt_decrypt_timings_s, "\n", sep="")
    no_crt_decrypt_avg = sum(no_crt_decrypt_timings_s) / len(no_crt_decrypt_timings_s)
    crt_decrypt_avg = sum(crt_decrypt_timings_s) / len(crt_decrypt_timings_s)
    percent_improvement = 100 - ((crt_decrypt_avg / no_crt_decrypt_avg) * 100)
    print("Average RSA decryption time without CRT acceleration = ", format(no_crt_decrypt_avg, "0.3f"), " seconds", sep="")
    print("Average RSA decryption time with CRT acceleration = ", format(crt_decrypt_avg, "0.3f"), " seconds", sep="")
    print("Percent improvement by CRT acceleration = ", format(percent_improvement, "0.3f"), "%\n", sep="")
    t, p = stats.ttest_ind(no_crt_decrypt_timings_s, crt_decrypt_timings_s)
    print("p-value = ", p, sep="")
    if p < 0.01:
        print("The results of this experiment are statistically significant for p < 0.01")
    else:
        print("The results of this experiment are not statistically significant")
    print()


if __name__ == "__main__":
    main()
