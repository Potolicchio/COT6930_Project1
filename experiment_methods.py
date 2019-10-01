import secrets
import string


def generate_random_string(length):
    alphabet = string.ascii_letters + string.digits
    phrase = ''.join(secrets.choice(alphabet) for i in range(length))
    return phrase


