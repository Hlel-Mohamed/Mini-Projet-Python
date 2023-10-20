"""***********************************

Nom Programme : Mini-Projet Python (DS)

Auteurs :

            BANI Mootez

            BARRANI Nour

Classe : CII-2-SIIR-C

***********************************"""
from math import gcd


def affine_encrypt():
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    message = input("Enter the message to encrypt: ").upper()
    key_a = int(input("Enter the key 'Ka' (a number coprime to 26): "))
    key_b = int(input("Enter the key 'Kb' (an integer): "))

    if gcd(key_a, 26) != 1:
        print("Ka is not coprime to 26. Choose a different value for Ka.")
        return

    encrypted_message = ""

    for char in message:
        if char in alphabet:
            char_index = alphabet.index(char)
            encrypted_index = (key_a * char_index + key_b) % 26
            encrypted_message += alphabet[encrypted_index]
        else:
            encrypted_message += char  # Keep non-alphabetic characters as is

    print(f"Encrypted message: {encrypted_message}")


def affine_decrypt():
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    message = input("Enter the message to decrypt: ").upper()
    key_a = int(input("Enter the key 'Ka' (a number coprime to 26): "))
    key_b = int(input("Enter the key 'Kb' (an integer): "))

    if gcd(key_a, 26) != 1:
        print("Ka is not coprime to 26. Choose a different value for Ka.")
        return

    decrypted_message = ""

    for char in message:
        if char in alphabet:
            char_index = alphabet.index(char)
            decrypted_index = (mod_inverse(key_a, 26) * (char_index - key_b)) % 26
            decrypted_message += alphabet[decrypted_index]
        else:
            decrypted_message += char  # Keep non-alphabetic characters as is

    print(f"Decrypted message: {decrypted_message}")


def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None
