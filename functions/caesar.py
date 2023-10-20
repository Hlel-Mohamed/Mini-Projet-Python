"""***********************************

Nom Programme : Mini-Projet Python (DS)

Auteurs :

            BANI Mootez

            BARRANI Nour

Classe : CII-2-SIIR-C

***********************************"""


def caesar_encrypt():
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    message = input("Enter the message to encrypt: ").upper()
    shift = int(input("Enter the shift value (key): "))

    encrypted_message = ""

    for char in message:
        if char in alphabet:
            char_index = alphabet.index(char)
            encrypted_index = (char_index + shift) % 26
            encrypted_message += alphabet[encrypted_index]
        else:
            encrypted_message += char  # Keep non-alphabetic characters as is

    print(f"Encrypted message: {encrypted_message}")


def caesar_decrypt():
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    message = input("Enter the message to decrypt: ").upper()
    shift = int(input("Enter the shift value (key): "))

    decrypted_message = ""

    for char in message:
        if char in alphabet:
            char_index = alphabet.index(char)
            decrypted_index = (char_index - shift) % 26
            decrypted_message += alphabet[decrypted_index]
        else:
            decrypted_message += char  # Keep non-alphabetic characters as is

    print(f"Decrypted message: {decrypted_message}")
