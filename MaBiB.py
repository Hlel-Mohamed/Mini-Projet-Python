# Déclaration des fonctions dans cette bibliothèque
"""*********************************** 

Nom Programme : Mini-Projet Python (DS)

Auteurs :

            BANI Mootez

            BARRANI Nour

Classe : CII-2-SIIR-C

***********************************"""

import re
from getpass import getpass
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Global variables to store RSA keys and signatures
public_key = None
private_key = None
signature = None

# Global variables to store results of hash algorithms
ListeMD5 = []
ListeSHA256 = []
ListeBlake2b = []

# Global dictionary to store login-password pairs for authentication
AuthDic = {}


def load_auth_data():
    try:
        with open("Authentification.txt", "r") as file:
            for line in file:
                if line.startswith("Login&pwd: "):
                    login, pwd = line[len("Login&pwd: "):].strip().split('&')
                    AuthDic[login] = pwd
    except FileNotFoundError:
        print("No Authentification.txt file found. Please use MenuA to save user data.")


def authenticate_user():
    load_auth_data()
    login = input("Login: ")
    pwd = input("Password: ")

    if login in AuthDic and AuthDic[login] == pwd:
        return True
    else:
        print("Authentication failed. Please register before attempting authentication.")
        return False


def task_A():
    while True:
        print("""--------|       Menu A : Enregistrement      |--------
A1- Sauvegarder Données utilisateur
A2- Lire Données utilisateur 
A3- Revenir au menu principal""")

        choiceP = input("Enter your choice (A1/A2/A3): ").upper()

        if choiceP == 'A1':
            save_user_data()
        elif choiceP == 'A2':
            read_user_data()
        elif choiceP == 'A3':
            return
        else:
            print("Invalid choice. Please choose from A, B, or C.")


def save_user_data():
    with open("Authentification.txt", "a") as file:
        print("Enter user information:")
        id_user = input("Id_user: ")
        login = input("Login: ")
        pwd = input("Password: ")
        email = input("Email: ")

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            print("Invalid email address. Data not saved.")
            return

        classe = "CII-2-SIIR-" + input("Classe (A/B/C/D): ").upper()

        user_info = f"""
Id_user : {id_user}
Login&pwd: {login}&{pwd}
Classe : {classe}
Email : {email}
"""
        file.write(user_info)
        print("User data saved successfully!")


def read_user_data():
    try:
        with open("Authentification.txt", "r") as file:
            user_data = file.read()
            print("User Data:")
            print(user_data)
    except FileNotFoundError:
        print("No user data found. Please use option A to save user data.")


def task_B():
    while True:
        print("""--------|       Menu B : Authentification      |--------
B1- Hachage
B2- Chiffrement
B3- Revenir au menu principal""")

        choiceB = input("Enter your choice (B1/B2/B3): ").upper()

        if choiceB == 'B1':
            menu_B1()
        elif choiceB == 'B2':
            menu_B2()
        elif choiceB == 'B3':
            return
        else:
            print("Invalid choice. Please choose from B1, B2, or B3.")


def menu_B1():
    while True:
        print("""--------|       Menu B1 :  Hachage      |--------
B1-a  Hacher un message par MD5
B1-b  Hacher un message par SHA256
B1-c  Hacher un message par Blake2b
B1-d  Cracker un message Haché
B1-e Revenir au menu MenuB""")

        choiceB1 = input("Enter your choice (a/b/c/d/e): ").upper()

        if choiceB1 == 'A':
            hash_messages("MD5", ListeMD5, ["Password", "azerty", "shadow", "hunter"])
        elif choiceB1 == 'B':
            hash_messages("SHA256", ListeSHA256, ["Password", "azerty", "shadow", "hunter"])
        elif choiceB1 == 'C':
            hash_messages("Blake2b", ListeBlake2b, ["Password", "azerty", "shadow", "hunter"])
        elif choiceB1 == 'D':
            crack_hashed_message()
        elif choiceB1 == 'E':
            return
        else:
            print("Invalid choice. Please choose from B1-a, B1-b, B1-c, B1-d, or B1-e.")


def menu_B2():
    while True:
        print("""--------|       Menu B2 :  Chiffrement      |--------
B2-a Cesar 
B2-b Affine
B2-c RSA
B1-d Revenir au menu MenuB
""")

        choiceB2 = input("Enter your choice (A/B/C/D): ").upper()

        if choiceB2 == 'A':
            menu_B2a()
        elif choiceB2 == 'B':
            menu_B2b()
        elif choiceB2 == 'C':
            menu_B2c()
        elif choiceB2 == 'D':
            return
        else:
            print("Invalid choice. Please choose from A, B, C, or D .")


def menu_B2a():
    while True:
        print("""--------| Menu B2a : Chiffrement de Cesar |--------
B2-a1 Chiffrement message
B2-a2 Déchiffrement message
B2-a3 Revenir au menu MenuB2""")

        choiceB2a = input("Enter your choice (A1/A2/A3): ").upper()

        if choiceB2a == 'A1':
            caesar_encrypt()
        elif choiceB2a == 'A2':
            caesar_decrypt()
        elif choiceB2a == 'A3':
            return
        else:
            print("Invalid choice. Please choose from A1, A2, or A3.")


def menu_B2b():
    while True:
        print("""--------| Menu B2b : Chiffrement Affine |--------
B2-b1 Chiffrement message
B2-b2 Déchiffrement message
B2-b3 Revenir au menu MenuB2""")

        choiceB2b = input("Enter your choice (B1/B2/B3): ").upper()

        if choiceB2b == 'B1':
            affine_encrypt()
        elif choiceB2b == 'B2':
            affine_decrypt()
        elif choiceB2b == 'B3':
            return
        else:
            print("Invalid choice. Please choose from B, B2, or B3.")


def menu_B2c():
    rsa_generate_key_pair()
    while True:
        print("""--------| Menu B2c : Chiffrement RSA |--------
B2-c1 Chiffrement message
B2-c2 Déchiffrement message
B2-c3 Signature
B2-c4 Vérification Signature
B2-c5 Revenir au menu MenuB2""")

        choiceB2c = input("Enter your choice (C1/C2/C3/C4/C5): ").upper()

        if choiceB2c == 'C1':
            rsa_encrypt()
        elif choiceB2c == 'C2':
            rsa_decrypt()
        elif choiceB2c == 'C3':
            rsa_sign()
        elif choiceB2c == 'C4':
            rsa_verify()
        elif choiceB2c == 'C5':
            return
        else:
            print("Invalid choice. Please choose from C1, C2, C3, C4, or C5.")


def hash_messages(algorithm, result_list, messages):
    for message in messages:
        hasher = hashlib.new(algorithm)
        hasher.update(message.encode('utf-8'))
        hashed_message = hasher.hexdigest()
        result_list.append(hashed_message)
        print(f"{algorithm} hash of '{message}': {hashed_message}")


def crack_hashed_message():
    hashed_message = input("Enter a hashed message: ")

    if hashed_message in ListeMD5:
        print(f"Message found in MD5 list.")
    elif hashed_message in ListeSHA256:
        print(f"Message found in SHA256 list.")
    elif hashed_message in ListeBlake2b:
        print(f"Message found in Blake2b list.")
    else:
        print(f"Message not found in any list.")


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


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def rsa_generate_key_pair():
    global public_key, private_key

    # Generate a new RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Serialize and store the private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open("private_key.pem", "wb") as private_key_file:
        private_key_file.write(private_pem)

    # Get the corresponding public key
    public_key = private_key.public_key()

    # Serialize and store the public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("public_key.pem", "wb") as public_key_file:
        public_key_file.write(public_pem)

    print("RSA key pair generated and stored in private_key.pem and public_key.pem.")


def rsa_encrypt():
    if public_key is None:
        print("RSA public key not available. Generate key pair first.")
        return

    message = input("Enter the message to encrypt: ").encode('utf-8')

    # Use PKCS1v15 padding for encryption
    encrypted_message = public_key.encrypt(message, padding.PKCS1v15())

    print("Encrypted message: ", encrypted_message)


def rsa_decrypt():
    if private_key is None:
        print("RSA private key not available. Generate key pair first.")
        return

    encrypted_message = input("Enter the message to decrypt: ").encode('utf-8')

    # Specify the padding when decrypting
    decrypted_message = private_key.decrypt(encrypted_message, padding.PKCS1v15()).decode('utf-8')

    print("Decrypted message: ", decrypted_message)


def rsa_sign():
    if private_key is None:
        print("RSA private key not available. Generate key pair first.")
        return

    message = input("Enter the message to sign: ").encode('utf-8')
    global signature
    signature = hashlib.md5(message).digest()
    print("Signature created successfully.")


def rsa_verify():
    if public_key is None or signature is None:
        print("RSA public key or signature not available. Generate key pair and sign first.")
        return

    message = input("Enter the message to verify: ").encode('utf-8')
    new_signature = hashlib.md5(message).digest()
    if new_signature == signature:
        print("Signature verified successfully.")
    else:
        print("Signature verification failed.")


def task_C():
    print("Exiting the application.")
    exit()
