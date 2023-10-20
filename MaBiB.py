# Déclaration des fonctions dans cette bibliothèque
"""*********************************** 

Nom Programme : Mini-Projet Python (DS)

Auteurs :

            BANI Mootez

            BARRANI Nour

Classe : CII-2-SIIR-C

***********************************"""

from functions.rsa import *
from functions.userData import *
from functions.hash import *
from functions.caesar import *
from functions.affine import *


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


def task_C():
    print("Exiting the application.")
    exit()


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
            hash_messages("blake2b", ListeBlake2b, ["Password", "azerty", "shadow", "hunter"])
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
