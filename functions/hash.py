"""***********************************

Nom Programme : Mini-Projet Python (DS)

Auteurs :

            BANI Mootez

            BARRANI Nour

Classe : CII-2-SIIR-C

***********************************"""

import hashlib

ListeMD5 = []
ListeSHA256 = []
ListeBlake2b = []


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
