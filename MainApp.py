# Tapez le code principal
"""*********************************** 

Nom Programme : Mini-Projet Python (DS)

Auteurs : 

            BANI Mootez

            BARRANI Nour

Classe : CII-2-SIIR-C

***********************************"""

import MaBiB


def main():
    while True:
        print("""|        Application Multi Taches          | 
--------|       Menu Principal      |--------
A- Enregistrement
B- Authentification
	B1- Hachage
	B2- Chiffrement
C- Quitter""")

        choiceP = input("Enter your choice (A/B/C): ").upper()

        if choiceP == 'A':
            MaBiB.task_A()
        elif choiceP == 'B':
            if MaBiB.authenticate_user():
                MaBiB.task_B()
        elif choiceP == 'C':
            MaBiB.task_C()
        else:
            print("Invalid choice. Please choose from A, B, or C.")


if __name__ == "__main__":
    main()
