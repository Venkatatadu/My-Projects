from cipher import encrypt_message, decrypt_message

def main():
    print("Welcome to Cryptography Tool!")
    while True:
        print("\nMain Menu:")
        print("1. Encrypt a Message")
        print("2. Decrypt a Message")
        print("3. Exit")
        
        choice = input("Enter your choice (1/2/3): ")
        
        if choice == "1":
            message = input("Enter the message to encrypt: ")
            key = int(input("Enter the key (number): "))
            encrypted_message = encrypt_message(message, key)
            print(f"Encrypted Message: {encrypted_message}")
        elif choice == "2":
            encrypted_message = input("Enter the encrypted message: ")
            key = int(input("Enter the key (number): "))
            decrypted_message = decrypt_message(encrypted_message, key)
            print(f"Decrypted Message: {decrypted_message}")
        elif choice == "3":
            print("Exiting... Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

