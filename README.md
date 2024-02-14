/*
 * Program: FileEncryptor
 * Description: File encryption and decryption using C# 7.0 console application 
 * Author: DanyOli
 * Date: 2024
 * Version: 1.0
 */

The "File Encryption and Decryption Utility with Password Protection" is a software tool designed to provide users with a secure method to encrypt and decrypt files using the Advanced Encryption Standard (AES) encryption algorithm while ensuring additional security through password protection. The program offers an intuitive command-line interface for encrypting and decrypting files with ease, requiring users to provide a password for both encryption and decryption operations.

Features:

Password-Based Encryption: Users can encrypt individual files or entire directories by providing a password. The program generates a random salt and derives a cryptographic key from the user-provided password using the PBKDF2 key derivation function. Each file is encrypted using AES encryption in CBC mode with a unique initialization vector (IV) for added security.

Password Protection: Encrypted files are protected with a password, ensuring that only users with the correct password can decrypt and access the contents of the files. The program enforces password authentication during the decryption process, enhancing data security and confidentiality.

Decryption with Password: To decrypt encrypted files, users must provide the correct password that was used during encryption. The program validates the decryption password against the stored cryptographic key derived from the original password and salt, ensuring secure access to the decrypted files.
