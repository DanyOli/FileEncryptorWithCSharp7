/*
 * Program: FileEncryptor
 * Description: File encryption and decryption using C# 7.0 console application 
 * Author: DanyOli
 * Date: 2024
 * Version: 1.0
 */

using System;
using System.IO;
using System.Security.Cryptography;

UserChoice();
void UserChoice()
{
    Console.WriteLine("Choose one option below:-  \n 1. Encryption \n 2. Decryption \n");
    string choice = Console.ReadLine() ?? "";

    if (choice == "1")
        EncryptFolder();
    else if (choice == "2")
        DecryptFolder();
    else
        Console.WriteLine("------------------------");

    Console.WriteLine($"Invalid input 😊: Please choose one option below:- \n ");
    UserChoice();
}

void EncryptFolder()
{
    Console.WriteLine("Enter the path of the folder you want to encrypt:");
    string folderPath = Console.ReadLine() ?? "";
    if (string.IsNullOrEmpty(folderPath))
        Console.WriteLine("Invalid input: Source path cannot be empty.");

    Console.WriteLine("Enter a password to encrypt the folder:");
    string password = Console.ReadLine() ?? "";

    // Generate a random salt
    byte[] salt = new byte[16];
    using (RNGCryptoServiceProvider rng = new())
        rng.GetBytes(salt);

    // Create a new folder for the encrypted files
    string newFolderPath = Path.Combine(Path.GetDirectoryName(folderPath), Path.GetFileName(folderPath) + "_encrypted");
    int folderNumber = 1;
    while (Directory.Exists(newFolderPath))
        newFolderPath = Path.Combine(Path.GetDirectoryName(folderPath), $"{Path.GetFileName(folderPath)}_encrypted({folderNumber++})");

    Directory.CreateDirectory(newFolderPath);

    Rfc2898DeriveBytes keyGenerator = new(password, salt, 1000);
    byte[] key = keyGenerator.GetBytes(32);

    // Save the salt to a file in the new folder
    string saltFilePath = Path.Combine(newFolderPath, "salt.bin");
    File.WriteAllBytes(saltFilePath, salt);

    // Iterate through all files in the folder
    int count = 0;
    foreach (string filePath in Directory.GetFiles(folderPath))
    {
        // Encrypt each file and save it to the new folder
        using FileStream fsIn = new(filePath, FileMode.Open, FileAccess.Read);
        using Aes aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV();

        string encryptedFilePath = Path.Combine(newFolderPath, Path.GetFileNameWithoutExtension(filePath) + ".enc");
        // Get the original file extension
        string extension = Path.GetExtension(filePath);

        // Append the extension to the encrypted file name
        encryptedFilePath += extension;

        using FileStream fsOut = new(encryptedFilePath, FileMode.Create, FileAccess.Write);
        using CryptoStream cryptoStream = new(fsOut, aes.CreateEncryptor(), CryptoStreamMode.Write);
        // Write the IV to the beginning of the file
        fsOut.Write(aes.IV, 0, aes.IV.Length);

        // Copy the plaintext to the CryptoStream
        fsIn.CopyTo(cryptoStream);
        count++;
    }
    Console.WriteLine($"Encryption complete. Encrypted {count} files saved to {newFolderPath}");
    Console.WriteLine($"_____________________");

    UserChoice();
}

void DecryptFolder()
{
    Console.WriteLine("Enter the source path of the folder you want to decrypt:");
    string folderPath = Console.ReadLine() ?? "";
    if (string.IsNullOrEmpty(folderPath))
        Console.WriteLine("Invalid input: Source path cannot be null.");

    Console.WriteLine("Enter the password to decrypt the folder:");
    string decryptionPassword = Console.ReadLine() ?? "";

    // Read the salt from the salt file
    string saltFilePath = Path.Combine(folderPath, "salt.bin");
    byte[] saltFromFile = File.ReadAllBytes(saltFilePath);

    // Generate the key from the password and salt
    Rfc2898DeriveBytes keyGenerator = new(decryptionPassword, saltFromFile, 1000);
    byte[] key = keyGenerator.GetBytes(32);

    // Create a new folder for the decrypted files
    string newFolderPath = Path.Combine(Path.GetDirectoryName(folderPath) ?? "", Path.GetFileName(folderPath).Split('_')[0] + "_decrypted");
    int folderNumber = 1;
    while (Directory.Exists(newFolderPath))
        newFolderPath = Path.Combine(Path.GetDirectoryName(folderPath) ?? "", $"{Path.GetFileName(folderPath)}_encrypted({folderNumber++})");

    Directory.CreateDirectory(newFolderPath);

    // Iterate through all files in the folder
    int count = 0; int isError = 0;
    foreach (string filePath in Directory.GetFiles(folderPath))
    {
        // Skip the salt file
        if (filePath.EndsWith("salt.bin"))
            continue;

        // Decrypt each file and save it to the new folder
        using FileStream fsIn = new(filePath, FileMode.Open, FileAccess.Read);
        using Aes aes = Aes.Create();
        // Read the IV from the beginning of the file
        byte[] ivFile = new byte[16];
        int bytesRead = fsIn.Read(ivFile, 0, ivFile.Length);
        if (bytesRead != ivFile.Length)
        {
            Console.WriteLine("Error: Unable to read the IV from the encrypted file");
            continue;
        }

        aes.Key = key;
        aes.IV = ivFile;

        // Get the original file extension
        string originalExtension = Path.GetExtension(filePath).Replace(".enc", "");

        // Decrypt the file and save it to the original folder with the original file extension
        string decryptedFilePath = Path.Combine(newFolderPath, Path.GetFileNameWithoutExtension(filePath) + originalExtension);
        try
        {
            using FileStream fsOut = new(decryptedFilePath, FileMode.Create, FileAccess.Write);
            using CryptoStream cryptoStream = new(fsOut, aes.CreateDecryptor(), CryptoStreamMode.Write);
            // Copy the decrypted data to the output file
            fsIn.CopyTo(cryptoStream);
            count++;
        }
        catch (CryptographicException ex)
        {
            if (ex.Message.Contains("Padding is invalid and cannot be removed"))
            {
                Console.WriteLine("Error: Incorrect decryption password");
                isError = 1;
                break;
            }
        }
    }
    if (isError == 0)
        Console.WriteLine($"Decryption complete. Decrypted {count} files saved to {newFolderPath}");

    Console.WriteLine($"_____________________");
    UserChoice();
}



