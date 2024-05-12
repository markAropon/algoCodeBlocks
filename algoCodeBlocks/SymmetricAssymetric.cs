using System;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        while (true)
        {
            Console.WriteLine("\nChoose encryption method:");
            Console.WriteLine("1. Symmetric Encryption (AES)");
            Console.WriteLine("2. Asymmetric Encryption (RSA)");
            Console.WriteLine("3. Exit");
            Console.Write("Enter your choice (1, 2, or 3): ");

            int choice;
            while (!int.TryParse(Console.ReadLine(), out choice) || (choice != 1 && choice != 2 && choice != 3))
            {
                Console.WriteLine("\nInvalid choice. Please enter 1 for Symmetric Encryption, 2 for Asymmetric Encryption, or 3 to exit:");
            }

            if (choice == 1)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                SymmetricEncryption();
            }
            else if (choice == 2)
            {
                Console.ForegroundColor = ConsoleColor.Blue;
                AsymmetricEncryption();
            }
            else if (choice == 3)
            {
                break;
            }
        }
    }

    static void SymmetricEncryption()
    {
        Console.WriteLine("\nEnter the text to encrypt (type 'exit' to choose another method or quit):");
        string plainText = Console.ReadLine();

        if (plainText.ToLower() == "exit")
            return;

        // Generate a random salt
        byte[] salt = new byte[8];
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(salt);
        }

        byte[] encryptedBytes;

        string key = "this_is_a_secret_key";
        using (var deriveBytes = new Rfc2898DeriveBytes(key, salt, 10000))
        {
            byte[] aesKey = deriveBytes.GetBytes(32);
            byte[] aesIV = deriveBytes.GetBytes(16);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = aesKey;
                aesAlg.IV = aesIV;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (var msEncrypt = new System.IO.MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new System.IO.StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encryptedBytes = msEncrypt.ToArray();
                    }
                }
            }
        }

        Console.WriteLine($"\nEncrypted text: \n{Convert.ToBase64String(encryptedBytes)}");
        Console.ResetColor();

        // Decrypt the text
        SymmetricDecryption(encryptedBytes, key);
    }

    static void AsymmetricEncryption()
    {
        Console.WriteLine("\nEnter the text to encrypt (type 'exit' to choose another method or quit):");
        string plainText = Console.ReadLine();

        if (plainText.ToLower() == "exit")
            return;

        using (var rsa = new RSACryptoServiceProvider(2048))
        {
            string publicKey = rsa.ToXmlString(false); // false to get public key
            string privateKey = rsa.ToXmlString(true); // true to get private key

            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] encryptedBytes = rsa.Encrypt(plainBytes, true);

            Console.WriteLine($"\nEncrypted text: \n{Convert.ToBase64String(encryptedBytes)}");
            Console.ResetColor();

            // Decrypt the text
            AsymmetricDecryption(encryptedBytes, privateKey);
        }
    }

    static void SymmetricDecryption(byte[] encryptedBytes, string key)
    {
        using (var deriveBytes = new Rfc2898DeriveBytes(key, new byte[8], 10000))
        {
            byte[] aesKey = deriveBytes.GetBytes(32);
            byte[] aesIV = deriveBytes.GetBytes(16);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = aesKey;
                aesAlg.IV = aesIV;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (var msDecrypt = new System.IO.MemoryStream(encryptedBytes))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new System.IO.StreamReader(csDecrypt))
                        {
                            string decryptedText = srDecrypt.ReadToEnd();
                            Console.WriteLine($"\nDecrypted text: {decryptedText}");
                        }
                    }
                }
            }
        }
    }

    static void AsymmetricDecryption(byte[] encryptedBytes, string privateKey)
    {
        using (var rsa = new RSACryptoServiceProvider(2048))
        {
            rsa.FromXmlString(privateKey);

            byte[] decryptedBytes = rsa.Decrypt(encryptedBytes, true);
            string decryptedText = Encoding.UTF8.GetString(decryptedBytes);

            Console.WriteLine($"\nDecrypted text: {decryptedText}");
        }
    }
}
