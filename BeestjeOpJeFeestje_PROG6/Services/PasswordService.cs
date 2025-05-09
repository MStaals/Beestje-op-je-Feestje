using System.Security.Cryptography;
using System.Text;

namespace BeestjeOpJeFeestje_PROG6.Services;

public static class PasswordService
{
    // This is the secret key used for encryption and decryption.
    // The key must be exactly 16, 24, or 32 characters long for AES encryption.
    private static readonly string EncryptionKey = "YourSecretKey123456"; 

    /// <summary>
    /// Ensures the key has the correct length for AES-256 encryption (32 bytes).
    /// </summary>
    /// <returns>A byte array of 32 bytes in length</returns>
    private static byte[] GetValidKey()
    {
        byte[] keyBytes = Encoding.UTF8.GetBytes(EncryptionKey); // Convert the key to bytes
        Array.Resize(ref keyBytes, 32); // Ensures the key is 32 bytes long (for AES-256)
        return keyBytes;
    }

    /// <summary>
    /// Encrypts a password using AES-256 and returns it as a Base64-encoded string.
    /// </summary>
    /// <param name="password">The password to be encrypted</param>
    /// <returns>Encrypted Base64 string</returns>
    public static string EncryptPassword(string password)
    {
        byte[] keyBytes = GetValidKey(); // Get a valid encryption key
        byte[] iv = new byte[16]; // Initialization vector (IV) of 16 bytes, default filled with zeros

        using (Aes aes = Aes.Create()) // Create a new AES object
        {
            aes.Key = keyBytes; // Set the encryption key
            aes.IV = iv; // Set the initialization vector
            aes.Padding = PaddingMode.PKCS7; // Prevents "input data is not a complete block" error

            using (MemoryStream ms = new MemoryStream()) // Create a memory stream to store the data
            {
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    using (StreamWriter writer = new StreamWriter(cs))
                    {
                        writer.Write(password); // Write the password to the encrypted stream
                    }
                }
                return Convert.ToBase64String(ms.ToArray()); // Convert the encrypted bytes to a Base64 string
            }
        }
    }

    /// <summary>
    /// Decrypts a previously encrypted password.
    /// </summary>
    /// <param name="encryptedPassword">The encrypted Base64 string</param>
    /// <returns>The original password</returns>
    public static string DecryptPassword(string encryptedPassword)
    {
        byte[] keyBytes = GetValidKey(); // Get a valid decryption key
        byte[] iv = new byte[16]; // Same IV as used in encryption
        byte[] buffer = Convert.FromBase64String(encryptedPassword); // Convert Base64 string back to bytes

        using (Aes aes = Aes.Create()) // Create a new AES object
        {
            aes.Key = keyBytes; // Set the decryption key
            aes.IV = iv; // Set the initialization vector
            aes.Padding = PaddingMode.PKCS7; // Prevents errors when decrypting

            using (MemoryStream ms = new MemoryStream(buffer)) // Load the encrypted data into a memory stream
            {
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    using (StreamReader reader = new StreamReader(cs))
                    {
                        return reader.ReadToEnd(); // Read and return the decrypted text
                    }
                }
            }
        }
    }
}
