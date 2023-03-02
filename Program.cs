using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cryptor
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 3)
            {
                string mode = args[0];
                string key = args[1];
                string destinationDirectory = args[2];

                Stopwatch stopwatch = Stopwatch.StartNew();

                switch (mode)
                {
                    case "/e":
                        Console.WriteLine("Encryption...");
                        EncryptFiles(GetFiles(destinationDirectory), key);
                        Console.WriteLine($"Elapsed time on encrypt- {stopwatch.ElapsedMilliseconds} ms.");
                        break;

                    case "/d":
                        Console.WriteLine("Decryption...");
                        Console.WriteLine($"Elapsed time on decrypt - {stopwatch.ElapsedMilliseconds} ms.");
                        DecryptFiles(GetFiles(destinationDirectory), key);
                        break;

                    default:
                        ShowConsoleHelp();
                        break;
                }
            }
            else
            {
                ShowConsoleHelp();
            }
        }

        static void ShowConsoleHelp()
        {
            Console.WriteLine("Using:\n");
            Console.WriteLine("[/e | /d] \"{password}\" \"{destination}\"");
            Console.WriteLine("/e - Encrypt");
            Console.WriteLine("/d - Decrypt");
        }

        static void EncryptFiles(List<string> filePaths, string key)
        {
            for (int i = 0; i < filePaths.Count; i++)
            {
                string filePath = filePaths[i];

                try
                {
                    byte[] file = File.ReadAllBytes(filePath);
                    File.WriteAllBytes($"{filePath}.enc", AES.Encrypt(file, key));
                    File.Delete(filePath);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Encryption error({ex.Message}) - {filePath}");
                }

                double progress = Math.Round(((double)(i + 1) * 100.0) / filePaths.Count, 2);
                Console.WriteLine($"{progress}% - {filePath}");
            }
        }

        static void DecryptFiles(List<string> filePaths, string key)
        {
            for (int i = 0; i < filePaths.Count; i++)
            {
                string filePath = filePaths[i];

                try
                {
                    byte[] file = File.ReadAllBytes(filePath);
                    string[] externs = filePath.Split('.');

                    if (externs[externs.Length - 1] == "enc")
                    {
                        string originalFilePath = externs[0];
                        for (int j = 1; j < externs.Length - 1; j++)
                            originalFilePath += $".{externs[j]}";

                        File.WriteAllBytes($"{originalFilePath}", AES.Decrypt(file, key));
                        File.Delete(filePath);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Decryption error({ex.Message}) - {filePath}");
                }

                double progress = Math.Round(((double)(i + 1) * 100.0) / filePaths.Count, 2);
                Console.WriteLine($"{progress}% - {filePath}");
            }
        }

        static List<string> GetFiles(string directory)
        {
            if (directory == "")
                directory = Directory.GetCurrentDirectory();
            directory = Path.GetFullPath(directory);

            List<string> filePaths = new List<string>();
            List<string> nestedDirectories = new List<string>();

            filePaths.AddRange(Directory.GetFiles(directory));
            nestedDirectories.AddRange(Directory.GetDirectories(directory));

            while (nestedDirectories.Count != 0)
            {
                try
                {
                    filePaths.AddRange(Directory.GetFiles(nestedDirectories[0]));
                    nestedDirectories.AddRange(Directory.GetDirectories(nestedDirectories[0]));
                    nestedDirectories.RemoveAt(0);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Missed({ex.Message}) - {nestedDirectories[0]}");
                    nestedDirectories.RemoveAt(0);
                }
            }

            return filePaths;
        }
    }

    public static class AES
    {
        public static byte[] Encrypt(byte[] data, string keyString)
        {
            byte[] cipherData;
            Aes aes = Aes.Create();
            SHA256 sha256 = SHA256Managed.Create();
            aes.Key = sha256.ComputeHash(Encoding.UTF8.GetBytes(keyString));
            aes.GenerateIV();
            aes.Mode = CipherMode.CBC;
            ICryptoTransform cipher = aes.CreateEncryptor(aes.Key, aes.IV);

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, cipher, CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                }

                cipherData = ms.ToArray();
            }

            byte[] combinedData = new byte[aes.IV.Length + cipherData.Length];
            Array.Copy(aes.IV, 0, combinedData, 0, aes.IV.Length);
            Array.Copy(cipherData, 0, combinedData, aes.IV.Length, cipherData.Length);
            return combinedData;
        }

        public static byte[] Decrypt(byte[] combinedData, string keyString)
        {
            try
            {
                Aes aes = Aes.Create();
                SHA256 sha256 = SHA256Managed.Create();
                aes.Key = sha256.ComputeHash(Encoding.UTF8.GetBytes(keyString));
                byte[] iv = new byte[aes.BlockSize / 8];
                byte[] cipherData = new byte[combinedData.Length - iv.Length];
                Array.Copy(combinedData, iv, iv.Length);
                Array.Copy(combinedData, iv.Length, cipherData, 0, cipherData.Length);
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                ICryptoTransform decipher = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream ms = new MemoryStream(cipherData))
                {
                    byte[] decryptedData = new byte[ms.Length];

                    using (CryptoStream cs = new CryptoStream(ms, decipher, CryptoStreamMode.Read))
                    {
                        cs.Read(decryptedData, 0, (int)ms.Length);
                    }

                    return decryptedData;
                }
            }
            catch
            {
                throw new Exception("Data can't be decrypted!");
            }
        }
    }
}
