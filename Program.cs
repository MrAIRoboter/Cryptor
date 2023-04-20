using System;
using System.Collections.Generic;
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
                string destinationPath = args[2];
                List<string> missedPaths = new List<string>();
                List<string> errorFilePaths = new List<string>();

                switch (mode)
                {
                    case "/e":
                        Console.WriteLine("Шифрование...");
                        EncryptFiles(GetFiles(destinationPath, ref missedPaths), key, "enc", ref errorFilePaths);
                        Console.WriteLine("Шифрование завершено.");
                        break;

                    case "/d":
                        Console.WriteLine("Дешифрование...");
                        DecryptFiles(GetFiles(destinationPath, ref missedPaths), key, "enc", ref errorFilePaths);
                        Console.WriteLine("Дешифрование завершено.");
                        break;

                    default:
                        ShowConsoleHelp();
                        break;
                }

                if (missedPaths.Count > 0)
                {
                    Console.WriteLine("\nВозникли проблемы при чтении следующих путей:");

                    foreach (string path in missedPaths)
                        Console.WriteLine($" - {path}");
                }

                if (errorFilePaths.Count > 0)
                {
                    Console.WriteLine("\nВозникли проблемы со следующими файлами:");

                    foreach (string filePath in errorFilePaths)
                        Console.WriteLine($" - {filePath}");
                }
            }
            else
            {
                ShowConsoleHelp();
            }
        }

        static void ShowConsoleHelp()
        {
            Console.WriteLine("Использование:\n");
            Console.WriteLine("[/e | /d] \"пароль\" \"путь\"");
            Console.WriteLine("/e - Шифрование");
            Console.WriteLine("/d - Дешифрование");
        }

        static void EncryptFiles(List<string> filePaths, string key, string fileExtension, ref List<string> errorFilePaths)
        {
            for (int i = 0; i < filePaths.Count; i++)
            {
                string filePath = filePaths[i];

                try
                {
                    AES.Encrypt(filePath, fileExtension, key);
                    File.Delete(filePath);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Ошибка шифрования({ex.Message}) - {filePath}");
                    errorFilePaths.Add(filePath);
                }

                double progress = Math.Round(((double)(i + 1) * 100.0) / filePaths.Count, 2);
                Console.WriteLine($"{progress}% - {filePath}");
            }
        }

        static void DecryptFiles(List<string> filePaths, string key, string fileExtension, ref List<string> errorFilePaths)
        {
            for (int i = 0; i < filePaths.Count; i++)
            {
                string filePath = filePaths[i];
                string[] externs = filePath.Split('.');

                try
                {
                    if (externs[externs.Length - 1] == fileExtension)
                    {
                        string originalFilePath = externs[0];

                        for (int j = 1; j < externs.Length - 1; j++)
                            originalFilePath += $".{externs[j]}";

                        AES.Decrypt(filePath, originalFilePath, key);
                        File.Delete(filePath);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Ошибка дешифрования({ex.Message}) - {filePath}");
                    errorFilePaths.Add(filePath);
                }

                double progress = Math.Round(((double)(i + 1) * 100.0) / filePaths.Count, 2);
                Console.WriteLine($"{progress}% - {filePath}");
            }
        }

        static List<string> GetFiles(string fromDirectory, ref List<string> missedPaths)
        {
            List<string> filePaths = new List<string>();
            List<string> nestedDirectories = new List<string>();

            if (fromDirectory == "")
                fromDirectory = Directory.GetCurrentDirectory();
            fromDirectory = Path.GetFullPath(fromDirectory);

            filePaths.AddRange(Directory.GetFiles(fromDirectory));
            nestedDirectories.AddRange(Directory.GetDirectories(fromDirectory));

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
                    Console.WriteLine($"Пропущен({ex.Message}) - {nestedDirectories[0]}");
                    nestedDirectories.RemoveAt(0);
                    missedPaths.Add(nestedDirectories[0]);
                }
            }

            return filePaths;
        }
    }

    public static class AES
    {
        public static void Encrypt(string inputFilePath, string outputFileExtension, string keyString)
        {
            Aes aes = Aes.Create();
            SHA256 sha256 = SHA256Managed.Create();
            aes.Key = sha256.ComputeHash(Encoding.UTF8.GetBytes(keyString));
            aes.GenerateIV();
            aes.Mode = CipherMode.CBC;
            ICryptoTransform cipher = aes.CreateEncryptor(aes.Key, aes.IV);

            string outputDirectory = Path.GetDirectoryName(inputFilePath);
            string outputFilePath = $"{outputDirectory}/{Path.GetFileName(inputFilePath)}.{outputFileExtension}";

            using (FileStream inputStream = new FileStream(inputFilePath, FileMode.Open))
            {
                using (FileStream outputStream = new FileStream(outputFilePath, FileMode.Create))
                {
                    // Записываем IV в начало зашифрованного файла
                    outputStream.Write(aes.IV, 0, aes.IV.Length);

                    using (CryptoStream cryptoStream = new CryptoStream(outputStream, cipher, CryptoStreamMode.Write))
                    {
                        inputStream.CopyTo(cryptoStream);
                    }
                }
            }
        }

        public static void Decrypt(string inputFilePath, string outputFilePath, string keyString)
        {
            Aes aes = Aes.Create();
            SHA256 sha256 = SHA256Managed.Create();
            aes.Key = sha256.ComputeHash(Encoding.UTF8.GetBytes(keyString));
            aes.Mode = CipherMode.CBC;

            // Считываем IV из зашифрованного файла
            byte[] iv = new byte[aes.IV.Length];
            using (FileStream inputStream = new FileStream(inputFilePath, FileMode.Open))
            {
                inputStream.Read(iv, 0, iv.Length);
            }
            aes.IV = iv;

            ICryptoTransform cipher = aes.CreateDecryptor(aes.Key, aes.IV);

            using (FileStream inputStream = new FileStream(inputFilePath, FileMode.Open))
            {
                // Пропускаем первые 16 байт (IV)
                inputStream.Seek(aes.IV.Length, SeekOrigin.Begin);

                using (FileStream outputStream = new FileStream(outputFilePath, FileMode.Create))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(inputStream, cipher, CryptoStreamMode.Read))
                    {
                        cryptoStream.CopyTo(outputStream);
                    }
                }
            }
        }
    }
}