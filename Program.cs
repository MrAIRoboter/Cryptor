using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Cryptor
{
    public class Program
    {
        private static object _consoleLock;

        public static void Main(string[] args)
        {
            _consoleLock = new object();

            if (args.Length == 0)
            {
                args = new string[4];
                bool isModeEntered = false;
                bool isKeyEntered = false;
                bool isDestinationPathEntered = false;
                bool isStorageTypeEntered = false;

                while (isModeEntered == false)
                {
                    Console.Write("Введите режим /e - шифрование /d - дешифрование [/e | /d]: ");
                    args[0] = Console.ReadLine();

                    if (args[0] == "/e" || args[0] == "/d")
                        isModeEntered = true;
                }

                while (isKeyEntered == false)
                {
                    Console.Write("Введите пароль: ");
                    args[1] = Console.ReadLine();

                    if (args[1].Length > 0)
                        isKeyEntered = true;
                }

                while (isDestinationPathEntered == false)
                {
                    Console.Write("Введите путь: ");
                    args[2] = Console.ReadLine();

                    if (args[2].Length > 0)
                        isDestinationPathEntered = true;
                }

                while (isStorageTypeEntered == false)
                {
                    Console.Write($"Введите тип целевого накопителя данных [hdd | ssd] (по умолчанию hdd): ");
                    args[3] = Console.ReadLine();

                    if (args[3] == "")
                        args[3] = "hdd";

                    if (args[3] == "hdd" || args[3] == "ssd")
                        isStorageTypeEntered = true;
                }
            }

            if (args.Length >= 3)
            {
                string mode = args[0];
                string key = args[1];
                string destinationPath = args[2];
                string storageType = "hdd";
                List<string> missedPaths = new List<string>();
                List<string> errorFilePaths = new List<string>();
                Stopwatch stopwatch = Stopwatch.StartNew();
                bool isSynchronous = true;

                if (args.Length > 3)
                    if (args[3] == "hdd" || args[3] == "ssd")
                        storageType = args[3];

                if (args[3] == "ssd")
                    isSynchronous = false;

                switch (mode)
                {
                    case "/e":
                        Console.WriteLine("Шифрование...");
                        EncryptFiles(GetFiles(destinationPath, ref missedPaths), key, ref errorFilePaths, isSynchronous);
                        Console.WriteLine("\nШифрование завершено.");
                        break;

                    case "/d":
                        Console.WriteLine("Дешифрование...");
                        DecryptFiles(GetFiles(destinationPath, ref missedPaths), key, ref errorFilePaths, isSynchronous);
                        Console.WriteLine("\nДешифрование завершено.");
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

                stopwatch.Stop();
                Console.WriteLine($"Затрачено времени: {stopwatch.Elapsed.ToString("h'ч. 'm'м. 's'с.'")}");
            }
            else
            {
                ShowConsoleHelp();
            }

            //Console.ReadKey();
        }

        private static void ShowConsoleHelp()
        {
            Console.WriteLine("Использование:\n");
            Console.WriteLine("[/e | /d] [пароль] [\"путь\"] [hdd | ssd]");
            Console.WriteLine("/e - Шифрование");
            Console.WriteLine("/d - Дешифрование");
            Console.WriteLine("hdd - жёсткий диск, ssd - твердотельный SSD накопитель (по-умолчанию hdd)");
        }

        public static void EncryptFiles(List<string> filePaths, string key, ref List<string> errorFilePaths, bool isSynchronous = true)
        {
            ProcessFiles(TryEncryptFile, filePaths, key, ref errorFilePaths, isSynchronous);
        }

        public static void DecryptFiles(List<string> filePaths, string key, ref List<string> errorFilePaths, bool isSynchronous = true)
        {
            string fileExtension = "enc";
            filePaths = FilterFilesByExtension(filePaths, fileExtension);

            ProcessFiles(TryDecryptFile, filePaths, key, ref errorFilePaths, isSynchronous);
        }

        private static bool TryEncryptFile(string filePath, string key, int bufferSize = 64 << 20)
        {
            string fileExtension = "enc";
            bool isErrorFile = false;

            try
            {
                AES.Encrypt(filePath, fileExtension, key, bufferSize);
                File.Delete(filePath);
            }
            catch (Exception ex)
            {
                isErrorFile = true;

                Console.WriteLine($"\nОшибка шифрования({ex.Message}) - {filePath}");
            }

            return isErrorFile == false;
        }

        private static bool TryDecryptFile(string filePath, string key, int bufferSize)
        {
            string[] externs = filePath.Split('.');
            string originalFilePath = externs[0];
            bool isErrorFile = false;

            try
            {
                for (int j = 1; j < externs.Length - 1; j++)
                    originalFilePath += $".{externs[j]}";

                AES.Decrypt(filePath, originalFilePath, key, bufferSize);
                File.Delete(filePath);
            }
            catch (CryptographicException)
            {
                isErrorFile = true;

                Console.WriteLine($"\nНеверный пароль - {filePath}");
            }
            catch (Exception ex)
            {
                isErrorFile = true;

                Console.WriteLine($"\nОшибка дешифрования({ex.Message}) - {filePath}");
            }

            if (isErrorFile == true)
            {
                try
                {
                    File.Delete(originalFilePath);
                }
                catch { }
            }

            return isErrorFile == false;
        }

        private static void ShowProgress(string filePath, long completedCount, int filePathsCount)
        {
            double progress = Math.Round(((double)(completedCount) * 100.0) / filePathsCount, 2);
            Console.WriteLine($"{progress}% - {filePath}");
        }

        private static void ProcessFiles(Func<string, string,int, bool> tryCrypt, List<string> filePaths, string key, ref List<string> errorFilePaths, bool isSynchronous = true)
        {
            long completedCount = 0;
            List<string> tempErrorFilePaths = new List<string>();

            for (int i = 0; i < filePaths.Count; i++)
            {
                int index = i;
                string filePath = filePaths[index];
                bool isErrorFile = false;

                if (isSynchronous == true)
                {
                    ProcessFile(tryCrypt, out isErrorFile, filePath, key, ref completedCount, filePaths.Count, 512 << 20);
                }
                else
                {
                    ThreadPool.QueueUserWorkItem(state =>
                    {
                        ProcessFile(tryCrypt, out isErrorFile, filePath, key, ref completedCount, filePaths.Count, 64 << 20);

                        if (isErrorFile == true)
                            tempErrorFilePaths.Add(filePath);
                    });
                }

                if (isErrorFile == true)
                    tempErrorFilePaths.Add(filePath);
            }

            WaitForComlete(ref completedCount, filePaths.Count, 200);

            errorFilePaths.AddRange(tempErrorFilePaths);
        }

        private static void ProcessFile(Func<string, string, int, bool> tryCrypt, out bool isErrorFile, string filePath, string key, ref long completedCount, int filePathsCount, int bufferSize)
        {
            isErrorFile = tryCrypt(filePath, key, bufferSize) == false;

            Interlocked.Increment(ref completedCount);

            ShowProgress(filePath, completedCount, filePathsCount);
        }

        private static void WaitForComlete(ref long completedCount, int allCount, int delay)
        {
            for(int garbageCollectorDelay = 0; completedCount < allCount; garbageCollectorDelay += delay)
            {
                if(garbageCollectorDelay >= delay * 100)
                {
                    GC.Collect();
                    garbageCollectorDelay = 0;
                }

                Thread.Sleep(delay);
            }
        }

        private static List<string> FilterFilesByExtension(List<string> filePaths, string fileExtension)
        {
            List<string> result = new List<string>();

            foreach (string filePath in filePaths)
            {
                string[] externs = filePath.Split('.');

                if (externs.Length == 0)
                    continue;

                string currentExtension = externs[externs.Length - 1];

                if (currentExtension.ToLower().Equals(fileExtension.ToLower()) == true)
                    result.Add(filePath);
            }

            return result;
        }

        private static List<string> GetFiles(string fromDirectory, ref List<string> missedPaths)
        {
            if (string.IsNullOrEmpty(fromDirectory))
                fromDirectory = Directory.GetCurrentDirectory();

            fromDirectory = Path.GetFullPath(fromDirectory);

            return GetAllFiles(fromDirectory, missedPaths);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static List<string> GetAllFiles(string directory, List<string> missedPaths)
        {
            List<string> foundFiles = new List<string>();

            try
            {
                foundFiles.AddRange(Directory.GetFiles(directory));
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка при получении файлов {directory}: {ex.Message}");
                missedPaths.Add(directory);
            }

            foreach (string subdirectory in Directory.GetDirectories(directory))
            {
                try
                {
                    foundFiles.AddRange(GetAllFiles(subdirectory, missedPaths));
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Ошибка при получении списка подпапок {subdirectory}: {ex.Message}");
                    missedPaths.Add(subdirectory);
                }
            }

            return foundFiles;
        }

        private static void ConsoleWriteLine(string message)
        {
            lock (_consoleLock)
            {
                Console.WriteLine(message);
            }
        }
    }

    public static class AES
    {
        /// <param name="bufferSize">Размер буфера в байтах.</param>
        public static void Encrypt(string inputFilePath, string outputFileExtension, string keyString, int bufferSize = 64 << 20)
        {
            Aes aes = Aes.Create();
            SHA256 sha256 = SHA256Managed.Create();
            aes.Key = sha256.ComputeHash(Encoding.UTF8.GetBytes(keyString));
            aes.GenerateIV();
            aes.Mode = CipherMode.CBC;
            ICryptoTransform cipher = aes.CreateEncryptor(aes.Key, aes.IV);

            string outputDirectory = Path.GetDirectoryName(inputFilePath);
            string outputFilePath = $"{outputDirectory}/{Path.GetFileName(inputFilePath)}.{outputFileExtension}";
            bool isBigFile = false;

            using (FileStream inputStream = new FileStream(inputFilePath, FileMode.Open))
            {
                using (FileStream outputStream = new FileStream(outputFilePath, FileMode.Create))
                {
                    // Записываем IV в начало зашифрованного файла
                    outputStream.Write(aes.IV, 0, aes.IV.Length);

                    using (CryptoStream cryptoStream = new CryptoStream(outputStream, cipher, CryptoStreamMode.Write))
                    {
                        byte[] buffer;
                        isBigFile = inputStream.Length > bufferSize;

                        if (isBigFile == false)
                        {
                            buffer = new byte[inputStream.Length];

                            inputStream.Read(buffer, 0, buffer.Length);
                            cryptoStream.Write(buffer, 0, buffer.Length);
                        }
                        else
                        {
                            buffer = new byte[bufferSize];
                            int bytesReadCount;

                            while ((bytesReadCount = inputStream.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                cryptoStream.Write(buffer, 0, bytesReadCount);

                                if (bufferSize > (64 << 20))
                                    GC.Collect();
                            }
                        }
                    }
                }
            }

            if (isBigFile == true)
                GC.Collect();
        }

        /// <param name="bufferSize">Размер буфера в байтах.</param>
        public static void Decrypt(string inputFilePath, string outputFilePath, string keyString, int bufferSize = 64 << 20)
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
            // Пропускаем первые 16 байт (IV)
            long decryptedFileSize = new FileInfo(inputFilePath).Length - 16;
            bool isBigFile = decryptedFileSize > bufferSize;

            using (FileStream inputStream = new FileStream(inputFilePath, FileMode.Open))
            {
                // Пропускаем первые 16 байт (IV)
                inputStream.Seek(aes.IV.Length, SeekOrigin.Begin);

                using (FileStream outputStream = new FileStream(outputFilePath, FileMode.Create))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(inputStream, cipher, CryptoStreamMode.Read))
                    {
                        byte[] buffer;

                        if (isBigFile == false)
                        {
                            buffer = new byte[decryptedFileSize];

                            cryptoStream.Read(buffer, 0, buffer.Length);
                            outputStream.Write(buffer, 0, buffer.Length);
                        }
                        else
                        {
                            buffer = new byte[bufferSize];
                            int bytesReadCount;

                            while ((bytesReadCount = cryptoStream.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                outputStream.Write(buffer, 0, bytesReadCount);

                                if (bufferSize > (64 << 20))
                                    GC.Collect();
                            }
                        }
                    }
                }
            }

            if (isBigFile == true)
                GC.Collect();
        }
    }
}