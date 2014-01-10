using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Threading;
using Microsoft.WindowsAzure;
using Microsoft.WindowsAzure.Diagnostics;
using Microsoft.WindowsAzure.ServiceRuntime;
using Microsoft.WindowsAzure.Storage;
using System.Net.Sockets;
using System.IO;
using System.Text;

namespace EncryptWorker
{
    /// <summary>
    /// Klasa "workera" wykonuj¹cego zadania na serwerze
    /// </summary>
    public class WorkerRole : RoleEntryPoint
    {
        private AutoResetEvent connectionWaitHandle = new AutoResetEvent(false);

        StreamReader LoggerReader;
        StreamWriter LoggerWriter;

        List<string> loggerList;
        /// <summary>
        /// Metoda uruchamiaj¹ca workera i rozpoczynaj¹ca nas³uch na odpowiednim IP i porcie
        /// </summary>
        public override void Run()
        {
            TcpListener listener = null;
            try
            {
                listener = new TcpListener(RoleEnvironment.CurrentRoleInstance.InstanceEndpoints["EncryptEndpoint"].IPEndpoint);
                listener.ExclusiveAddressUse = false;
                listener.Start();
            }
            catch (SocketException)
            {
                Trace.Write("Encrypting server could not start.", "Error");
                return;
            }
                while (true)
                {
                    try
                    {
                        IAsyncResult result = listener.BeginAcceptTcpClient(HandleAsyncConnection, listener);
                        connectionWaitHandle.WaitOne();
                    }
                    catch
                    {
                        continue;
                    }
                }
        }
        /// <summary>
        /// Metoda wykonywana przy starcie workera
        /// Maksymalnie obs³ugiwanych mo¿e byæ 12 po³¹czeñ na raz
        /// </summary>
        /// <returns>zmienna bitowa informuj¹ca czy start siê uda³</returns>
        public override bool OnStart()
        {
            loggerList = new List<string>();
            ServicePointManager.DefaultConnectionLimit = 12;
            return base.OnStart();
        }
        /// <summary>
        /// metoda obs³uguj¹ca asynchroniczne przy³¹czanie klientów
        /// </summary>
        /// <param name="result"></param>
        private void HandleAsyncConnection(IAsyncResult result)
        {
            try
            {
                // Akceptuj po³¹czenia
                TcpListener listener = (TcpListener)result.AsyncState;
                TcpClient client = listener.EndAcceptTcpClient(result);

                connectionWaitHandle.Set();

                Cryptography crypt = new Cryptography();
                AesManaged myAes = new AesManaged();
                String AESKey = "SuperTajnyKlucz1"; //128 bit
                myAes.Key = Encoding.UTF8.GetBytes(AESKey);
                String AESIV = "SuperTajnyWektor"; //128 bit
                myAes.IV = Encoding.UTF8.GetBytes(AESIV);
                // Po³¹czenie zaakceptowane 
                Guid clientId = Guid.NewGuid();
                Trace.WriteLine("Accepted connection with ID " + clientId.ToString(), "Information");

                // Stwórz strumienie
                NetworkStream netStream = client.GetStream();
                StreamReader reader = new StreamReader(netStream);
                StreamWriter writer = new StreamWriter(netStream);
                writer.AutoFlush = true;
                //writer.WriteLine("Who are you?");
                String clientType = reader.ReadLine();
                // Gdy pod³¹czono loggera
                if (clientType == "logger")
                {
                    LoggerReader = reader;
                    LoggerWriter = writer;
                    LoggerWriter.WriteLine("Hello, Logger!\n\rPlease wait for incoming connections");
                    if (loggerList.Count != 0)
                    {
                        LoggerWriter.WriteLine("There are some incoming logs");
                        foreach (string s in loggerList)
                        {
                            LoggerWriter.WriteLine(s);
                        }
                    }
                    while (true)
                    {
                        try
                        {
                            String msg = LoggerReader.ReadLine();
                            if (msg == "quit")
                            {
                                LoggerReader = null;
                                LoggerWriter = null;
                                client.Close();
                                break;
                            }
                        }
                        catch
                        {
                            client.Close();
                        }
                    }
                }
                // Gdy pod³¹czono klienta
                else if (clientType == "client")
                {
                    // losuj klucz szyfru cezara
                    Random rnd = new Random();
                    String key = string.Empty;
                    String decryptedKey = string.Empty;
                    String plainText = string.Empty;
                   // writer.WriteLine("Key: ");
                  //  writer.WriteLine(ckey);
                  //  writer.WriteLine("Welcome to RC4 Encrypting Server!");
                    while (true)
                    {
                        try
                        {
                          //  writer.WriteLine("If you want to encrypt text, enter \"run\", if you want to quit, enter \"quit\"");
                            String command = reader.ReadLine();
                            if (command == "run")
                            {
                                //  writer.WriteLine("Please Enter Key:");
                                key = reader.ReadLine();
                                //byte[] keyAESBytes = Encoding.UTF8.GetBytes(key);
                                byte[] keyAESBytes = crypt.StringToByteArray(key);
                                // odszyfruj klucz
                                    decryptedKey = crypt.DecryptStringFromBytes_Aes(keyAESBytes, myAes.Key, myAes.IV);
                                // writer.WriteLine("Please Enter Plain Text:");

                                string isHexStr = reader.ReadLine();
                                bool isHex = (isHexStr == "hex") ? true : false;

                                plainText = reader.ReadLine();
                                Console.WriteLine("Key received : {0}", decryptedKey);
                                Console.WriteLine("Plain Text received : {0}", plainText);

                                byte[] keyBytes = Encoding.ASCII.GetBytes(decryptedKey);
                                byte[] textBytes;
                                if (!isHex) textBytes = Encoding.ASCII.GetBytes(plainText);
                                else textBytes = crypt.StringToByteArray(plainText);

                                Byte[] output = crypt.runRC4(keyBytes, textBytes);
                                // wynik szyfrowania w postaci heksadecymalnej
                                String outputString = crypt.ByteArrayToString(output);
                                // wynik szyfrowania w postaci stringu utf8
                                String outputStringUTF8 = Encoding.UTF8.GetString(output);

                                Byte[] decrypt = crypt.runRC4(keyBytes, output);

                                String decryptString = Encoding.ASCII.GetString(decrypt);
                                String decryptStringHex = crypt.ByteArrayToString(decrypt);
                                // wyœlij wynik do loggera
                                String msg;
                                if (!isHex) msg = "From Client : " + clientId.ToString() + "\n\rKey : " + decryptedKey + "\n\rPlain Text : " + plainText + "\n\rResult as hex string : \n\r" 
                                    + outputString + "\n\rDecrypt result : " + decryptString + "\n\r";
                                else msg = "From Client : " + clientId.ToString() + "\n\rKey : " + decryptedKey + "\n\rHex string : " + plainText + "\n\rResult as utf8 string : \n\r" 
                                    + outputStringUTF8 + "\n\rDecrypt hex result : " + decryptStringHex + "\n\r";
                                if (LoggerWriter != null) LoggerWriter.Write(msg);
                                else loggerList.Add(msg);
                            }
                            if (command == "quit")
                            {
                                client.Close();
                                break;
                            }
                        }
                        catch
                        {
                            Console.WriteLine("Error while connecting to client");
                            client.Close();
                        }
                    }
                }
                else
                {
                    client.Close();
                }
            }
            catch
            {
                Console.WriteLine("Something went wrong");
            }

        }
        /// <summary>
        /// Klasa obs³uguj¹ca szyfrowanie
        /// </summary>
        public class Cryptography {
            /// <summary>
            /// Metoda deszyfruj¹ca przes³any z wykorzystaniem AES klucz
            /// </summary>
            /// <param name="cipherText">szyfrogram w postaci tablicy bajtów</param>
            /// <param name="Key">podany klucz</param>
            /// <param name="IV">wektor pocz¹tkowy</param>
            /// <returns>odszyfrowany string</returns>
        public string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV) {
            // SprawdŸ argumenty 
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("Key");

            string plaintext = null;

            // Tworzenie obiektu AESManaged z danym kluczem i wektorem pocz¹tkowym
            using (AesManaged aesAlg = new AesManaged()) {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
       }
         /// <summary>
            /// Metoda szyfruj¹ca z u¿yciem szyfru RC4
            /// </summary>
            /// <param name="keyBytes">Bajty klucza</param>
            /// <param name="textBytes">Bajty tekstu wejœciowego</param>
            /// <returns>Tablica bajtów zaszyfrowanego tekstu</returns>
            public Byte[] runRC4(byte[] keyBytes, byte[] textBytes)
            {
                //inicjalizacja klucza
                int[] S = new int[256];
                int i;
                int j;
                for (i = 0; i < 256; i++)
                {
                    S[i] = i;
                }
                j = 0;
                int keyBytesLength = keyBytes.GetLength(0);
                for (i = 0; i < 256; i++)
                {
                    j = (j + S[i] + keyBytes[i % keyBytesLength]) % 256;
                    int temp = S[i];
                    S[i] = S[j];
                    S[j] = temp;
                }

                //pseudolosowa generacja
                List<Byte> result = new List<Byte>();
                i = 0;
                j = 0;
                int textBytesLength = textBytes.GetLength(0);

                Byte[] output = new Byte[textBytes.GetLength(0)];

                for (long offset = 0; offset < textBytesLength; offset++)
                {
                    i = (i + 1) % 256;
                    j = (j + S[i]) % 256;
                    byte temp = (byte)S[i];
                    S[i] = S[j];
                    S[j] = temp;
                    byte a = textBytes[offset];
                    byte b = (byte)S[(S[i] + S[j]) % 256];
                    output[offset] = (byte)((int)a ^ (int)b);
                }
                return output;
            }
            /// <summary>
            /// Metoda zmieniaj¹ca tablicê bajtów na string bêd¹cy zapisem tej tablicy w formacie hex
            /// </summary>
            /// <param name="ba">Podana tablica bajtów</param>
            /// <returns>String bêd¹cy wynikiem dzia³ania metody</returns>
            public string ByteArrayToString(byte[] ba)
            {
                StringBuilder hex = new StringBuilder(ba.Length * 2);
                foreach (byte b in ba)
                    hex.AppendFormat("{0:x2}", b);
                return hex.ToString();
            }
            /// <summary>
            /// Metoda zmieniaj¹ca string bêd¹cy zapisem bajtów w formacie hex na tablicê bajtów
            /// </summary>
            /// <param name="hex">String wejœciowy</param>
            /// <returns>tablica bajttów bêd¹ca wynikiem dzia³ania metody</returns>
            public byte[] StringToByteArray(string hex)
            {
                return Enumerable.Range(0, hex.Length)
                                 .Where(x => x % 2 == 0)
                                 .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                                 .ToArray();
            }
        }
    }
}
