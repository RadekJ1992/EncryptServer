using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
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
    /// Klasa "workera" wykonuj�cego zadania na serwerze
    /// </summary>
    public class WorkerRole : RoleEntryPoint
    {

        private AutoResetEvent connectionWaitHandle = new AutoResetEvent(false);

        StreamReader LoggerReader;
        StreamWriter LoggerWriter;
        /// <summary>
        /// Metoda uruchamiaj�ca workera i rozpoczynaj�ca nas�uch na odpowiednim IP i porcie
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
        /// Maksymalnie obs�ugiwanych mo�e by� 12 po��cze� na raz
        /// </summary>
        /// <returns>zmienna bitowa informuj�ca czy start si� uda�</returns>
        public override bool OnStart()
        {
            ServicePointManager.DefaultConnectionLimit = 12;
            return base.OnStart();
        }
        /// <summary>
        /// metoda obs�uguj�ca asynchroniczne przy��czanie klient�w
        /// </summary>
        /// <param name="result"></param>
        private void HandleAsyncConnection(IAsyncResult result)
        {
            try
            {
                // Akceptuj po��czenia
                TcpListener listener = (TcpListener)result.AsyncState;
                TcpClient client = listener.EndAcceptTcpClient(result);

                connectionWaitHandle.Set();

                Cryptography crypt = new Cryptography();
                // Po��czenie zaakceptowane 
                Guid clientId = Guid.NewGuid();
                Trace.WriteLine("Accepted connection with ID " + clientId.ToString(), "Information");

                // Stw�rz strumienie
                NetworkStream netStream = client.GetStream();
                StreamReader reader = new StreamReader(netStream);
                StreamWriter writer = new StreamWriter(netStream);
                writer.AutoFlush = true;
                //writer.WriteLine("Who are you?");
                String clientType = reader.ReadLine();
                // Gdy pod��czono loggera
                if (clientType == "logger")
                {
                    LoggerReader = reader;
                    LoggerWriter = writer;
                    LoggerWriter.WriteLine("Hello, Logger!\n\r Please wait for incoming connections");
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
                // Gdy pod��czono klienta
                else if (clientType == "client")
                {
                    // losuj klucz szyfru cezara
                    Random rnd = new Random();
                    int ckey = rnd.Next(1, 128);
                    String key = string.Empty;
                    String decryptedKey = string.Empty;
                    String plainText = string.Empty;
                   // writer.WriteLine("Key: ");
                    writer.WriteLine(ckey);
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
                                // odszyfruj klucz
                                decryptedKey = crypt.Cshift(key, -ckey);
                                // writer.WriteLine("Please Enter Plain Text:");
                                plainText = reader.ReadLine();
                                Console.WriteLine("Key received : {0}", decryptedKey);
                                Console.WriteLine("Plain Text received : {0}", plainText);
                                byte[] keyBytes = Encoding.ASCII.GetBytes(decryptedKey);
                                byte[] textBytes = Encoding.ASCII.GetBytes(plainText);

                                Byte[] output = crypt.runRC4(keyBytes, textBytes);

                                String outputString = crypt.ByteArrayToString(output);

                                Byte[] decrypt = crypt.runRC4(keyBytes, output);

                                String decryptString = Encoding.ASCII.GetString(decrypt);
                                // wy�lij wynik do loggera
                                String msg = "From Client : " + clientId.ToString() + "\n\rKey : " + decryptedKey + "\n\rPlain Text : " + plainText + "\n\rResult : " + outputString + "\n\rDecrypt result : " + decryptString + "\n\r";
                                if (LoggerWriter != null) LoggerWriter.Write(msg);
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
        /// Klasa obs�uguj�ca szyfrowanie
        /// </summary>
        public class Cryptography
        {
            /// <summary>
            /// Metoda szyfruj�ca z u�yciem szyfru Cezara
            /// </summary>
            /// <param name="str">Szyfrowany tekst</param>
            /// <param name="shift">Klucz</param>
            /// <returns>Wynik szyfrowania</returns>
            public string Cshift(string str, int shift)
            {
                string output = null;
                char[] text = null;
                text = str.ToCharArray();
                int temp;

                for (int i = 0; i < str.Length; i++)
                {
                    temp = (int)(text[i] + shift);
                    output += (char)temp;
                }
                return output;
            }
            /// <summary>
            /// Metoda szyfruj�ca z u�yciem szyfru RC4
            /// </summary>
            /// <param name="keyBytes">Bajty klucza</param>
            /// <param name="textBytes">Bajty tekstu wej�ciowego</param>
            /// <returns>Tablica bajt�w zaszyfrowanego tekstu</returns>
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
            /// Metoda zmieniaj�ca tablic� bajt�w na string b�d�cy zapisem tej tablicy w formacie hex
            /// </summary>
            /// <param name="ba">Podana tablica bajt�w</param>
            /// <returns>String b�d�cy wynikiem dzia�ania metody</returns>
            public string ByteArrayToString(byte[] ba)
            {
                StringBuilder hex = new StringBuilder(ba.Length * 2);
                foreach (byte b in ba)
                    hex.AppendFormat("{0:x2}", b);
                return hex.ToString();
            }
            /// <summary>
            /// Metoda zmieniaj�ca string b�d�cy zapisem bajt�w w formacie hex na tablic� bajt�w
            /// </summary>
            /// <param name="hex">String wej�ciowy</param>
            /// <returns>tablica bajtt�w b�d�ca wynikiem dzia�ania metody</returns>
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
