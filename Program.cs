using Chilkat;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Chilkat;
using Renaissance.Common.Encryption;
using System;
using System.Data;
using System.Data.SqlClient;
using System.IO;

namespace JPMorganTestProtocols
{
    class Program
    { 
        private static string EncryptedFileName;
    private static string FileToEncrypt;
    private static string PublicKeyFileName;
    private static string PrivateKeyFileName;

    static void Main(string[] args)
    {
        SFtp sftp = new SFtp();
        if (!sftp.UnlockComponent("TEAMTW.CB40417_FXn0SJA6A19G"))
        {
            Console.WriteLine(sftp.LastErrorText);
        }
        else
        {
            sftp.ConnectTimeoutMs = 15000;
            sftp.IdleTimeoutMs = 15000;
            string hostname = "transmissions.jpmorgan.com";
            int port = 22;
            if (!sftp.Connect(hostname, port))
            {
                Console.WriteLine(sftp.LastErrorText);
            }
            else
            {
                Console.WriteLine("sending private key");
                SshKey privateKey = new SshKey();
                privateKey.VerboseLogging = true;
                string keyStr = privateKey.LoadText("x:\\_tlh\\SCF\\chaseprivatekey.ppk");
                privateKey.Password = "ifitistobeitisuptome";
                if (keyStr == null)
                    Console.WriteLine(privateKey.LastErrorText);
                else if (!privateKey.FromOpenSshPrivateKey(keyStr))
                    Console.WriteLine(privateKey.LastErrorText);
                else if (!sftp.AuthenticatePk("TWGINC", privateKey))
                    Console.WriteLine(sftp.LastErrorText);
                else if (!sftp.InitializeSftp())
                {
                    Console.WriteLine(sftp.LastErrorText);
                }
                else
                {
                    Console.WriteLine("Connected");
                   
                }
            }



            DateTime dateTime = new DateTime(2001, 1, 1);
            long ticks1 = DateTime.Now.Ticks - dateTime.Ticks;
            TimeSpan timeSpan = new TimeSpan(ticks1);

            string remoteFilePath2 = "/Inbound/Encrypted/TWGINC.TRANSPORT.IN.DAT";

            Program.EncryptedFileName = "C:\\_tlh\\SCF\\Enc_TWGINC.TRANSPORT.IN.DAT";
            Program.FileToEncrypt = "C:\\_tlh\\SCF\\test.txt";
            Program.PublicKeyFileName = "C:\\_tlh\\SCF\\TWGJPMCProdPgpKey.asc";
            Program.PrivateKeyFileName = "C:\\_tlh\\SCF\\TWGSignEncryptSK3.asc";
                      
            Program.EncryptAndSign();
            Console.WriteLine("file encrypted");


            if (!sftp.UploadFileByName(remoteFilePath2, Program.EncryptedFileName))
            {
                Console.WriteLine(sftp.LastErrorText);
            }
            else
            {
                Console.WriteLine("encrypted file sent up");
              
            }

            remoteFilePath2 = "/Inbound/Encrypted/TWGINC.TEST.IN.DAT";

            Program.EncryptedFileName = "C:\\_tlh\\SCF\\Enc_TWGINC.TEST.IN.DAT";
            Program.FileToEncrypt = "C:\\_tlh\\SCF\\test.txt";
            Program.PublicKeyFileName = "C:\\_tlh\\SCF\\TWGJPMCProdPgpKey.asc";
            Program.PrivateKeyFileName = "C:\\_tlh\\SCF\\TWGSignEncryptSK3.asc";

            Program.EncryptAndSign();
            Console.WriteLine("file encrypted");


            if (!sftp.UploadFileByName(remoteFilePath2, Program.EncryptedFileName))
            {
                Console.WriteLine(sftp.LastErrorText);
            }
            else
            {
                Console.WriteLine("encrypted file sent up");
                Console.ReadLine();
            }
        }
    }
            
    private static void EncryptAndSign()
    {
      using (System.IO.Stream outputStream = (System.IO.Stream) File.Create(Program.EncryptedFileName))
        new PgpEncrypt(new PgpEncryptionKeys(Program.PublicKeyFileName, Program.PrivateKeyFileName, "PASPHRASEGOESHERE")).EncryptAndSign(outputStream, new FileInfo(Program.FileToEncrypt));
    }
  }
}

 