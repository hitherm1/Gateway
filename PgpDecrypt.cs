// Decompiled with JetBrains decompiler
// Type: JPMorganSupplyChainFinanceUpload.PgpDecrypt
// Assembly: JPMorganSupplyChainFinanceUpload, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: 7B0E185F-6D5F-4728-BC85-0B315A3AE997
// Assembly location: \\twg-jks-e10sql1\d$\jpm\JPMorganSupplyChainFinanceUpload\bin\Debug\JPMorganSupplyChainFinanceUpload.exe

using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Utilities.IO;
using Renaissance.Common.Encryption;
using System;
using System.IO;
using System.Linq;

namespace JPMorganSupplyChainFinanceUpload
{
  internal class PgpDecrypt
  {
    public string _encryptedFilePath;
    public string _privKeyPath;
    public char[] _password;
    public string _outputPath;
    public PgpEncryptionKeys pgpKeys;

    public PgpDecrypt(string encryptedFilePath, string privKeyPath, string password, string outputPath, string pubKeyPath)
    {
      this._encryptedFilePath = encryptedFilePath;
      this._outputPath = outputPath;
      this._password = password.ToCharArray();
      this._privKeyPath = privKeyPath;
      this.pgpKeys = new PgpEncryptionKeys(pubKeyPath, privKeyPath, password);
    }

    public void Decrypt(Stream input, string outputpath)
    {
      input = PgpUtilities.GetDecoderStream(input);
      try
      {
        PgpObjectFactory pgpObjectFactory1 = new PgpObjectFactory(input);
        PgpObject pgpObject1 = pgpObjectFactory1.NextPgpObject();
        PgpEncryptedDataList encryptedDataList = !(pgpObject1 is PgpEncryptedDataList) ? (PgpEncryptedDataList) pgpObjectFactory1.NextPgpObject() : (PgpEncryptedDataList) pgpObject1;
        PgpPrivateKey privKey = this.pgpKeys.PrivateKey;
        PgpPublicKeyEncryptedData keyEncryptedData = encryptedDataList.GetEncryptedDataObjects().Cast<PgpPublicKeyEncryptedData>().FirstOrDefault<PgpPublicKeyEncryptedData>((Func<PgpPublicKeyEncryptedData, bool>) (pked => privKey != null));
        if (keyEncryptedData == null)
          return;
        PgpObject pgpObject2 = new PgpObjectFactory(keyEncryptedData.GetDataStream(privKey)).NextPgpObject();
        if (pgpObject2 is PgpCompressedData)
        {
          PgpObjectFactory pgpObjectFactory2 = new PgpObjectFactory(((PgpCompressedData) pgpObject2).GetDataStream());
          PgpObject pgpObject3 = pgpObjectFactory2.NextPgpObject();
          if (pgpObject3 is PgpOnePassSignatureList)
          {
            PgpLiteralData pgpLiteralData = (PgpLiteralData) pgpObjectFactory2.NextPgpObject();
            Stream outStr = (Stream) File.Create(outputpath + "\\" + pgpLiteralData.FileName);
            Streams.PipeAll(pgpLiteralData.GetInputStream(), outStr);
          }
          else
          {
            PgpLiteralData pgpLiteralData = (PgpLiteralData) pgpObject3;
            Stream outStr = (Stream) File.Create(outputpath + "\\" + pgpLiteralData.FileName);
            Streams.PipeAll(pgpLiteralData.GetInputStream(), outStr);
          }
        }
      }
      catch (Exception ex)
      {
        throw new Exception(ex.Message);
      }
    }
  }
}
