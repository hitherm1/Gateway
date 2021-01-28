// Decompiled with JetBrains decompiler
// Type: JPMorganSupplyChainFinanceUpload.PGPEncryptSign
// Assembly: JPMorganSupplyChainFinanceUpload, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: 7B0E185F-6D5F-4728-BC85-0B315A3AE997
// Assembly location: \\twg-jks-e10sql1\d$\jpm\JPMorganSupplyChainFinanceUpload\bin\Debug\JPMorganSupplyChainFinanceUpload.exe

using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using System;
using System.Collections;
using System.IO;

namespace JPMorganSupplyChainFinanceUpload
{
  internal class PGPEncryptSign
  {
    public void SignAndEncryptFile(string actualFileName, string embeddedFileName, Stream keyIn, long keyId, Stream outputStream, char[] password, bool armor, bool withIntegrityCheck, PgpPublicKey encKey)
    {
      if (armor)
        outputStream = (Stream) new ArmoredOutputStream(outputStream);
      PgpEncryptedDataGenerator encryptedDataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());
      encryptedDataGenerator.AddMethod(encKey);
      Stream outStr = encryptedDataGenerator.Open(outputStream, new byte[65536]);
      PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
      Stream stream1 = compressedDataGenerator.Open(outStr);
      PgpSecretKey secretKey = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(keyIn)).GetSecretKey(keyId);
      if (secretKey == null)
        throw new ArgumentException(keyId.ToString("X") + " could not be found in specified key ring bundle.", "keyId");
      PgpPrivateKey privateKey = secretKey.ExtractPrivateKey(password);
      PgpSignatureGenerator signatureGenerator = new PgpSignatureGenerator(secretKey.PublicKey.Algorithm, HashAlgorithmTag.Sha1);
      signatureGenerator.InitSign(0, privateKey);
      IEnumerator enumerator = secretKey.PublicKey.GetUserIds().GetEnumerator();
      try
      {
        if (enumerator.MoveNext())
        {
          string current = (string) enumerator.Current;
          PgpSignatureSubpacketGenerator subpacketGenerator = new PgpSignatureSubpacketGenerator();
          subpacketGenerator.SetSignerUserId(false, current);
          signatureGenerator.SetHashedSubpackets(subpacketGenerator.Generate());
        }
      }
      finally
      {
        IDisposable disposable = enumerator as IDisposable;
        if (disposable != null)
          disposable.Dispose();
      }
      signatureGenerator.GenerateOnePassVersion(false).Encode(stream1);
      PgpLiteralDataGenerator literalDataGenerator = new PgpLiteralDataGenerator();
      FileInfo fileInfo1 = new FileInfo(embeddedFileName);
      FileInfo fileInfo2 = new FileInfo(actualFileName);
      Stream stream2 = literalDataGenerator.Open(stream1, 'b', fileInfo1.Name, fileInfo2.LastWriteTime, new byte[65536]);
      FileStream fileStream = fileInfo2.OpenRead();
      byte[] numArray = new byte[65536];
      int num;
      while ((num = fileStream.Read(numArray, 0, numArray.Length)) > 0)
      {
        stream2.Write(numArray, 0, num);
        signatureGenerator.Update(numArray, 0, num);
      }
      stream2.Close();
      literalDataGenerator.Close();
      signatureGenerator.Generate().Encode(stream1);
      stream1.Close();
      compressedDataGenerator.Close();
      outStr.Close();
      encryptedDataGenerator.Close();
      fileStream.Close();
      if (!armor)
        return;
      outputStream.Close();
    }
  }
}
