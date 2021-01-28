// Decompiled with JetBrains decompiler
// Type: Renaissance.Common.Encryption.PgpEncrypt
// Assembly: JPMorganSupplyChainFinanceUpload, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: 7B0E185F-6D5F-4728-BC85-0B315A3AE997
// Assembly location: \\twg-jks-e10sql1\d$\jpm\JPMorganSupplyChainFinanceUpload\bin\Debug\JPMorganSupplyChainFinanceUpload.exe

using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using System;
using System.Collections;
using System.IO;

namespace Renaissance.Common.Encryption
{
  public class PgpEncrypt
  {
    private const int BufferSize = 65536;
    private PgpEncryptionKeys m_encryptionKeys;

    public PgpEncrypt(PgpEncryptionKeys encryptionKeys)
    {
      if (encryptionKeys == null)
        throw new ArgumentNullException("encryptionKeys", "encryptionKeys is null.");
      this.m_encryptionKeys = encryptionKeys;
    }

    public void EncryptAndSign(Stream outputStream, FileInfo unencryptedFileInfo)
    {
      if (outputStream == null)
        throw new ArgumentNullException("outputStream", "outputStream is null.");
      if (unencryptedFileInfo == null)
        throw new ArgumentNullException("unencryptedFileInfo", "unencryptedFileInfo is null.");
      if (!File.Exists(unencryptedFileInfo.FullName))
        throw new ArgumentException("File to encrypt not found.");
      using (Stream encryptedOut = this.ChainEncryptedOut(outputStream))
      {
        using (Stream compressedOut = PgpEncrypt.ChainCompressedOut(encryptedOut))
        {
          PgpSignatureGenerator signatureGenerator = this.InitSignatureGenerator(compressedOut);
          using (Stream literalOut = PgpEncrypt.ChainLiteralOut(compressedOut, unencryptedFileInfo))
          {
            using (FileStream inputFile = unencryptedFileInfo.OpenRead())
              PgpEncrypt.WriteOutputAndSign(compressedOut, literalOut, inputFile, signatureGenerator);
          }
        }
      }
    }

    private static void WriteOutputAndSign(Stream compressedOut, Stream literalOut, FileStream inputFile, PgpSignatureGenerator signatureGenerator)
    {
      byte[] numArray = new byte[65536];
      int num;
      while ((num = inputFile.Read(numArray, 0, numArray.Length)) > 0)
      {
        literalOut.Write(numArray, 0, num);
        signatureGenerator.Update(numArray, 0, num);
      }
      signatureGenerator.Generate().Encode(compressedOut);
    }

    private Stream ChainEncryptedOut(Stream outputStream)
    {
      PgpEncryptedDataGenerator encryptedDataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.TripleDes, new SecureRandom());
      encryptedDataGenerator.AddMethod(this.m_encryptionKeys.PublicKey);
      return encryptedDataGenerator.Open(outputStream, new byte[65536]);
    }

    private static Stream ChainCompressedOut(Stream encryptedOut)
    {
      return new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip).Open(encryptedOut);
    }

    private static Stream ChainLiteralOut(Stream compressedOut, FileInfo file)
    {
      return new PgpLiteralDataGenerator().Open(compressedOut, 'b', file);
    }

    private PgpSignatureGenerator InitSignatureGenerator(Stream compressedOut)
    {
      PgpSignatureGenerator signatureGenerator = new PgpSignatureGenerator(this.m_encryptionKeys.SecretKey.PublicKey.Algorithm, HashAlgorithmTag.Sha1);
      signatureGenerator.InitSign(0, this.m_encryptionKeys.PrivateKey);
      IEnumerator enumerator = this.m_encryptionKeys.SecretKey.PublicKey.GetUserIds().GetEnumerator();
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
      signatureGenerator.GenerateOnePassVersion(false).Encode(compressedOut);
      return signatureGenerator;
    }
  }
}
