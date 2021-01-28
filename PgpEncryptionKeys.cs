// Decompiled with JetBrains decompiler
// Type: Renaissance.Common.Encryption.PgpEncryptionKeys
// Assembly: JPMorganSupplyChainFinanceUpload, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: 7B0E185F-6D5F-4728-BC85-0B315A3AE997
// Assembly location: \\twg-jks-e10sql1\d$\jpm\JPMorganSupplyChainFinanceUpload\bin\Debug\JPMorganSupplyChainFinanceUpload.exe

using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.IO;
using System.Linq;

namespace Renaissance.Common.Encryption
{
  public class PgpEncryptionKeys
  {
    public PgpPublicKey PublicKey { get; private set; }

    public PgpPrivateKey PrivateKey { get; private set; }

    public PgpSecretKey SecretKey { get; private set; }

    public PgpEncryptionKeys(string publicKeyPath, string privateKeyPath, string passPhrase)
    {
      if (!File.Exists(publicKeyPath))
        throw new ArgumentException("Public key file not found", "publicKeyPath");
      if (!File.Exists(privateKeyPath))
        throw new ArgumentException("Private key file not found", "privateKeyPath");
      if (string.IsNullOrEmpty(passPhrase))
        throw new ArgumentException("passPhrase is null or empty.", "passPhrase");
      this.PublicKey = this.ReadPublicKey(publicKeyPath);
      this.SecretKey = this.ReadSecretKey(privateKeyPath);
      this.PrivateKey = this.ReadPrivateKey(passPhrase);
    }

    private PgpSecretKey ReadSecretKey(string privateKeyPath)
    {
      using (Stream inputStream = (Stream) File.OpenRead(privateKeyPath))
      {
        using (Stream decoderStream = PgpUtilities.GetDecoderStream(inputStream))
        {
          PgpSecretKey firstSecretKey = this.GetFirstSecretKey(new PgpSecretKeyRingBundle(decoderStream));
          if (firstSecretKey != null)
            return firstSecretKey;
        }
      }
      throw new ArgumentException("Can't find signing key in key ring.");
    }

    private PgpSecretKey GetFirstSecretKey(PgpSecretKeyRingBundle secretKeyRingBundle)
    {
      foreach (PgpSecretKeyRing keyRing in secretKeyRingBundle.GetKeyRings())
      {
        PgpSecretKey pgpSecretKey = keyRing.GetSecretKeys().Cast<PgpSecretKey>().Where<PgpSecretKey>((Func<PgpSecretKey, bool>) (k => k.IsSigningKey)).FirstOrDefault<PgpSecretKey>();
        if (pgpSecretKey != null)
          return pgpSecretKey;
      }
      return (PgpSecretKey) null;
    }

    private PgpPublicKey ReadPublicKey(string publicKeyPath)
    {
      using (Stream inputStream = (Stream) File.OpenRead(publicKeyPath))
      {
        using (Stream decoderStream = PgpUtilities.GetDecoderStream(inputStream))
        {
          PgpPublicKey firstPublicKey = this.GetFirstPublicKey(new PgpPublicKeyRingBundle(decoderStream));
          if (firstPublicKey != null)
            return firstPublicKey;
        }
      }
      throw new ArgumentException("No encryption key found in public key ring.");
    }

    private PgpPublicKey GetFirstPublicKey(PgpPublicKeyRingBundle publicKeyRingBundle)
    {
      foreach (PgpPublicKeyRing keyRing in publicKeyRingBundle.GetKeyRings())
      {
        PgpPublicKey pgpPublicKey = keyRing.GetPublicKeys().Cast<PgpPublicKey>().Where<PgpPublicKey>((Func<PgpPublicKey, bool>) (k => k.IsEncryptionKey)).FirstOrDefault<PgpPublicKey>();
        if (pgpPublicKey != null)
          return pgpPublicKey;
      }
      return (PgpPublicKey) null;
    }

    private PgpPrivateKey ReadPrivateKey(string passPhrase)
    {
      PgpPrivateKey privateKey = this.SecretKey.ExtractPrivateKey(passPhrase.ToCharArray());
      if (privateKey != null)
        return privateKey;
      throw new ArgumentException("No private key found in secret key.");
    }
  }
}
