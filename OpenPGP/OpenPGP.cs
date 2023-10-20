using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using OutSystems.NssOpenPGP;
using System.Text;

namespace OpenPGP
{
    public class OpenPGP : IOpenPGP
    {
        public byte[] File_Decrypt(byte[] File_Encrypted, byte[] Private_Key, string Password)
        {
            MemoryStream msEncryptedFile = new (File_Encrypted);
            string privateKeyString = Encoding.ASCII.GetString(Private_Key);

            Stream decryptedFile = PGPUtilities.PgpDecrypt(msEncryptedFile, privateKeyString, Password);

            byte[] File_Decrypted = PGPUtilities.ReadFully(decryptedFile);

            msEncryptedFile.Dispose();
            decryptedFile.Dispose();
            return File_Decrypted;
        }

        public byte[] File_Encrypt(byte[] File_PlainText, byte[] Public_Key, bool UseIntegrityPacket = false, string CipherAlgorithm = "Aes256", string CompressionAlgorithm = "Zip")
        {
            MemoryStream msDecryptedFile = new(File_PlainText);
            MemoryStream msPublicKey = new (Public_Key);
            PgpPublicKey pgpPublicKey = PGPUtilities.ImportPublicKey(msPublicKey);
            Stream encryptedFile = PGPUtilities.PgpEncrypt(msDecryptedFile, pgpPublicKey, UseIntegrityPacket, CipherAlgorithm, CompressionAlgorithm);
            byte[] File_Encrypted = PGPUtilities.ReadFully(encryptedFile);
            msDecryptedFile.Dispose();
            msPublicKey.Dispose();
            encryptedFile.Dispose();

            return File_Encrypted;
        }

        public void GenerateKeys(string Identity, string Password, out byte[] Private_Key, out byte[] PublicKey)
        {
            OpenPGPRing openPGPRing = OpenPGPKeyRingGenerator.generateKeyRing(Identity, Password);

            MemoryStream msPvtKey = new();
            ArmoredOutputStream armorOutPvt = new(msPvtKey);
            armorOutPvt.Write(openPGPRing.m_PrivateKeyRing.GetEncoded());
            armorOutPvt.Close();
            Private_Key = PGPUtilities.ReadFully(msPvtKey);

            MemoryStream msPubKey = new();
            ArmoredOutputStream armorOut = new(msPubKey);
            armorOut.Write(openPGPRing.m_PublicKeyRing.GetEncoded());
            armorOut.Close();

            PublicKey = PGPUtilities.ReadFully(msPubKey);
            msPvtKey.Dispose();
            msPubKey.Dispose();
        }
    }
}