using OutSystems.ExternalLibraries.SDK;

namespace OpenPGP
{
    [OSInterface(Description = "OpenPGP encryption and decryption using BouncyCastle.Cryptography C# library", IconResourceName = "OpenPGP.resources.logo.png", Name = "OpenPGP")]
    public interface IOpenPGP
    {
        /// <summary>
        /// Decrypts binary file using the private key
        /// </summary>
        [OSAction(Description = "Decrypts binary file using the private key", IconResourceName = "OpenPGP.resources.logo.png", ReturnName = "File_Decrypted")]
        public byte[] File_Decrypt(
            [OSParameter(Description = "Encrypted binary file")]
            byte[] File_Encrypted,
            [OSParameter(Description = "Private key in PEM format")]
            byte[] Private_Key,
            [OSParameter(Description = "Password for the private key")]
            string Password);

        /// <summary>
        /// Decrypts binary file using the private key
        /// </summary>
        [OSAction(Description = "Encrypts binary file using the public key", IconResourceName = "OpenPGP.resources.logo.png", ReturnName = "File_Encrypted")]
        public byte[] File_Encrypt(
            [OSParameter(Description = "Plain Text binary file.")]
            byte[] File_PlainText,
            [OSParameter(Description = "Public key in PEM format")]
            byte[] Public_Key,
            [OSParameter(Description = "Flag used to enforce the usage of the Integrity Packet")]
            bool UseIntegrityPacket = false,
            [OSParameter(Description = "Cipher algorithm. Defaults to \"Aes256\"\r\n\r\nAvailable algorithms:\r\nIdea, TripleDes, Cast5 , Blowfish, Aes128, Aes192, Aes256, Twofish, Camellia128, Camellia192, Camellia256")]
            string CipherAlgorithm = "Aes256",
            [OSParameter(Description = "Compression algorithm: Defaults to \"Zip\"\r\nAvailable algorithms:\r\nUncompressed, Zip, ZLib, BZip2")]
            string CompressionAlgorithm = "Zip");

        /// <summary>
        /// Decrypts binary file using the private key
        /// </summary>
        [OSAction(Description = "Generate a new pair of Private and Public keys to be used in the PGP Encrypt/Decrypt actions", IconResourceName = "OpenPGP.resources.logo.png")]
        public void GenerateKeys(
            [OSParameter(Description = "Password for the private key")]
            string Identity,
            [OSParameter(Description = "Private key password")]
            string Password,
            [OSParameter(Description = "Private key binary file in PEM format")]
            out byte[] Private_Key,
            [OSParameter(Description = "Public key binary file in PEM format")]
            out byte[] PublicKey);
    }
}
