using System.Text;

namespace OpenPGPUnitTests
{
    public class UnitTests
    {
        [Theory]
        [InlineData("your@email.com", "password", "LoremIpsum_Large.txt")]
        [InlineData("your@email.com", "$peci4alC#arac|ers", "LoremIpsum_Large.txt")]
        public void TestGenerateKeyAndEcryptDecrypt(string identity, string password, string expectedResultFile)
        {
            var directory = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);

            var expectedResultPath = Path.Combine(directory!, "testfiles", expectedResultFile);
            byte[] plainTextFile = File.ReadAllBytes(expectedResultPath);
            var expected = Encoding.ASCII.GetString(plainTextFile);


            OpenPGP.OpenPGP openPGP = new();
            openPGP.GenerateKeys(identity, password, out byte[] privateKey, out byte[] publicKey);

            byte[] encryptedFile = openPGP.File_Encrypt(plainTextFile, publicKey, true, "Aes256", "Zip");



            byte[] decryptedFile = openPGP.File_Decrypt(encryptedFile, privateKey, password);

            string decryptedText = Encoding.ASCII.GetString(decryptedFile);

            Assert.Equal(expected, decryptedText);
        }

        [Theory]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "Aes256", "Zip")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "Idea", "Zip")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "TripleDes", "Zip")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "Cast5", "Zip")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "Blowfish", "Zip")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "Aes128", "Zip")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "Twofish", "Zip")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "Camellia128", "Zip")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "Camellia256", "Zip")]

        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "Aes256", "ZLib")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "Idea", "ZLib")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "TripleDes", "ZLib")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "Cast5", "ZLib")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "Blowfish", "ZLib")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "Aes128", "ZLib")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "Twofish", "ZLib")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "Camellia128", "ZLib")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "Camellia256", "ZLib")]

        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "Aes256", "BZip2")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "Idea", "BZip2")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "TripleDes", "BZip2")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "Cast5", "BZip2")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "Blowfish", "BZip2")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "Aes128", "BZip2")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "Twofish", "BZip2")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "Camellia128", "BZip2")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", true, "Camellia256", "BZip2")]

        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "Aes256", "Zip")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "Idea", "Zip")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "TripleDes", "Zip")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "Cast5", "Zip")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "Blowfish", "Zip")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "Aes128", "Zip")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "Twofish", "Zip")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "Camellia128", "Zip")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "Camellia256", "Zip")]

        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "Aes256", "ZLib")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "Idea", "ZLib")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "TripleDes", "ZLib")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "Cast5", "ZLib")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "Blowfish", "ZLib")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "Aes128", "ZLib")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "Twofish", "ZLib")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "Camellia128", "ZLib")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "Camellia256", "ZLib")]

        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "Aes256", "BZip2")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "Idea", "BZip2")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "TripleDes", "BZip2")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "Cast5", "BZip2")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "Blowfish", "BZip2")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "Aes128", "BZip2")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "Twofish", "BZip2")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "Camellia128", "BZip2")]
        [InlineData("Bob_PublicKey.pem", "Bob_PrivateKey.pem", "LoremIpsum_Large.txt", false, "Camellia256", "BZip2")]

        public void TestEncryptDecrypt(string publicKeyFile, string privateKeyFile, string expectedResultFile, bool verify, string symmetricKeyAlgorithm, string CompressionAlgorithm)
        {
            var directory = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);

            var publicKeyPath = Path.Combine(directory!, "testfiles", publicKeyFile);
            var privateKeyPath = Path.Combine(directory!, "testfiles", privateKeyFile);
            var expectedResultPath = Path.Combine(directory!, "testfiles", expectedResultFile);

            byte[] expectedvalue = File.ReadAllBytes(expectedResultPath);
            var expected = Encoding.ASCII.GetString(expectedvalue);
            byte[] publicKeyValue = File.ReadAllBytes(publicKeyPath);
            byte[] privateKeyValue = File.ReadAllBytes(privateKeyPath);

            OpenPGP.OpenPGP openPGP = new ();

            byte[] encryptedFile = openPGP.File_Encrypt(expectedvalue, publicKeyValue, verify, symmetricKeyAlgorithm, CompressionAlgorithm);

            byte[] decryptedFile = openPGP.File_Decrypt(encryptedFile, privateKeyValue, "");

            string decryptedText = Encoding.ASCII.GetString(decryptedFile);

            Assert.Equal(expected, decryptedText);
        }
    }
}