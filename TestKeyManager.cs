using System.Security.Cryptography;

namespace dotnet;

public class TestKeyManager
{
    private const string TEST_KEY_FILE = "test_signing_key.xml";

    public static RSA CreateOrLoadTestKeys()
    {
        var rsa = new RSACryptoServiceProvider(2048);

        if (File.Exists(TEST_KEY_FILE))
        {
            // Load existing key
            string keyXml = File.ReadAllText(TEST_KEY_FILE);
            rsa.FromXmlString(keyXml);
            Console.WriteLine("Loaded existing test keys");
        }
        else
        {
            // Generate and save new key
            string keyXml = rsa.ToXmlString(true); // true to include private key
            File.WriteAllText(TEST_KEY_FILE, keyXml);
            Console.WriteLine("Generated and saved new test keys");
        }

        return rsa;
    }
}
