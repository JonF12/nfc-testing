using System.Security.Cryptography;
using PCSC;

namespace dotnet;

public class DesfireCommands
{
    private readonly SCardContext _context;
    private readonly SCardReader _reader;

    // Keys remain the same
    public static byte[] DEFAULT_KEY =>
        new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    public static byte[] NEW_KEY =>
        new byte[16] { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00 };

    public DesfireCommands(SCardContext context, SCardReader reader)
    {
        if (!reader.IsConnected)
            throw new InvalidOperationException("Reader must be connected");
        _context = context;
        _reader = reader;
    }

    public bool EncryptNewKey(byte[] currentKey, byte[] newKey)
    {
        Console.WriteLine("Starting key change process...");

        // First authenticate with current key
        if (!AuthenticateWithKey(currentKey))
        {
            Console.WriteLine("Authentication failed, cannot change key");
            return false;
        }

        // Prepare key change command
        byte[] changeKeyCommand = new byte[]
        {
            0x90, // CLA
            0xC4, // INS (Change Key)
            0x00, // P1 - Key Number (master key)
            0x00, // P2
            0x10, // Lc - Length of key data (16 bytes)
        }
            .Concat(newKey)
            .ToArray();

        var response = new byte[256];
        var result = _reader.Transmit(changeKeyCommand, ref response);

        if (result != SCardError.Success)
        {
            Console.WriteLine($"Key change failed: {result}");
            return false;
        }

        // Check response
        if (response[0] == 0x91 && response[1] == 0x00)
        {
            Console.WriteLine("Key change successful!");
            return true;
        }

        Console.WriteLine($"Unexpected response: {BitConverter.ToString(response.Take(2).ToArray())}");
        return false;
    }

    public bool AuthenticateWithKey(byte[] key)
    {
        Console.WriteLine("Starting authentication...");
        Console.WriteLine($"Using key: {BitConverter.ToString(key)}");

        // Step 1: Initial auth command
        byte[] authCommand = new byte[] { 0x90, 0x0A, 0x00, 0x00, 0x01, 0x00 };
        var response = new byte[256];
        var result = _reader.Transmit(authCommand, ref response);
        Thread.Sleep(200);

        Console.WriteLine($"Initial auth response: {BitConverter.ToString(response.Take(2).ToArray())}");
        if (response[0] == 0x91 && response[1] == 0x7E)
        {
            // Step 2: Get initial challenge data - first with empty Get_Data
            byte[] getInitialCmd = new byte[] { 0x90, 0xAF, 0x01, 0x00, 0x10 };

            var initialResponse = new byte[256];
            result = _reader.Transmit(getInitialCmd, ref initialResponse);
            Thread.Sleep(200);
            Console.WriteLine($"Initial challenge exchange: {BitConverter.ToString(initialResponse.Take(18).ToArray())}");

            // Now get the actual challenge data
            byte[] getChallengeCmd = new byte[] { 0x90, 0xAF, 0x01, 0x00, 0x10 };

            var challengeResponse = new byte[256];
            result = _reader.Transmit(getChallengeCmd, ref challengeResponse);
            Thread.Sleep(200);

            Console.WriteLine($"Full challenge data: {BitConverter.ToString(challengeResponse.Take(18).ToArray())}");

            // Extract challenge data - should be in the response after status bytes
            var challenge = new byte[16];
            if (challengeResponse.Length >= 18) // 2 status bytes + 16 data bytes
            {
                Array.Copy(challengeResponse, 2, challenge, 0, 16);
            }

            Console.WriteLine($"Extracted challenge: {BitConverter.ToString(challenge)}");
            var encryptedResponse = EncryptChallenge(challenge, key);
            Console.WriteLine($"Encrypted response: {BitConverter.ToString(encryptedResponse)}");

            // Step 3: Send encrypted response
            byte[] authResponse = new byte[] { 0x90, 0xAF, 0x00, 0x00, 0x10 }
                .Concat(encryptedResponse)
                .ToArray();

            var firstResponse = new byte[256];
            result = _reader.Transmit(authResponse, ref firstResponse);
            Thread.Sleep(200);

            Console.WriteLine($"Response after sending encrypted data: {BitConverter.ToString(firstResponse.Take(18).ToArray())}");

            // Step 4: Handle card's response for mutual authentication
            if (firstResponse[0] == 0x91 && firstResponse[1] == 0x7E)
            {
                byte[] getCardAuthCmd = new byte[] { 0x90, 0xAF, 0x00, 0x00, 0x10 };

                var cardAuthResponse = new byte[256];
                result = _reader.Transmit(getCardAuthCmd, ref cardAuthResponse);
                Console.WriteLine($"Card auth data: {BitConverter.ToString(cardAuthResponse.Take(18).ToArray())}");

                // If we get actual data (not 91-7E), send final confirmation
                if (cardAuthResponse[0] != 0x91 || cardAuthResponse[1] != 0x7E)
                {
                    byte[] finalCmd = new byte[] { 0x90, 0xAF, 0x00, 0x00, 0x00 };

                    var finalResponse = new byte[256];
                    result = _reader.Transmit(finalCmd, ref finalResponse);
                    Thread.Sleep(200);

                    Console.WriteLine($"Final auth status: {BitConverter.ToString(finalResponse.Take(2).ToArray())}");

                    return finalResponse[0] == 0x90 && finalResponse[1] == 0x00;
                }
            }
        }

        Console.WriteLine("Authentication failed");
        return false;
    }

    private byte[] EncryptChallenge(byte[] challenge, byte[] key)
    {
        Console.WriteLine($"Challenge to encrypt: {BitConverter.ToString(challenge)}");
        using (var aes = Aes.Create())
        {
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            aes.KeySize = 128;
            aes.BlockSize = 128;
            aes.Key = key;
            aes.IV = new byte[16]; // Zero IV for DESFire

            // For DESFire EV3, we need to:
            // 1. Return the full 16-byte block
            // 2. Use TransformFinalBlock instead of TransformBlock
            using var encryptor = aes.CreateEncryptor();
            return encryptor.TransformFinalBlock(challenge, 0, 16);
        }
    }
}
