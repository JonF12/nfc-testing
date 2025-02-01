using System.Security.Cryptography;
using PCSC;

namespace dotnet;

public class CardSigner
{
    private static byte[] CreateAuthenticateCommand() => new byte[] { 0xFF, 0x0A, 0x00, 0x00, 0x01 };

    private static byte[] CreateGetUidCommand() => new byte[] { 0x00, 0xCA, 0x00, 0x00, 0x00 };

    private static byte[] CreateReadCommand(byte page) => new byte[] { 0xFF, 0xB0, 0x00, page, 0x04 };

    private static byte[] CreateWriteBinaryCommand(byte page, byte[] data) =>
        new byte[] { 0xFF, 0xD6, 0x00, page, 0x04 }
            .Concat(data)
            .ToArray();

    private const int NTAG215_PAGE_COUNT = 135;
    private const int NTAG215_USER_START_PAGE = 4;
    private const int NTAG215_USER_END_PAGE = 129;

    // Move our storage to later pages to avoid conflict with the Spotify URL
    private const int CHALLENGE_START_PAGE = 120; // Use later pages
    private const int SIGNATURE_START_PAGE = 124; // Use later pages

    private static bool IsValidNtag215Page(byte page)
    {
        return page >= NTAG215_USER_START_PAGE && page <= NTAG215_USER_END_PAGE;
    }

    private static byte[] CreateWriteNtagCommand(byte page, byte[] data)
    {
        // NTAG215 sometimes needs this specific command structure
        return new byte[]
        {
            0xFF, // CLA
            0xD6, // INS: UPDATE BINARY
            0x00, // P1
            page, // P2: Page number
            0x04, // Lc: Length of data
        }
            .Concat(data)
            .ToArray();
    }

    // Alternative write command to try
    private static byte[] CreateAltWriteCommand(byte page, byte[] data)
    {
        return new byte[]
        {
            0xFF, // CLA
            0xF0, // INS: MIFARE Write
            0x00, // P1
            page, // P2: Page number
            0x04, // Lc: Length of data
        }
            .Concat(data)
            .ToArray();
    }

    public static void SignCard(ICardReader reader, RSA signingKey)
    {
        try
        {
            var uid = ExecuteCommand(reader, CreateGetUidCommand(), "Get UID");
            if (uid == null)
                throw new InvalidOperationException("Failed to read UID");

            Console.WriteLine($"Successfully read UID: {BitConverter.ToString(uid)}");

            // Test write with both command types
            Console.WriteLine("Testing write operations...");
            var testData = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD };
            byte testPage = 0x04;

            // Try first command type
            var testWrite = CreateWriteNtagCommand(testPage, testData);
            var testResponse = ExecuteCommand(reader, testWrite, "Test Write Standard");

            if (testResponse == null)
            {
                // Try alternative command
                Console.WriteLine("Trying alternative write command...");
                testWrite = CreateAltWriteCommand(testPage, testData);
                testResponse = ExecuteCommand(reader, testWrite, "Test Write Alternative");

                if (testResponse == null)
                {
                    throw new Exception("Both write attempts failed");
                }
            } // If we get here, writing works - proceed with actual signing
            // Generate challenge
            using var rng = new RNGCryptoServiceProvider();
            var challenge = new byte[4];
            rng.GetBytes(challenge);

            // Write challenge
            var challengeWrite = CreateWriteNtagCommand(CHALLENGE_START_PAGE, challenge);
            var challengeResponse = ExecuteCommand(reader, challengeWrite, "Write Challenge");
            if (challengeResponse == null)
            {
                throw new Exception("Failed to write challenge");
            }

            // Create and write signature
            var dataToSign = uid.Concat(challenge).ToArray();
            var signature = signingKey.SignData(dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var truncatedSignature = signature.Take(8).ToArray();

            // Write signature parts
            for (int i = 0; i < 2; i++)
            {
                var pageData = new byte[4];
                Array.Copy(truncatedSignature, i * 4, pageData, 0, 4);

                var signatureWrite = CreateWriteNtagCommand((byte)(SIGNATURE_START_PAGE + i), pageData);
                Console.WriteLine($"Writing signature part {i + 1} to page {SIGNATURE_START_PAGE + i}...");

                var signResponse = ExecuteCommand(reader, signatureWrite, $"Write Signature Part {i + 1}");
                if (signResponse == null)
                {
                    throw new InvalidOperationException($"Failed to write signature part {i + 1}");
                }

                // Add a small delay between writes
                Thread.Sleep(50);
            }

            Console.WriteLine("Card signed successfully!");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Signing failed: {ex.Message}");
        }
    }

    public static bool VerifyCardSignature(ICardReader reader, RSA publicKey)
    {
        try
        {
            // 1. Read UID
            var uidCommand = new byte[] { 0xFF, 0xCA, 0x00, 0x00, 0x00 };
            var uid = ExecuteCommand(reader, uidCommand, "Get UID");
            if (uid == null)
                return false;

            // 2. Read stored challenge
            byte[] challenge = new byte[8];
            for (int i = 0; i < 2; i++)
            {
                var readCommand = new byte[] { 0xFF, 0xB0, 0x00, (byte)(CHALLENGE_START_PAGE + i), 0x04 };
                var pageData = ExecuteCommand(reader, readCommand, $"Read Challenge Page {i}");
                if (pageData == null)
                    return false;
                Array.Copy(pageData, 0, challenge, i * 4, 4);
            }

            // 3. Read stored signature
            byte[] storedSignature = new byte[16];
            for (int i = 0; i < 4; i++)
            {
                var readCommand = new byte[] { 0xFF, 0xB0, 0x00, (byte)(SIGNATURE_START_PAGE + i), 0x04 };
                var pageData = ExecuteCommand(reader, readCommand, $"Read Signature Page {i}");
                if (pageData == null)
                    return false;
                Array.Copy(pageData, 0, storedSignature, i * 4, 4);
            }

            // 4. Recreate original signed data
            byte[] dataToVerify = uid.Concat(challenge).ToArray();

            // 5. Pad truncated signature back to full RSA size
            byte[] paddedSignature = new byte[publicKey.KeySize / 8];
            Array.Copy(storedSignature, paddedSignature, storedSignature.Length);

            // 6. Verify signature
            return publicKey.VerifyData(dataToVerify, paddedSignature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Verification failed: {ex.Message}");
            return false;
        }
    }

    private static byte[] ExecuteCommand(ICardReader reader, byte[] command, string commandName)
    {
        try
        {
            Console.WriteLine($"Sending {commandName}: {BitConverter.ToString(command)}");

            var receiveBuffer = new byte[256];
            var received = reader.Transmit(command, receiveBuffer);

            if (received >= 2)
            {
                byte sw1 = receiveBuffer[received - 2];
                byte sw2 = receiveBuffer[received - 1];

                Console.WriteLine($"{commandName} status: {sw1:X2}-{sw2:X2}");

                if (sw1 == 0x90 && sw2 == 0x00)
                {
                    if (received == 2)
                        return new byte[0];
                    byte[] response = new byte[received - 2];
                    Array.Copy(receiveBuffer, response, received - 2);
                    return response;
                }
                else
                {
                    Console.WriteLine($"{commandName} failed. Status: {sw1:X2}-{sw2:X2}");
                    return null;
                }
            }
            return null;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"{commandName} error: {ex.Message}");
            return null;
        }
    }

    // Add method to dump memory contents for debugging
    public static void DumpMemory(ICardReader reader)
    {
        Console.WriteLine("\nDumping card memory contents:");

        for (byte page = 0; page < 16; page++)
        {
            byte[] readCommand = new byte[]
            {
                0xFF, // CLA
                0xB0, // INS - READ BINARY
                0x00, // P1
                page, // P2 - Page number
                0x04, // Le - Expected length
            };

            var data = ExecuteCommand(reader, readCommand, $"Read Page {page}");
            if (data != null)
            {
                Console.WriteLine($"Page {page:X2}: {BitConverter.ToString(data)}");
            }
        }
    }
}
