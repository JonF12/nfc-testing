using System;
using System.Text;
using PCSC;
using PCSC.Monitoring;

namespace dotnet;

public static class CardInfo
{
    public static byte[] ExecuteCommand(ICardReader reader, byte[] command, string commandName = "Command")
    {
        try
        {
            var receiveBuffer = new byte[256];
            var received = reader.Transmit(command, receiveBuffer);

            if (received >= 2 && receiveBuffer[received - 2] == 0x90 && receiveBuffer[received - 1] == 0x00)
            {
                byte[] response = new byte[received - 2];
                Array.Copy(receiveBuffer, response, received - 2);
                return response;
            }
            Console.WriteLine(
                $"{commandName} failed. Status: {BitConverter.ToString(new byte[] { receiveBuffer[received - 2], receiveBuffer[received - 1] })}"
            );
            return null!;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"{commandName} error: {ex.Message}");
            return null!;
        }
    }

    public static void PrintCardDetails(ICardReader reader)
    {
        Console.WriteLine("\n=== Card Information ===");

        // Get ATR and parse it
        var atr = reader.GetAttrib(SCardAttribute.AtrString);
        Console.WriteLine($"ATR: {BitConverter.ToString(atr)}");

        // Get UID
        var uidCommand = new byte[] { 0xFF, 0xCA, 0x00, 0x00, 0x00 };
        var uid = ExecuteCommand(reader, uidCommand, "Get UID");
        if (uid != null)
        {
            Console.WriteLine($"UID: {BitConverter.ToString(uid)}");
        }

        // Get Version Info
        var versionCommand = new byte[] { 0xFF, 0xCA, 0x00, 0x03, 0x00 };
        var version = ExecuteCommand(reader, versionCommand, "Get Version");
        if (version != null)
        {
            Console.WriteLine($"Version Info: {BitConverter.ToString(version)}");
            ParseVersion(version);
        }
        // Read all memory pages (MIFARE Ultralight has 16 pages of 4 bytes each)
        Console.WriteLine("\nMemory Contents:");
        for (byte page = 0; page < 128; page++)
        {
            var readCommand = new byte[] { 0xFF, 0xB0, 0x00, page, 0x04 };
            var data = ExecuteCommand(reader, readCommand, $"Read Page {page}");
            if (data != null)
            {
                Console.WriteLine($"Page {page:X2}: {BitConverter.ToString(data)} | ASCII: {ConvertToAscii(data)}");
            }
        }
        // Get Application Directory (if available)
        var getAppDirCmd = new byte[] { 0xFF, 0xCA, 0x01, 0x00, 0x00 };
        var appDir = ExecuteCommand(reader, getAppDirCmd, "Get Application Directory");
        if (appDir != null)
        {
            Console.WriteLine($"\nApplication Directory: {BitConverter.ToString(appDir)}");
        }
    }

    private static void ParseVersion(byte[] version)
    {
        if (version == null || version.Length < 1)
            return;

        Console.WriteLine("\nVersion Analysis:");
        switch (version[0])
        {
            case 0x00:
                Console.WriteLine("Card Type: MIFARE Ultralight");
                Console.WriteLine("Security Features: Basic (No Crypto)");
                break;
            case 0x01:
                Console.WriteLine("Card Type: MIFARE Ultralight C");
                Console.WriteLine("Security Features: 3DES Authentication");
                break;
            case 0x02:
                Console.WriteLine("Card Type: MIFARE Ultralight EV1");
                break;
            default:
                Console.WriteLine($"Unknown Card Type: {version[0]:X2}");
                break;
        }

        if (version.Length >= 2)
        {
            Console.WriteLine($"Vendor ID: {version[1]:X2}");
        }
    }

    private static string ConvertToAscii(byte[] data)
    {
        return Encoding
            .ASCII.GetString(data)
            .Select(c => char.IsControl(c) ? '.' : c)
            .Aggregate(new StringBuilder(), (sb, c) => sb.Append(c))
            .ToString();
    }
}
