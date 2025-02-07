using System.Text;
using PCSC;

namespace dotnet;

public class DesfireEv3Reader
{
    private const byte GET_VERSION = 0x60;
    private const byte GET_APPLICATION_IDS = 0x6A;
    private const byte SELECT_APPLICATION = 0x5A;
    private const byte GET_FILE_IDS = 0x6F;
    private const byte GET_FILE_SETTINGS = 0xF5;

    private readonly ICardReader reader;

    public DesfireEv3Reader(ICardReader reader)
    {
        this.reader = reader;
    }

    public CardVersion GetVersion()
    {
        var response = SendCommand(GET_VERSION);
        if (response == null || response.Length < 7)
            throw new Exception("Invalid version response");

        return new CardVersion
        {
            HardwareVendorId = response[0],
            HardwareType = response[1],
            HardwareSubtype = response[2],
            HardwareVersionMajor = response[3],
            HardwareVersionMinor = response[4],
            HardwareStorageSize = response[5],
            HardwareProtocol = response[6],
        };
    }

    public IEnumerable<uint> GetApplicationIds()
    {
        var response = SendCommand(GET_APPLICATION_IDS);
        var applicationIds = new List<uint>();

        for (int i = 0; i < response.Length; i += 3)
        {
            var aid = BitConverter.ToUInt32(new byte[] { response[i], response[i + 1], response[i + 2], 0x00 }, 0);
            applicationIds.Add(aid);
        }

        return applicationIds;
    }

    public void SelectApplication(uint aid)
    {
        var aidBytes = BitConverter.GetBytes(aid);
        SendCommand(SELECT_APPLICATION, aidBytes[..3]);
    }

    public byte[] GetFileIds()
    {
        return SendCommand(GET_FILE_IDS);
    }

    public FileSettings GetFileSettings(byte fileId)
    {
        var response = SendCommand(GET_FILE_SETTINGS, new[] { fileId });
        return ParseFileSettings(response);
    }

    private byte[] SendCommand(byte command, byte[]? parameters = null)
    {
        // Build APDU command manually
        var commandBytes = new List<byte>
        {
            0x90, // CLA
            command, // INS
            0x00, // P1
            0x00, // P2
        };

        if (parameters != null)
        {
            commandBytes.Add((byte)parameters.Length); // Lc
            commandBytes.AddRange(parameters);
        }
        commandBytes.Add(0x00); // Le

        var receiveBuffer = new byte[256];
        var receivedBytes = reader.Transmit(commandBytes.ToArray(), receiveBuffer);

        if (receivedBytes < 2)
            throw new Exception("Invalid response length");

        var status = new[] { receiveBuffer[receivedBytes - 2], receiveBuffer[receivedBytes - 1] };
        if (status[0] != 0x91)
            throw new Exception($"Command failed with status: {status[0]:X2}{status[1]:X2}");

        System.Console.WriteLine(string.Join(",", receiveBuffer));
        return receiveBuffer.Take(receivedBytes - 2).ToArray();
    }

    private FileSettings ParseFileSettings(byte[] response)
    {
        return new FileSettings
        {
            FileType = response[0],
            CommunicationSettings = response[1],
            AccessRights = BitConverter.ToUInt16(response, 2),
        };
    }
}

public class CardVersion
{
    public byte HardwareVendorId { get; set; }
    public byte HardwareType { get; set; }
    public byte HardwareSubtype { get; set; }
    public byte HardwareVersionMajor { get; set; }
    public byte HardwareVersionMinor { get; set; }
    public byte HardwareStorageSize { get; set; }
    public byte HardwareProtocol { get; set; }
}

public class FileSettings
{
    public byte FileType { get; set; }
    public byte CommunicationSettings { get; set; }
    public ushort AccessRights { get; set; }
}
