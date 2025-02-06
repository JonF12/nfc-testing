using dotnet;
using PCSC;
using PCSC.Monitoring;

// Establish PC/SC context
using var context = ContextFactory.Instance.Establish(SCardScope.System);
var readerNames = context.GetReaders();
using var monitor = MonitorFactory.Instance.Create(SCardScope.System);

monitor.CardInserted += (sender, args) =>
{
    Console.WriteLine($"\nCard inserted into {args.ReaderName}");
    ReadCard(context, args.ReaderName);
};

monitor.CardRemoved += (sender, args) =>
{
    Console.WriteLine($"\nCard removed from {args.ReaderName}");
};
monitor.Start(readerNames);
Console.WriteLine("\nListening for cards. Press any key to exit.");
Console.ReadKey();

static void ReadCard(ISCardContext context, string readerName)
{
    try
    {
        using var reader = context.ConnectReader(readerName, SCardShareMode.Shared, SCardProtocol.T1);
        var desfireReader = new DesfireEv3Reader(reader);

        // Read card version
        Console.WriteLine("\nReading card version...");
        var version = desfireReader.GetVersion();
        Console.WriteLine($"Hardware Version: {version.HardwareVersionMajor}.{version.HardwareVersionMinor}");
        Console.WriteLine($"Storage Size: {version.HardwareStorageSize}");
        Console.WriteLine($"Protocol: {version.HardwareProtocol}");

        // Read applications
        Console.WriteLine("\nReading applications...");
        var applications = desfireReader.GetApplicationIds();
        foreach (var aid in applications)
        {
            Console.WriteLine($"\nApplication ID: {aid:X6}");

            // Select this application
            desfireReader.SelectApplication(aid);

            // Read file IDs in this application
            var fileIds = desfireReader.GetFileIds();
            Console.WriteLine($"Files in application {aid:X6}:");

            foreach (var fileId in fileIds)
            {
                try
                {
                    var settings = desfireReader.GetFileSettings(fileId);
                    Console.WriteLine($"  File {fileId:X2}:");
                    Console.WriteLine($"    Type: {settings.FileType:X2}");
                    Console.WriteLine($"    Communication Settings: {settings.CommunicationSettings:X2}");
                    Console.WriteLine($"    Access Rights: {settings.AccessRights:X4}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  Error reading file {fileId:X2}: {ex.Message}");
                }
            }
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Error reading card: {ex.Message}");
    }
}
