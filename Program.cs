using dotnet;
using PCSC;
using PCSC.Monitoring;

// Establish PC/SC context
using SCardContext context = new SCardContext();
context.Establish(SCardScope.System);
var readerNames = context.GetReaders();
using var monitor = MonitorFactory.Instance.Create(SCardScope.System);

monitor.CardInserted += (sender, args) =>
{
    Console.WriteLine($"\nCard inserted into {args.ReaderName}");
    using var reader = new SCardReader(context);
    reader.Connect(args.ReaderName, SCardShareMode.Shared, SCardProtocol.T1);
    var cmds = new DesfireCommands(context, reader);
    byte[] getAppIds = new byte[] { 0x90, 0x6A, 0x00, 0x00, 0x00 };
    var appResponse = new byte[256];
    reader.Transmit(getAppIds, ref appResponse);
    Console.WriteLine($"App IDs response: {BitConverter.ToString(appResponse.Take(10).ToArray())}");
    // To change the key:
    //cmds.EncryptNewKey(DesfireCommands.DEFAULT_KEY, DesfireCommands.NEW_KEY);

    // To just authenticate:
    cmds.AuthenticateWithKey(DesfireCommands.DEFAULT_KEY);
};
monitor.CardRemoved += (sender, args) =>
{
    Console.WriteLine($"\nCard removed from {args.ReaderName}");
};
monitor.Start(readerNames);
Console.WriteLine("\nListening for cards. Press any key to exit.");
Console.ReadKey();
