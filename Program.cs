using dotnet;
using PCSC;
using PCSC.Monitoring;

// Establish PC/SC context
using var context = ContextFactory.Instance.Establish(SCardScope.System);
var readerNames = context.GetReaders();
using var monitor = MonitorFactory.Instance.Create(SCardScope.System);

monitor.CardInserted += (sender, args) =>
{
    Console.WriteLine($"\nCard inserted into {args.ReaderName}:");
    using var reader = context.ConnectReader(args.ReaderName, SCardShareMode.Direct, SCardProtocol.Raw);

    CardInfo.PrintCardDetails(reader);
    using var rsa = TestKeyManager.CreateOrLoadTestKeys();
    CardSigner.SignCard(reader, rsa);

    if (CardSigner.VerifyCardSignature(reader, rsa))
    {
        Console.WriteLine("Signature verified successfully!");
    }
    else
    {
        Console.WriteLine("Signature verification failed!");
    }
};

monitor.CardRemoved += (sender, args) =>
{
    Console.WriteLine($"\nCard removed from {args.ReaderName}");
};
monitor.Start(readerNames);
Console.WriteLine("\nListening for cards. Press any key to exit.");
Console.ReadKey();
