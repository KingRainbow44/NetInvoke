using System.Net;
using System.Net.Sockets;

namespace NetInvoke.Test.Server;

internal static class Program {
    private static readonly UdpClient Server = new(12345);
    private static bool _isRunning = true;
    
    /// <summary>
    /// Console entry-point.
    /// </summary>
    public static async Task Main() {
        // Listen for incoming messages.
        NetworkInvoke.OnError += (ex, _) => {
            Console.WriteLine($"Error: {ex.Message}");
        };
        NetworkInvoke.Server(Output, "12345");
        
        Task.Run(ReceiveMessages);

        Console.WriteLine("Waiting for messages.");
        
        // Wait until termination signal to stop the server.
        Console.CancelKeyPress += (_, args) => {
            args.Cancel = true; // Prevent the process from terminating immediately.
            
            _isRunning = false;
            Console.WriteLine("Stopping server...");
            Server.Close();
        };
        
        await Task.Delay(-1);
    }

    /// <summary>
    /// UDP output method that sends data to the specified target endpoint.
    /// </summary>
    private static async Task Output(IPEndPoint target, byte[] data) {
        await Server.SendAsync(data, target);
    }

    /// <summary>
    /// Asynchronously receives messages from the server and invokes the appropriate handlers.
    /// </summary>
    private static async Task ReceiveMessages() {
        while (_isRunning) {
            var data = await Server.ReceiveAsync();
            await NetworkInvoke.Receive(data.Buffer, data.RemoteEndPoint);
        }
    }

    /// <summary>
    /// A test method that can be invoked remotely.
    /// </summary>
    [Rpc]
    public static async Task TestMethod(NetworkClient sender, string message, int number) {
        Console.WriteLine("Received message: " + message);
        Console.WriteLine("Received number: " + number);
        
        // Invoke the client response method.
        await NetworkInvoke.InvokeClient(sender, "HelloWorld", Math.PI);
    }
}