using System.Net.Sockets;
using NetInvoke;

var socket = new UdpClient();
socket.Connect("127.0.0.1", 12345);

// Send the message to the socket.
NetworkInvoke.OnError += (ex, _) => {
    Console.WriteLine($"Error: {ex.Message}");
};
NetworkInvoke.Client(async data => {
    await socket.SendAsync(data);
}, "12345");

Task.Run(async () => {
    while (true) {
        var result = await socket.ReceiveAsync();
        await NetworkInvoke.Receive(result.Buffer);
    }
});

await NetworkInvoke.Handshake();
await NetworkInvoke.InvokeServer("TestMethod", "hello world!", 12345);

Console.WriteLine("Sent message!");
await Task.Delay(-1);