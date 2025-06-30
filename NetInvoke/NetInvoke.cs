using System.Net;
using System.Reflection;

// 'NetInvoke', short for 'Network Invoke', is a single-file library
// designed for multi-platform use with the goal of providing a simple
// API to invoke methods over the network.
//
// The protocol is platform independent, and the underlying wrapper can
// be used with any transport layer (most commonly UDP due to simplicity).
//
// The main class 'NetworkInvoke' acts as both a client and server wrapper,
// however, it can only act as one at a time.
//
// See 'NetInvoke.Test.Server' for an example server implementation.
// See 'NetInvoke.Test.Client' for an example client implementation.
namespace NetInvoke;

internal enum EndpointType {
    /// <summary>
    /// The <see cref="NetworkInvoke"/> wrapper has not been configured yet.
    /// </summary>
    NotConfigured,
    
    /// <summary>
    /// <see cref="NetworkInvoke"/> is running as a client.
    /// </summary>
    Client,
    
    /// <summary>
    /// <see cref="NetworkInvoke"/> is running as a server.
    /// </summary>
    Server
}

/// <summary>
/// Main class for interacting with network invokes.
/// </summary>
public static class NetworkInvoke {
    #region Exposed API

    public static event Action<Exception, byte[]>? OnError;

    #endregion
    
    #region Shared

    /// <summary>
    /// A list of methods that can be invoked remotely.
    /// </summary>
    private static readonly List<MethodInfo> Methods = [];

    /// <summary>
    /// The client type that <see cref="NetworkInvoke"/> is running as.
    /// </summary>
    private static EndpointType _type = EndpointType.NotConfigured;

    /// <summary>
    /// The expected authentication key.
    /// </summary>
    private static string? _key;

    /// <summary>
    /// Resolves all remote callable methods.
    /// </summary>
    private static void ResolveTypes() {
        // Get all methods marked with the Rpc attribute.
        var rpcMethods = AppDomain.CurrentDomain.GetAssemblies()
            .SelectMany(a => a.GetTypes())
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static))
            .Where(m => m.GetCustomAttribute<Rpc>() is not null);

        // Add them to the list of methods.
        Methods.AddRange(rpcMethods);
    }

    /// <summary>
    /// Invokes a method by its name.
    /// All parameters are read from the provided <see cref="BinaryReader"/>.
    /// </summary>
    private static async Task InvokeMethod(string name, BinaryReader reader, NetworkClient? sender = null) {
        // Find the method by name.
        var method = Methods.FirstOrDefault(m => m.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (method is null) {
            OnError?.Invoke(new InvalidOperationException($"Method '{name}' not found."), []);
            return;
        }
        
        // Parse the method parameters.
        List<object?> parameters = [];
        foreach (var parameter in method.GetParameters()) {
            // Read the parameter value based on its type.
            object? value = parameter.ParameterType switch {
                { } t when t == typeof(int) => reader.ReadInt32(),
                { } t when t == typeof(uint) => reader.ReadUInt32(),
                { } t when t == typeof(string) => reader.ReadString(),
                { } t when t == typeof(bool) => reader.ReadBoolean(),
                { } t when t == typeof(float) => reader.ReadSingle(),
                { } t when t == typeof(double) => reader.ReadDouble(),
                { } t when t == typeof(byte[]) => reader.ReadBytes(reader.ReadInt32()),
                { } t when t == typeof(NetworkClient) && sender is not null => sender,
                _ => throw new InvalidOperationException($"Unsupported parameter type: {parameter.ParameterType}")
            };
            parameters.Add(value);
        }
        
        // Invoke the method with the parsed parameters.
        try {
            var result = method.Invoke(null, parameters.ToArray());
            if (result is Task task) {
                await task; // Await the task if it's asynchronous.
            }
        }
        catch (Exception ex) {
            OnError?.Invoke(ex, []);
        }
    }

    #endregion

    #region Constants

    internal const uint HandshakeHeader = 0x98f13ac5;
    internal const uint HandshakeFooter = 0x5c3a1f98;

    private const uint OperationSuccess = 0x01010101;
    private const uint OperationError = 0x02020202;
    
    private const uint OperationHandshake = 0x10101010;
    private const uint OperationDisconnect = 0x20202020;

    #endregion
    
    #region Client

    /// <summary>
    /// The action used for sending data to the server.
    /// </summary>
    private static Func<byte[], Task>? _clientOutput;
    
    /// <summary>
    /// Indicates whether the handshake has been completed successfully.
    /// </summary>
    private static bool _handshakeCompleted;

    /// <summary>
    /// Prepares <see cref="NetworkInvoke"/> for usage as a client.
    /// </summary>
    /// <param name="output">The action used for sending data to the server.</param>
    /// <param name="key">The authentication key expected from the server.</param>
    public static void Client(Func<byte[], Task> output, string? key = null) {
        _type = EndpointType.Client;
        _clientOutput = output;
        _key = key;
        
        ResolveTypes();
    }

    /// <summary>
    /// Performs a handshake with the server to establish a connection.
    /// </summary>
    public static async Task Handshake() {
        if (_type != EndpointType.Client || _clientOutput is null) {
            throw new InvalidOperationException("Handshake can only be performed on a client.");
        }

        // Create a handshake message.
        var message = new HandshakeMessage {
            Key = _key
        };
        
        // Send the handshake message to the server.
        await _clientOutput.Invoke(message);
        
        // Wait for the response from the server.
        _handshakeCompleted = false;
    }

    /// <summary>
    /// Invokes a method on the remote server.
    /// </summary>
    public static async Task InvokeServer(string method, params object[] args) {
        if (_type != EndpointType.Client || _clientOutput is null) {
            throw new InvalidOperationException("Invoke can only be performed on a client.");
        }

        // Create an invoke message.
        var message = new InvokeMessage {
            MethodName = method,
            Parameters = args
        };
        
        // Send the invoke message to the server.
        await _clientOutput.Invoke(message);
    }

    #endregion
    
    #region Server

    /// <summary>
    /// The action used for sending data to clients.
    /// </summary>
    private static Func<IPEndPoint, byte[], Task>? _serverOutput;
    
    /// <summary>
    /// A global dictionary storing active network clients.
    /// </summary>
    public static readonly Dictionary<IPEndPoint, NetworkClient> Clients = new();
    
    /// <summary>
    /// Prepares <see cref="NetworkInvoke"/> for usage as a server.
    /// </summary>
    /// <param name="output">The action used for sending data to clients.</param>
    /// <param name="key">The authentication key required for use.</param>
    public static void Server(Func<IPEndPoint, byte[], Task> output, string? key = null) {
        _type = EndpointType.Server;
        _serverOutput = output;
        _key = key;
        
        ResolveTypes();
    }
    
    /// <summary>
    /// Invokes a method on a remote client.
    /// </summary>
    public static async Task InvokeClient(IPEndPoint target, string method, params object[] args) {
        if (_type != EndpointType.Server || _serverOutput is null) {
            throw new InvalidOperationException("Invoke can only be performed on a server.");
        }

        // Create an invoke message.
        var message = new InvokeMessage {
            MethodName = method,
            Parameters = args
        };
        
        // Send the invoke message to the specified client.
        await _serverOutput.Invoke(target, message);
    }
    
    /// <summary>
    /// Finds the first client that matches the given predicate.
    /// </summary>
    public static NetworkClient? FirstOrDefault(Func<NetworkClient, bool> predicate) {
        // Find the first client that matches the predicate.
        return Clients.Values.FirstOrDefault(predicate);
    }

    /// <summary>
    /// Removes the client from the list.
    /// Sends a disconnect packet to the client if it exists.
    /// </summary>
    /// <param name="target">The target to remove.</param>
    public static async Task RemoveClient(IPEndPoint target) {
        if (Clients.Remove(target, out var client) && _serverOutput is not null) {
            // Send a disconnect message to the client.
            var message = new StatusCodeMessage { StatusCode = OperationDisconnect };
            await _serverOutput.Invoke(client, message);
        }
    }

    #endregion
    
    /// <summary>
    /// A receiver method that processes incoming data from a network endpoint.
    /// </summary>
    /// <param name="data">The raw binary data to receive.</param>
    /// <param name="sender">The client endpoint which sent the data.</param>
    public static async Task Receive(byte[] data, IPEndPoint? sender = null) {
        using var stream = new MemoryStream(data);
        using var reader = new BinaryReader(stream);

        #region Check Header & Footer

        // Check if the header & footer are present & valid.
        if (data.Length < 8) {
            OnError?.Invoke(new InvalidDataException("Malformed data received: invalid handshake"), data);
            return;
        }
        
        // Get the first 4 bytes as the header.
        var header = reader.ReadUInt32();
        if (header != HandshakeHeader) {
            OnError?.Invoke(new InvalidDataException("Malformed data received: invalid handshake header"), data);
            return;
        }
        
        // Get the last 4 bytes as the footer.
        var currentPosition = stream.Position;
        stream.Seek(-4, SeekOrigin.End);
        var footer = reader.ReadUInt32();
        if (footer != HandshakeFooter) {
            OnError?.Invoke(new InvalidDataException("Malformed data received: invalid handshake footer"), data);
            return;
        }
        stream.Position = currentPosition;

        #endregion
        
        switch (_type) {
            // Check if the handshake was completed.
            case EndpointType.Client when !_handshakeCompleted: {
                // Check if the data is a handshake response.
                if (data.Length < 12) {
                    OnError?.Invoke(new InvalidDataException("Malformed handshake response received"), data);
                    return;
                }

                // Read the handshake response.
                var responseCode = reader.ReadUInt32();
                switch (responseCode) {
                    case OperationSuccess:
                        // Handshake successful, set the flag.
                        _handshakeCompleted = true;
                        return;
                    case OperationError: {
                        // Handshake failed, read the error message.
                        var errorMessage = reader.ReadString();
                        OnError?.Invoke(new InvalidOperationException($"Handshake failed: {errorMessage}"), data);
                        return;
                    }
                }
                
                // If we reach here, the response code is invalid.
                OnError?.Invoke(new InvalidDataException("Malformed handshake response received: invalid response code"), data);
                return;
            }
            case EndpointType.Client when _handshakeCompleted && _clientOutput is not null: {
                // Invoke the method.
                var methodName = reader.ReadString();
                try {
                    await InvokeMethod(methodName, reader);
                    // TODO: Send a success response.
                    // await _clientOutput.Invoke(new StatusCodeMessage { StatusCode = OperationSuccess });
                }
                catch (Exception ex) {
                    // TODO: Send an error response.
                    // await _clientOutput.Invoke(new StatusCodeMessage { StatusCode = OperationError });
                    OnError?.Invoke(ex, data);
                }
                return;
            }
            // Check that a sender is specified.
            case EndpointType.Server when sender is null:
                OnError?.Invoke(new InvalidOperationException("No sender specified for server-side invocation"), data);
                return;
            case EndpointType.Server when _serverOutput is not null: {
                // Add the client to the clients dictionary if not already present.
                if (!Clients.TryGetValue(sender, out var client)) {
                    client = new NetworkClient(sender);
                    Clients[sender] = client;
                }
                
                // Check if the client is authenticated.
                if (_key is not null && !client.Authenticated) {
                    try {
                        // Try reading the authentication key.
                        var clientKey = reader.ReadString();
                        // Check if the key matches the expected key.
                        if (!_key.Equals(clientKey)) {
                            // Disconnect the client.
                            OnError?.Invoke(new UnauthorizedAccessException("Authentication failed: invalid key"), data);
                            await _serverOutput.Invoke(sender, new StatusCodeMessage { StatusCode = OperationError });
                            return;
                        }
                        
                        // Authentication successful, mark the client as authenticated.
                        client.Authenticated = true;
                        await _serverOutput.Invoke(sender, new StatusCodeMessage { StatusCode = OperationSuccess });
                        return;
                    }
                    catch (Exception exception) {
                        OnError?.Invoke(new InvalidDataException("Malformed data received: authentication key missing", exception), data);
                        return;
                    }
                }
                
                // Invoke the method.
                var methodName = reader.ReadString();
                try {
                    await InvokeMethod(methodName, reader, client);
                    // TODO: Send a success response.
                    // await _serverOutput.Invoke(sender, new StatusCodeMessage { StatusCode = OperationSuccess });
                }
                catch (Exception ex) {
                    // TODO: Send an error response.
                    // await _serverOutput.Invoke(sender, new StatusCodeMessage { StatusCode = OperationError });
                    OnError?.Invoke(ex, data);
                }
                return;
            }
        }
    }
}

public interface IClientData {
    /// <summary>
    /// Interface getter to retrieve the client associated with this data instance.
    /// </summary>
    public NetworkClient Client { get; }
}

/// <summary>
/// A data structure for server-side network clients.
/// </summary>
public record NetworkClient(IPEndPoint Endpoint) {
    public bool Authenticated { get; set; }

    /// <summary>
    /// The data container for this client.
    /// </summary>
    private readonly Dictionary<Type, object> _data = new();
    
    /// <summary>
    /// Implicit conversion from <see cref="NetworkClient"/> to <see cref="IPEndPoint"/>.
    /// </summary>
    public static implicit operator IPEndPoint(NetworkClient client) {
        return client.Endpoint;
    }
    
    /// <summary>
    /// Gets or creates a data instance for the player.
    /// </summary>
    public T Data<T>() where T : IClientData {
        // Check if the entry exists.
        var type = typeof(T);
        if (_data.TryGetValue(type, out var data) &&
            data is T expected) {
            return expected;
        }

        // Otherwise, we create a new instance.
        var instance = Activator.CreateInstance(type, this);
        if (instance is not T casted) {
            throw new Exception("Instance does not match expected type");
        }

        _data[type] = casted;
        return casted;
    }
}

/// <summary>
/// An interface used for identifying network messages.
/// </summary>
public abstract class NetworkMessage {
    /// <summary>
    /// Enables implicit conversion from the KeyBinding type to a string.
    /// </summary>
    public static implicit operator byte[](NetworkMessage bind) {
        return bind.Serialize();
    }
}

/// <summary>
/// Represents a message sent to disconnect a client.
/// </summary>
public sealed class StatusCodeMessage : NetworkMessage {
    public uint StatusCode { get; set; }
}

/// <summary>
/// Represents a message used for the initial handshake between client and server.
/// </summary>
public sealed class HandshakeMessage : NetworkMessage {
    public string? Key { get; set; } = null;
}

/// <summary>
/// Represents a message that invokes a remote procedure call (RPC).
/// </summary>
public sealed class InvokeMessage : NetworkMessage {
    public string MethodName { get; set; } = string.Empty;
    public object[] Parameters { get; set; } = [];
}

public static class SerializationExtensions {
    /// <summary>
    /// Serializes a network message into a byte array.
    /// </summary>
    public static byte[] Serialize(this NetworkMessage msg) {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        
        // Write the header.
        writer.Write(NetworkInvoke.HandshakeHeader);
        
        // Write each field in order using reflection.
        var properties = msg.GetType().GetProperties();
        foreach (var property in properties) {
            // Check if the property is readable.
            if (!property.CanRead) {
                continue;
            }
            
            // Get the value of the property.
            var value = property.GetValue(msg);
            
            // Write the value based on its type.
            writer.SmartWrite(value);
        }
        
        // Write the footer.
        writer.Write(NetworkInvoke.HandshakeFooter);
        
        return stream.ToArray();
    }

    /// <summary>
    /// Writes a value to the binary writer based on its type.
    /// </summary>
    public static void SmartWrite(this BinaryWriter writer, object? value) {
        if (value is null) {
            // Skip writing this object.
            return;
        }
        
        switch (value) {
            case uint uintValue:
                writer.Write(uintValue);
                break;
            case string strValue:
                writer.Write(strValue);
                break;
            case int intValue:
                writer.Write(intValue);
                break;
            case bool boolValue:
                writer.Write(boolValue);
                break;
            case float floatValue:
                writer.Write(floatValue);
                break;
            case double doubleValue:
                writer.Write(doubleValue);
                break;
            case byte[] bytesValue:
                writer.Write(bytesValue.Length);
                writer.Write(bytesValue);
                break;
            case object[] objectsValue:
                foreach (var @object in objectsValue) {
                    writer.SmartWrite(@object);
                }
                break;
            default:
                throw new InvalidOperationException($"Unsupported property type {value?.GetType().Name}");
        }
    }
}

/// <summary>
/// Attribute to mark methods as remote procedure calls (RPCs).
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
public class Rpc : Attribute;
