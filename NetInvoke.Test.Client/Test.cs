namespace NetInvoke.Test.Client;

public static class Test {
    [Rpc]
    public static void HelloWorld(double pi) {
        Console.WriteLine("Did we receive pi? " + Math.PI.Equals(pi));
    }
}