using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/vault", (HttpContext context) =>
{
    string authHeader = context.Request.Headers["Authorization"];
    
    // Hardcoded "State" for the exercise (In reality, this changes every request)
    string realm = "BankVault";
    string nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"; // Static for the lab
    string opaque = "5ccc069c403ebaf9f0171e9517f40e41";

    // 1. If no header, trigger the Challenge
    if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Digest "))
    {
        context.Response.Headers["WWW-Authenticate"] = 
            $"Digest realm=\"{realm}\", qop=\"auth\", nonce=\"{nonce}\", opaque=\"{opaque}\"";
        return Results.Unauthorized();
    }

    try
    {
        // 2. Parse the Client's Response (Regex to extract fields)
        var username = Regex.Match(authHeader, "username=\"([^\"]+)\"").Groups[1].Value;
        var uri = Regex.Match(authHeader, "uri=\"([^\"]+)\"").Groups[1].Value;
        var response = Regex.Match(authHeader, "response=\"([^\"]+)\"").Groups[1].Value;
        var nc = Regex.Match(authHeader, "nc=([^,]+)").Groups[1].Value;
        var cnonce = Regex.Match(authHeader, "cnonce=\"([^\"]+)\"").Groups[1].Value;

        // 3. The Secret Password we are protecting
        var password = "monkey123"; 

        // 4. Calculate Expected Hash (RFC 2617)
        // HA1 = MD5(username:realm:password)
        var ha1 = CalculateMd5($"{username}:{realm}:{password}");
        
        // HA2 = MD5(method:uri)
        var ha2 = CalculateMd5($"{context.Request.Method}:{uri}");

        // Response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
        var expectedResponse = CalculateMd5($"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}");

        if (response == expectedResponse)
        {
            return Results.Ok(new { flag = "flag{md5_is_fast_but_weak}", status = "Unlocked" });
        }
    }
    catch { /* Ignore parsing errors for simplicity */ }

    return Results.Unauthorized();
});

string CalculateMd5(string input)
{
    using var md5 = MD5.Create();
    var bytes = md5.ComputeHash(Encoding.ASCII.GetBytes(input));
    return Convert.ToHexString(bytes).ToLower();
}

app.Run("http://0.0.0.0:8081");
