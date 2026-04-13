using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Security.Cryptography;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// Secret Key (Only the server knows this)
var SECRET_KEY = Encoding.UTF8.GetBytes("super_secret_key_never_share_this_12345");

// --- 1. LOGIN (Get a valid User Token) ---
app.MapGet("/login", () =>
{
    var header = new { alg = "HS256", typ = "JWT" };
    var payload = new { sub = "student", role = "user", iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds() };

    string token = CreateToken(header, payload, SECRET_KEY);
    return Results.Ok(new { token = token });
});

// --- 2. PROTECTED RESOURCE (Admin Only) ---
app.MapGet("/admin", (HttpContext context) =>
{
    string authHeader = context.Request.Headers["Authorization"];
    if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
        return Results.Unauthorized();

    string token = authHeader.Substring("Bearer ".Length).Trim();

    try
    {
        // VULNERABILITY: We trust the token to tell us how to verify it.
        if (ValidateToken(token, out var claims))
        {
            if (claims["role"].ToString() == "admin")
            {
                return Results.Ok(new { 
                    status = "pwned", 
                    flag = "flag{always_check_the_algorithm}",
                    msg = "Welcome, Administrator."
                });
            }
            return Results.Problem("Forbidden: Admins only.", statusCode: 403);
        }
    }
    catch { return Results.BadRequest("Invalid Token"); }

    return Results.Unauthorized();
});

// --- NAIVE JWT LOGIC ---
string CreateToken(object header, object payload, byte[] key)
{
    string b64Header = Base64UrlEncode(JsonSerializer.Serialize(header));
    string b64Payload = Base64UrlEncode(JsonSerializer.Serialize(payload));
    string signature = ComputeSignature(b64Header, b64Payload, key);
    return $"{b64Header}.{b64Payload}.{signature}";
}

bool ValidateToken(string token, out JsonNode claims)
{
    claims = null;
    var parts = token.Split('.');
    if (parts.Length != 3) return false; 

    string b64Header = parts[0];
    string b64Payload = parts[1];
    string incomingSig = parts[2];

    // Decode Header to check Algorithm
    var headerJson = Encoding.UTF8.GetString(Base64UrlDecode(b64Header));
    var headerObj = JsonNode.Parse(headerJson);
    string alg = headerObj["alg"]?.ToString();

    // THE CRITICAL FLAW: Trusting "none"
    if (alg == "none" || alg == "None")
    {
        // Bypass signature check!
        var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(b64Payload));
        claims = JsonNode.Parse(payloadJson);
        return true;
    }

    // Normal Validation (HS256)
    if (alg == "HS256")
    {
        string expectedSig = ComputeSignature(b64Header, b64Payload, SECRET_KEY);
        if (incomingSig == expectedSig)
        {
            var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(b64Payload));
            claims = JsonNode.Parse(payloadJson);
            return true;
        }
    }
    return false;
}

string ComputeSignature(string head, string body, byte[] key)
{
    using var hmac = new HMACSHA256(key);
    var bytes = hmac.ComputeHash(Encoding.UTF8.GetBytes($"{head}.{body}"));
    return Base64UrlEncode1(bytes);
}

// Helper: JWT uses Base64URL (no padding, -_ instead of +/)
string Base64UrlEncode(string input) => Base64UrlEncode1(Encoding.UTF8.GetBytes(input));
string Base64UrlEncode1(byte[] input) => Convert.ToBase64String(input)
    .Replace("+", "-").Replace("/", "_").Replace("=", "");

byte[] Base64UrlDecode(string input)
{
    string incoming = input.Replace("-", "+").Replace("_", "/");
    switch (incoming.Length % 4) {
        case 2: incoming += "=="; break;
        case 3: incoming += "="; break;
    }
    return Convert.FromBase64String(incoming);
}

app.Run("http://0.0.0.0:8084");
