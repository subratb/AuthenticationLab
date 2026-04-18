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