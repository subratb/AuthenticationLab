using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthorization();

// --- CONFIGURATION ---
// The internal Docker URL to fetch Public Keys (JWKS)
var KEYCLOAK_INTERNAL = "http://keycloak:8080/realms/demo-realm"; 

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        // 1. Where to find the Public Keys (Internal Docker Network)
        options.MetadataAddress = $"{KEYCLOAK_INTERNAL}/.well-known/openid-configuration";
        options.RequireHttpsMetadata = false; // Dev only

        options.TokenValidationParameters = new TokenValidationParameters
        {
            // 2. Validate the Signature (Crucial!)
            ValidateIssuerSigningKey = true,

            // 3. Docker Dev Hack:
            // The token says "Issuer: localhost:8080" (from Browser)
            // But the API sees Keycloak at "keycloak:8080"
            // We disable Issuer Validation for this lab to avoid DNS headaches.
            ValidateIssuer = false, 
            
            ValidateAudience = false, // We accept tokens for any client in the realm
            ClockSkew = TimeSpan.Zero
        };
    });

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "Welcome to the Resource API!");

// --- PROTECTED ENDPOINT ---
app.MapGet("/balance", (System.Security.Claims.ClaimsPrincipal user) =>
{
    // If we get here, the Token is valid!
    var userId = user.FindFirst("sub")?.Value;
    var username = user.FindFirst("preferred_username")?.Value;
    
    return Results.Ok(new 
    { 
        message = "Vault Unlocked", 
        user = username, 
        balance = "$1,000,000", 
        status = "Authorized via Keycloak"
    });
}).RequireAuthorization();

app.Run("http://0.0.0.0:8082");