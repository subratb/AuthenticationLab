using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using StackExchange.Redis;  

var builder = WebApplication.CreateBuilder(args);

// Internal URL: How the Container talks to Keycloak
var REALM_URL_INTERNAL = "http://keycloak:8080/realms/sso-realm"; 
// External URL: How YOUR BROWSER talks to Keycloak
var REALM_URL_EXTERNAL = "http://localhost:8080/realms/sso-realm"; 

// --- 1. LOAD ENV VARS ---
// We read the Client ID and Port from the environment
var clientId = Environment.GetEnvironmentVariable("CLIENT_ID") ?? "app-a";
var appPort = Environment.GetEnvironmentVariable("APP_PORT") ?? "8081";

// --- 1. REDIS CONNECTION ---
var redisConn = "redis-session:6379";
var redis = ConnectionMultiplexer.Connect(redisConn);

// --- 2. DATA PROTECTION (The "Keys") ---
// This stores the encryption keys in Redis. 
// If App A restarts, it downloads these keys and can still read your old cookies.
builder.Services.AddDataProtection()
    .PersistKeysToStackExchangeRedis(redis, "DataProtection-Keys")
    .SetApplicationName("UniqueSsoMesh"); // Shared name so apps can share cookies if needed

// --- 3. SESSION STATE (The "Data") ---
// This stores actual session data in Redis
builder.Services.AddStackExchangeRedisCache(options => {
    options.Configuration = redisConn;
    options.InstanceName = $"{clientId}_";
});
builder.Services.AddSession(options => {
    options.IdleTimeout = TimeSpan.FromMinutes(10);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

// --- 4. OIDC CONFIGURATION ---
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(options => 
{
    options.Cookie.Name = $"{clientId}.Cookie"; // Unique cookie per app
})
.AddOpenIdConnect(options =>
{
    // 1. INTERNAL: Use Docker Network alias for Back-Channel communication
    // This prevents the "Connection Refused" error.
    var internalKeycloak = "http://keycloak:8080/realms/sso-realm";
    options.Authority = internalKeycloak;
    options.MetadataAddress = $"{internalKeycloak}/.well-known/openid-configuration";
    options.RequireHttpsMetadata = false;

    // Standard Config
    options.ClientId = clientId;
    options.ClientSecret = ""; 
    options.ResponseType = OpenIdConnectResponseType.Code;
    options.SaveTokens = true;
    options.Scope.Add("openid");
    options.Scope.Add("profile");

    // 2. DOCKER HACK: Validate Issuer (Optional but recommended for dev)
    options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
    {
        ValidateIssuer = false, // Simplifies dev; strictly, it should match Keycloak's config
        // THE FIX: Tell .NET to map 'preferred_username' to Identity.Name
        NameClaimType = "preferred_username"
    };

    // 3. EXTERNAL: Fix the Browser Redirect (Front-Channel) - "Split-Horizon" configuration
    // When the App reads the metadata from 'keycloak:8080', it will think the 
    // login page is at 'keycloak:8080'. The browser can't resolve that.
    // We intercept the redirect and swap the domain to 'localhost'.
    options.Events = new OpenIdConnectEvents
    {
        // 1. Fix LOGIN Redirect
        OnRedirectToIdentityProvider = context =>
        {
            // Replace internal container name with localhost for the user's browser
            context.ProtocolMessage.IssuerAddress = 
                context.ProtocolMessage.IssuerAddress.Replace("keycloak:8080", "localhost:8080");
            
            return Task.CompletedTask;
        },
        // 2. Fix LOGOUT Redirect
        OnRedirectToIdentityProviderForSignOut = context =>
        {
            // The Metadata says logout is at "http://keycloak:8080/..."
            // We rewrite it to "http://localhost:8080/..." so the browser can find it.
            context.ProtocolMessage.IssuerAddress = 
                context.ProtocolMessage.IssuerAddress.Replace("keycloak:8080", "localhost:8080");
                
            return Task.CompletedTask;
        }
    };
});


builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.UseSession();
app.UseDeveloperExceptionPage();

// --- UI ---
app.MapGet("/", async (HttpContext context) =>
{
    var user = "Guest";
    
    if (context.User.Identity?.IsAuthenticated == true) {
        user = context.User.Identity.Name;
        // FORCE REDIS WRITE: Store a timestamp in the session
        context.Session.SetString("LastActive", DateTime.UtcNow.ToString());
    }

    var style = clientId == "app-a" ? "background-color: #e3f2fd;" : "background-color: #fce4ec;";
    
    var html = $@"
    <body style='font-family: sans-serif; padding: 50px; {style}'>
        <h1>Application: {clientId.ToUpper()}</h1>
        <h2>User: {user}</h2>
        <hr>
        <a href='/login'>Login (SSO)</a> | 
        <a href='/logout'>Logout</a>
        <hr>
        <p>Redis Status: <b>Session Active</b></p>
        <hr>
        <p>Try switching apps. If SSO works, you won't need to login again.</p>
        <ul>
            <li><a href='http://localhost:8081'>Go to App A (Blue)</a></li>
            <li><a href='http://localhost:8082'>Go to App B (Pink)</a></li>
        </ul>
    </body>";
    
    return Results.Content(html, "text/html");
});

app.MapGet("/login", (HttpContext context) => { 
    
    var r = Results.Challenge(
    new Microsoft.AspNetCore.Authentication.AuthenticationProperties { RedirectUri = "/" },
    [OpenIdConnectDefaults.AuthenticationScheme]);
    return r;
    });

app.MapGet("/logout", (HttpContext context) => 
{
    // We sign out of BOTH the Local Cookie and the Remote OIDC Session
    return Results.SignOut(
        authenticationSchemes: new[] 
        { 
            CookieAuthenticationDefaults.AuthenticationScheme, 
            OpenIdConnectDefaults.AuthenticationScheme 
        },
        properties: new Microsoft.AspNetCore.Authentication.AuthenticationProperties 
        { 
            // Crucial: Tells Keycloak where to send the user after logout
            RedirectUri = "/" 
        }
    );
});

app.Run($"http://0.0.0.0:{appPort}");