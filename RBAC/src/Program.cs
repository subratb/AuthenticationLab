using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using StackExchange.Redis;
using System.Reflection.Metadata.Ecma335;
using Microsoft.AspNetCore.Mvc.Rendering;

var builder = WebApplication.CreateBuilder(args);

// Internal URL: How the Container talks to Keycloak
var REALM_URL_INTERNAL = "http://keycloak:8080/realms/rbac-realm"; 

// --- 1. LOAD ENV VARS ---
// We read the Client ID and Port from the environment
var clientId = Environment.GetEnvironmentVariable("CLIENT_ID") ?? "client-app";
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

    // Override the default "/Account/AccessDenied"
    options.AccessDeniedPath = "/access-denied";
})
.AddOpenIdConnect(options =>
{
    // 1. INTERNAL: Use Docker Network alias for Back-Channel communication
    // This prevents the "Connection Refused" error.    
    options.Authority = REALM_URL_INTERNAL;
    options.MetadataAddress = $"{REALM_URL_INTERNAL}/.well-known/openid-configuration";
    options.RequireHttpsMetadata = false;

    // 2. CRITICAL: Stop .NET from renaming claims. 
    // Keeps 'roles' as 'roles', and 'preferred_username' as 'preferred_username'.
    options.MapInboundClaims = false;

    // Standard Config
    options.ClientId = clientId;
    options.ClientSecret = ""; 
    options.ResponseType = OpenIdConnectResponseType.Code;
    options.SaveTokens = true;
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("roles");

    // 2. DOCKER HACK: Validate Issuer (Optional but recommended for dev)
    options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
    {
        ValidateIssuer = false, // Simplifies dev; strictly, it should match Keycloak's config
        // Map'preferred_username' to Identity.Name
        NameClaimType = "preferred_username",
        RoleClaimType = "roles" // Matches the Keycloak Mapper we just made
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
    var user = context.User.Identity?.IsAuthenticated == true 
        ? context.User.Identity.Name 
        : "Guest";

    // CHECK ROLE
    var isManager = context.User.IsInRole("manager");
    var managerBadge = isManager ? "<span style='background:gold;padding:5px'>MANAGER</span>" : "";

    // DEBUG: decoding the raw JWT token to show claims (for learning purposes)
    var claimsHtml = string.Empty;
    var idTokenString = string.Empty;//await context.GetTokenAsync(OpenIdConnectDefaults.AuthenticationScheme, "id_token") ?? "No Token";
    await context.GetTokenAsync(OpenIdConnectDefaults.AuthenticationScheme, "id_token").ContinueWith(async tokenTask => 
    {
        idTokenString = await tokenTask;
        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(tokenTask.Result);
        // D. Display the Claims
        claimsHtml = string.Join("", jwt.Claims.Select(c => $"<li><b>{c.Type}:</b> {c.Value}</li>"));       
         
    });    

    var html = $@"
    <body style='font-family: sans-serif; padding: 50px;'>
        <h1>Application: {Environment.GetEnvironmentVariable("CLIENT_ID")}</h1>
        <h2>User: {user} {managerBadge}</h2>
        <hr>
        <a href='/login'>Login</a> | <a href='/logout'>Logout</a>
        <hr>
        <h3>Actions</h3>
        <ul>
            <li><a href='/public'>Public Feature</a> (Everyone)</li>
            <li><a href='/admin'>Admin Panel</a> (Managers Only)</li>
        </ul>
        <ul>{claimsHtml}</ul>
        
        <span>Manager: {isManager}</span>
        <h3>Raw Token</h3>
        <textarea rows='4' cols='80'>{idTokenString}</textarea>
        
    </body>";
    
    return Results.Content(html, "text/html");
});

// --- PROTECTED ENDPOINTS ---

// Accessible by anyone logged in
app.MapGet("/public", () => Results.Content($@"
    <body style='font-family: sans-serif; padding: 50px;'>
        <h1>Application: {Environment.GetEnvironmentVariable("CLIENT_ID")}</h1>
        <h2>I am public data.</h2>
        <hr>
        <a href='/'>Home</a>
        <hr>
    </body>","text/html"));

// Accessible ONLY by users with 'manager' role
app.MapGet("/admin", () => Results.Content($@"
    <body style='font-family: sans-serif; padding: 50px;'>
        <h1>Application: {Environment.GetEnvironmentVariable("CLIENT_ID")}</h1>
        <h2>Welcome to the secret Admin bunker!</h2>
        <hr>
        <a href='/'>Home</a>
        <hr>
    </body>","text/html"))
   .RequireAuthorization(p => p.RequireRole("manager"));

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

app.MapGet("/access-denied", (HttpContext context) =>
{
    var user = context.User.Identity?.Name ?? "Unknown";
    
    var html = $@"
    <body style='font-family: sans-serif; padding: 50px; background-color: #fff3cd; text-align: center;'>
        <h1 style='color: #856404;'>🚫 Access Denied</h1>
        <p>Sorry <b>{user}</b>, you do not have the required permissions to view this page.</p>
        <hr>
        <a href='/' style='padding: 10px 20px; background: #333; color: white; text-decoration: none; border-radius: 5px;'>Go Home</a>
        <span style='margin: 0 10px;'>or</span>
        <a href='/logout' style='color: #333;'>Logout & Switch User</a>
    </body>";

    context.Response.StatusCode = 403; // Keep the status code semantic
    return Results.Content(html, "text/html");
});

app.Run($"http://0.0.0.0:{appPort}");