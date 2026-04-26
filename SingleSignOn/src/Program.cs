using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

// Internal URL: How the Container talks to Keycloak
var REALM_URL_INTERNAL = "http://keycloak:8080/realms/sso-realm"; 
// External URL: How YOUR BROWSER talks to Keycloak
var REALM_URL_EXTERNAL = "http://localhost:8080/realms/sso-realm"; 

// --- 1. LOAD ENV VARS ---
// We read the Client ID and Port from the environment
var clientId = Environment.GetEnvironmentVariable("CLIENT_ID") ?? "app-a";
var appPort = Environment.GetEnvironmentVariable("APP_PORT") ?? "8081";

// --- 2. REDIS SESSION STORE ---
// In a real cluster, we store keys in Redis so scaling works.
builder.Services.AddStackExchangeRedisCache(options => {
    options.Configuration = "redis-session:6379"; // Connects to container name 'redis-session'
    options.InstanceName = $"{clientId}_";
});

// --- 3. OIDC CONFIGURATION ---
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
    // Where is Keycloak? (Internal Docker Network)
    options.Authority = REALM_URL_INTERNAL;
    
    // Browser needs to see this URL (External Localhost)
    options.MetadataAddress = $"{REALM_URL_EXTERNAL}/.well-known/openid-configuration";
    options.RequireHttpsMetadata = false;    

    options.ClientId = clientId;
    options.ClientSecret = ""; // Public Client (No secret needed for Code Flow usually)
    options.ResponseType = OpenIdConnectResponseType.Code;
    
    options.SaveTokens = true;
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    
    // Docker Token Validation Hack
    options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
    {
        ValidateIssuer = false 
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.UseDeveloperExceptionPage();

// --- UI ---
app.MapGet("/", async (HttpContext context) =>
{
    var user = context.User.Identity?.IsAuthenticated == true 
        ? context.User.Identity.Name 
        : "Guest";

    var style = clientId == "app-a" ? "background-color: #e3f2fd;" : "background-color: #fce4ec;";
    
    var html = $@"
    <body style='font-family: sans-serif; padding: 50px; {style}'>
        <h1>Application: {clientId.ToUpper()}</h1>
        <h2>User: {user}</h2>
        <hr>
        <a href='/login'>Login (SSO)</a> | 
        <a href='/logout'>Logout</a>
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

app.MapGet("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    await context.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
});

app.Run($"http://0.0.0.0:{appPort}");