# The Magic of SSO: Connecting Microservices with Keycloak, Redis, and OIDC
In our previous labs, we secured a single application. But in the real world, an organization has dozens of apps (HR, Payroll, Chat, Wiki). Users hate managing dozens of passwords, and Security teams hate it even more.

## The Solution: Single Sign-On (SSO).

The user authenticates with a central **Identity Provider (IdP).** The IdP gives the user a "Session". When the user visits App B, App C, or App D, the IdP recognizes the session and logs them in automatically.

### The Core Concept
Single Sign-On (SSO) allows a user to log in once (at the Identity Provider) and gain access to multiple independent applications without re-entering credentials.

#### The Identity Protocols
- **OIDC (OpenID Connect):** The modern standard (JSON/REST). Used by Google, Microsoft, and modern Enterprise apps. We will use this.
- **SAML 2.0 (Security Assertion Markup Language):** The legacy standard (XML). Dominant in government and old enterprise systems. Harder to implement.
- **CAS (Central Authentication Service):** Common in higher education, ticket-based.

##### A Quick Comparison
Before we build, you need to know what runs the world.

|Protocol|Type|Age|Format|Use Case|
|---|---|---|---|---|
|**OIDC (OpenID Connect)**|Modern|~2014|**JSON (JWT)**|	**The Winner.** Web Apps, Mobile Apps, SPAs, Microservices. Built on OAuth 2.0.|
|**SAML 2.0**|Legacy|~2005|**XML**|	Enterprise "Big Iron", Government, Old Corporate Intranets. Very verbose and complex.|
|**CAS**|Academic|~2002|Ticket|Universities (Yale, etc.). Slowly fading.|

**We will use OIDC**, as it is the native language of the modern cloud.

In this lab, we will deploy a **Micro-PaaS** consisting of:
1. **Keycloak:** The Central IdP.
2. **Redis:** A high-performance key-value store to hold user sessions (making our apps stateless).
3. **App 1 & App 2:** Two separate .NET Web Apps that share the same Login State.
---

## Phase 1: The Infrastructure (Redis & Keycloak)
We need a shared network and our backing services.
### 1. Create Network
```bash
podman network create sso-net
```
### 2. Launch Redis (The Session Store)

We use Redis so that if we restart our App containers, the users stay logged in.
```bash
podman run -d --name redis-session \
  --network sso-net \
  redis:alpine
```
### 3. Launch Keycloak (The IdP)
```bash
podman run -d --name keycloak \
  --network sso-net \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:24.0.1 \
  start-dev
```
## Phase 2: Configure Keycloak (The One-Time Setup)
We need to tell Keycloak about our two separate applications.
1. Login: `http://localhost:8080` (admin/admin).
2. Create Realm: Name it `sso-realm`.
3. Create User: Name: `employee`, Password: `password123`.
4. Create Client 1 (App A):
    1. Client ID: `app-a`
    2. Valid Redirect URIs: `http://localhost:8081/signin-oidc`
    3. Valid post logout redirect URIs: `http://localhost:8081/signout-callback-oidc`
    4. Save.
5. Create Client 2 (App B):
    1. Client ID: `app-b`
    2. Valid Redirect URIs: `http://localhost:8082/signin-oidc`
    3. Valid post logout redirect URIs: `http://localhost:8082/signout-callback-oidc`
    4. Save.
    
Note: `signin-oidc` is the default callback route for the .NET OIDC middleware.
## Phase 3: The Universal Client Code (.NET)
Instead of writing two apps, we will write one "Cloud Native" app that configures itself based on Environment Variables. We will run this same image twice on different ports.
### 1. The Application Code (`Program.cs`)
Create `SingleSignOn` folder.
Create `src` folder within `SingleSignOn`. Create a minimal web project from within the src folder.
```bash
cd src
dotnet new web -n app -o .
```
We are going to use `SignOutAsync`,`OpenIdConnectResponseType` and authentication schemes from `Microsoft.AspNetCore.Authentication.OpenIdConnect` nuget package. Add them now.
We are also going to use `AddStackExchangeRedisCache` from `Microsoft.Extensions.Caching.StackExchangeRedis` nuget package. Add them now.
```bash
dotnet add package Microsoft.AspNetCore.Authentication.OpenIdConnect
dotnet add package Microsoft.Extensions.Caching.StackExchangeRedis
dotnet add package Microsoft.AspNetCore.DataProtection.StackExchangeRedis
```
Replace the entire content of `Program.cs` with the content below. This code persists **Security Keys** to redis(visible as `DataProtection-Keys`) and enables **session state**(visible as `aap-a_...`) This code integrates `StackExchange.Redis` to store the localized session data.
```csharp
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

// --- 2. REDIS CONNECTION ---
var redisConn = "redis-session:6379";
var redis = ConnectionMultiplexer.Connect(redisConn);

// --- 3. DATA PROTECTION (The "Keys") ---
// This stores the encryption keys in Redis. 
// If App A restarts, it downloads these keys and can still read your old cookies.
builder.Services.AddDataProtection()
    .PersistKeysToStackExchangeRedis(redis, "DataProtection-Keys")
    .SetApplicationName("UniqueSsoMesh"); // Shared name so apps can share cookies if needed

// --- 4. SESSION STATE (The "Data") ---
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

// --- 5. OIDC CONFIGURATION ---
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
```
### 2. The Containerfile
```dockerfile
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY src/* /src/
WORKDIR /src
RUN dotnet restore
# Do not generate assembly info and target framework attributes during publish to avoid issues with the build cache.
RUN dotnet publish -c Release /p:GenerateAssemblyInfo=false /p:GenerateTargetFrameworkAttribute=false -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app .
ENTRYPOINT ["dotnet", "app.dll"]
```
## Phase 4: Deploy the "Mesh"
We will build the image once, then run it twice with different configurations.
```bash
# 1. Build the Universal Client
podman build -t sso-client .

# 2. Run App A (Port 8081, Blue)
podman run -d --name app-a \
  --network sso-net \
  -p 8081:8081 \
  -e CLIENT_ID=app-a \
  -e APP_PORT=8081 \
  sso-client

# 3. Run App B (Port 8082, Pink)
podman run -d --name app-b \
  --network sso-net \
  -p 8082:8082 \
  -e CLIENT_ID=app-b \
  -e APP_PORT=8082 \
  sso-client
```
### Phase 5: The Walkthrough (The SSO Magic)
#### Step 1: Login to App A
1. Open browser to `http://localhost:8081` (The Blue App).
2. You are "Guest". Click **Login**.
3. You are redirected to Keycloak.
4. Login with `employee / password123`.
5. **Result:** You are back at App A. "User: employee".
#### Step 2: The Magic (App B)
1. Open a new tab to `http://localhost:8082` (The Pink App).
2. You are "Guest". Click **Login**.
3. **Watch closely.** The browser redirects to Keycloak. Keycloak checks its own cookie. It sees "Oh, this is employee, they are already here." It immediately redirects you back to App B.
4. **Result:** You are logged in to App B **without entering a password**.
#### Step 3: Redis Verification
If you inspect the `redis-session` container, you will see keys created for the session states, ensuring that even if we crash and restart App A, the user's session context (within the validity window) can be preserved or managed efficiently. Because DataProtection-Keys is in Redis, the new container accepts the old cookie. You can verify user activity by checking the app-a_ keys.
```bash
# Find keys
podman exec -it redis-session redis-cli KEYS "*"
# Check the type
podman exec -it redis-session redis-cli TYPE app-a_...
# Result: It should say hash. If it says string, use GET. If it says hash, use HGETALL
# You will not see the plain text "LastActive". You will see binary data represented as hex or escape sequences.
podman exec -it redis-session redis-cli HGETALL app-a_...
```
ASP.NET Core serializes the Session Dictionary into a binary format for efficiency before sending it to Redis. The fact that you see a data field with content proves that persistence is working.


## Conclusion
You have implemented the "Holy Grail" of corporate identity.
1. **Centralized Auth:** Keycloak handles the passwords. App A and App B never see them.
2. **Seamless UX:** The user logs in once and glides between applications.
3. **Stateless Apps:** Using Redis allows our apps to scale horizontally without losing user sessions.