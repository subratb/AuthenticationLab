# Role-Based Access Control (RBAC)
We have solved `Identity` (Who are you?), but we haven't solved `Authority` (What are you allowed to do?). In the real world, "Alice" might be an Admin, while "Bob" is just a Viewer. This is `Role-Based Access Control (RBAC)`.

In this exercise, we will configure Keycloak to assign roles to users and update our .NET apps to enforce those roles using the `[Authorize]` attribute.

## The Architecture of Authority

### The Concept:

1. **Keycloak ( The Source):** Defines roles (`manager`, `employee`) and assigns them to users.
2. **The Token (The Courier):**  Carries these roles inside the JWT (JSON Web Token).
3. **The App (The Enforcer):** Reads the token, extracts the roles, and unlocks features.

The "Shape" Problem:

By default, Keycloak nests roles deep inside the JSON token (`realm_access.roles`). ASP.NET Core expects roles to be flat (`roles`). We will fix this using a **Protocol Mapper** in Keycloak, so we don't have to write complex parsing code.

### Phase 1: The Infrastructure (Podman)
We need a custom network so our containers can talk to each other using internal DNS names (keycloak, client-app).

#### 1. Create the Network
```bash
podman network create rbac-net
```
#### 2. Launch Redis (The Session Store)

We use Redis so that if we restart our App containers, the users stay logged in.
```bash
podman run -d --name redis-session \
  --network rbac-net \
  redis:alpine
```
#### 3. Launch Keycloak
We use the official image. We set the admin credentials to admin:admin.
```bash
podman run -d --name keycloak \
  --network rbac-net \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:24.0.1 \
  start-dev
```
Note: Keycloak is heavy (Java-based). Give it 30-60 seconds to boot.
#### 4. Configure Keycloak (The Browser Setup)
We need to tell Keycloak about our application. 
1. Open http://localhost:8080 in your browser.
2. Click **Administration Console** and login (admin / admin).
3. **Create Realm:** Hover over "Master" (top left) -> **Create Realm** -> Name: `rbac-realm` -> Create.
4. Create Client (client-app):
    1. Client ID: `client-app`
    2. Valid Redirect URIs: `http://localhost:8081/signin-oidc`
    3. Valid post logout redirect URIs: `http://localhost:8081/signout-callback-oidc`
    4. Save.

We will create a "Manager" role and give it to our `employee` user.

5. **Create Role:** In the left menu, click **Realm roles** -> **Create Role** -> Name: `manager` -> Save.
6. **Create User:** Users -> Add user -> Username: `employee` -> Email: employee@test.com -> Firstname: employee -> Lastname: employee -> EmailVerified -> Yes -> Create.
    1. **Set Password:** Credentials Tab -> Set Password -> `password123` (Turn off "Temporary").
    2. **Role mapping:** Click on Role mapping tab -> Click **Assign role** -> Search `manager` -> check the box -> click **Assign**

We must tell Keycloak to put the roles where .NET can find them.

7. The Magic Mapper (Crucial)
    1. Go to **Client scopes** in the left menu.
    2. Click on the `roles` scope (it's a default scope).
    3. Click the **Mappers** tab.
    4. Click **Add mapper -> By configuration**.
    5. Select **User Realm Role**.
    6. **Configure it strictly:**
        1. **Name**: `dotnet-roles-flat`
        2. **Token Claim Name**: `roles` (This matches our C# config)
        3. **Claim JSON Type**: `String`
        4. **Multivalued**: `On` (Important!)
        5. **Add to ID token**: `On`
        6. **Add to access token**: `On`
    7. Click **Save**.

#### 5. The Application Code (`Program.cs`)
Create `RBAC` folder.
Create `src` folder within `RBAC`. Create a minimal web project from within the src folder.
```bash
cd src
dotnet new web -n rbac -o .
```
We are going to use `SignOutAsync`,`OpenIdConnectResponseType` and authentication schemes from `Microsoft.AspNetCore.Authentication.OpenIdConnect` nuget package. Add them now.

We are also going to use `AddStackExchangeRedisCache` from `Microsoft.Extensions.Caching.StackExchangeRedis` nuget package. Add them now.

We are also going to use `PersistKeysToStackExchangeRedis` from `Microsoft.AspNetCore.DataProtection.StackExchangeRedis` nuget package. Add them now.
```bash
dotnet add package Microsoft.AspNetCore.Authentication.OpenIdConnect
dotnet add package Microsoft.Extensions.Caching.StackExchangeRedis
dotnet add package Microsoft.AspNetCore.DataProtection.StackExchangeRedis
```
Replace the entire content of `Program.cs` with the content below. We need to update our app to check for this new role. We will add a "Manager Only" button and a protected API endpoint.
```csharp
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
```
#### 6. The Containerfile
Save this as `Containerfile.rbac` in `RBAC` folder.
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
ENTRYPOINT ["dotnet", "rbac.dll"]
```

## Phase 2: Deploy the "Mesh"
```bash
# 1. Build the Universal Client
podman build -t rbac-client -f Containerfile.rbac

# 2. Run App A (Port 8081, Blue)
podman run -d --name client-app \
  --network rbac-net \
  -p 8081:8081 \
  -e CLIENT_ID=client-app \
  -e APP_PORT=8081 \
  rbac-client
```

## Phase 3: Verification
Let's test the security boundaries.
1. The Manager Test

    1. Go to `http://localhost:8081`.
    2. Login as `employee` (Password: `password123`).
    3. **Observe**: You see the **MANAGER** badge.
    4. Click **Admin Panel**.
    5. **Result**: You see "Welcome to the secret Admin bunker!".

2. The User Test (Negative Test)
To be sure, we should create a user without the role.

    1. Go to Keycloak Admin -> Users -> Add User (`intern`).
    2. Set password for `intern`.
    3. **Do NOT** assign the `manager` role.
    4. Login to client-app as `intern`.
    5. **Observe**: No Gold Badge.
    6. Click **Admin Panel**.
    9. **Result**: `403 Forbidden` (Access Denied).

## Summary
You have now implemented the "Big 3" of Identity:

    1. **Authentication (OIDC)**: "I am Alice."
    2. **Session Management (Redis)**: "Alice is still here."
    3. **Authorization (RBAC)**: "Alice is allowed to be here."