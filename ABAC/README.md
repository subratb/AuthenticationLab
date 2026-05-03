# Attribute-Based Access Control (ABAC)

Access is granted based on subject's **attributes**. 

**Role-Based** access is based on Static Titles ("Managers can approve"). It is simple but rigid.

Whereas, **Attribute-Based** access is based on Dynamic Context ("Users can approve if they are in the 'IT' department and it is before 5 PM"). It is complex but highly flexible.

In .NET, we implement ABAC using **Policy-Based Authorization**, where we check specific claims (Attributes) inside the token rather than just checking a Role.
|Feature|RBAC (Role-Based)|ABAC (Attribute-Based)|
|---|---|---|
|Logic|Check strict membership.|Evaluate boolean logic (IF X AND Y).|
|Example|[Authorize(Roles="Admin")]|[Authorize(Policy="SeniorDev")]|
|Granularity|Coarse (Bucket-style)|Fine (Laser-focused)|
|Scaling|Role Explosion: You end up creating "US_Manager", "EU_Manager", "US_Manager_NightShift".|Efficient: You just check Country=US, Title=Manager, Shift=Night.|

We will implement a policy that allows access only if the user belongs to the Engineering department. We will not create an "Engineering" role. Instead, we will use a user Attribute.

## The Architecture of Authority

### The Concept:

1. **Keycloak ( The Source):** Defines attributes (`department`, `shift`) and assigns them to users.
2. **The Token (The Courier):**  Carries these attributes inside the JWT (JSON Web Token).
3. **The App (The Enforcer):** Reads the token, extracts the attributes, and applies policies to unlock features.

### Phase 1: The Infrastructure (Podman)
We need a custom network so our containers can talk to each other using internal DNS names (keycloak, client-app).

#### 1. Create the Network
```bash
podman network create abac-net
```
#### 2. Launch Redis (The Session Store)

We use Redis so that if we restart our App containers, the users stay logged in.
```bash
podman run -d --name redis-session \
  --network abac-net \
  redis:alpine
```
#### 3. Launch Keycloak
We use the official image. We set the admin credentials to admin:admin.
```bash
podman run -d --name keycloak \
  --network abac-net \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:24.0.1 \
  start-dev
```
Note: Keycloak is heavy (Java-based). Give it 30-60 seconds to boot.
#### 4. Keycloak Configuration (The Attribute)
We need to tell Keycloak about our application. 
1. Open http://localhost:8080 in your browser.
2. Click **Administration Console** and login (admin / admin).
3. **Create Realm:** Hover over "Master" (top left) -> **Create Realm** -> Name: `abac-realm` -> Create.
4. Create Client (client-app):
    1. Client ID: `client-app`
    2. Valid Redirect URIs: `http://localhost:8081/signin-oidc`
    3. Valid post logout redirect URIs: `http://localhost:8081/signout-callback-oidc`
    4. Save.
5. **Create User:** Users -> Add user -> Username: `employee` -> Email: employee@test.com -> Firstname: employee -> Lastname: employee -> EmailVerified -> Yes -> Create.
    1. **Set Password:** Credentials Tab -> Set Password -> `password123` (Turn off "Temporary").

We need to attach data to the user and ensure it travels in the Token. 
1. **Add the Attribute**
    1. Go to **Realm Settings -> User Profile**.
    2. Click **Create attribute** (or "Attributes" sub-tab -> Create).
    3. **Name**: `department`.
    4. **Display Name**: `Department`.
    5. **Permissions**:
        1. **Can user view?** Yes.
        2. **Can admin view?** Yes.
        3. **Can admin edit?** Yes.
        4. **Save**.
2. **Assign the Attribute**
    1. Go to **Users** -> Select `employee`.
    2. Set Department field under General to: `engineering`
    3. Click **Save**.
4. **Map to Token**
    Attributes stay hidden in the database unless we map them.
    1. Go to **Client scopes** -> `roles` (or `profile`).
    2. Click **Mappers** tab -> **Add mapper** -> **By configuration**.
    3. Select **User Attribute**.
    4. **Configure**:
        1. **Name**: `department-mapper`
        2. **User Attribute**: `department` (The key we just set)
        3. **Token Claim Name**: `department` (The key .NET will see)
        4. **Claim JSON Type**: `String`
        5. **Add to ID/Access token**: `On`
    5. Click **Save**.
    
#### The Application Code (The Policy)
Create `ABAC` folder.
Create `src` folder within `ABAC`. Create a minimal web project from within the src folder.
```bash
cd src
dotnet new web -n abac -o .
```
We are going to use `SignOutAsync`,`OpenIdConnectResponseType` and authentication schemes from `Microsoft.AspNetCore.Authentication.OpenIdConnect` nuget package. Add them now.

We are also going to use `AddStackExchangeRedisCache` from `Microsoft.Extensions.Caching.StackExchangeRedis` nuget package. Add them now.

We are also going to use `PersistKeysToStackExchangeRedis` from `Microsoft.AspNetCore.DataProtection.StackExchangeRedis` nuget package. Add them now.
```bash
dotnet add package Microsoft.AspNetCore.Authentication.OpenIdConnect
dotnet add package Microsoft.Extensions.Caching.StackExchangeRedis
dotnet add package Microsoft.AspNetCore.DataProtection.StackExchangeRedis
```
Replace the entire content of `Program.cs` with the content below. We will define a Security Policy in .NET that inspects the department claim.
```csharp
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using StackExchange.Redis;
using System.Reflection.Metadata.Ecma335;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.Security.Claims; // Needed for Claim Types

var builder = WebApplication.CreateBuilder(args);

// Internal URL: How the Container talks to Keycloak
var REALM_URL_INTERNAL = "http://keycloak:8080/realms/abac-realm"; 

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

// --- 1. DEFINE ABAC POLICIES ---
builder.Services.AddAuthorization(options =>
{
    // Policy: Must be in Engineering
    options.AddPolicy("EngineeringOnly", policy => 
        policy.RequireClaim("department", "engineering"));

    // Policy: Must be a Manager AND in Sales (Complex Logic)
    options.AddPolicy("SalesManager", policy =>
        policy.RequireRole("manager")
              .RequireClaim("department", "sales"));
});

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

    // Read the attribute manually for display
    var dept = context.User.FindFirst("department")?.Value ?? "Unknown";

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
        <h2>User: {user} {dept}</h2>
        <hr>
        <a href='/login'>Login</a> | <a href='/logout'>Logout</a>
        <hr>
        <h3>Actions</h3>
        <ul>            
            <p><a href='/blueprint'>View Blueprints</a></p>
        </ul>
        <ul>{claimsHtml}</ul>
        
        <h3>Raw Token</h3>
        <textarea rows='4' cols='80'>{idTokenString}</textarea>
        
    </body>";
    
    return Results.Content(html, "text/html");
});

// --- 2. PROTECT ENDPOINTS ---

// This uses the ABAC Policy
app.MapGet("/blueprint", (HttpContext context) => {
    var user = context.User.Identity.Name;
    // Read the attribute manually for display
    var dept = context.User.FindFirst("department")?.Value ?? "Unknown";
    
    return Results.Content($"<h1>User: {user}</h1><h2>Department: {dept}</h2><p>You have access to the Secret Blueprints.</p><p><a href='/'>Home</a></p>", "text/html");
})
.RequireAuthorization("EngineeringOnly");



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
#### The Containerfile
Save this as `Containerfile.abac` in `ABAC` folder.
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
ENTRYPOINT ["dotnet", "abac.dll"]
```

## Phase 2: Deploy the "Mesh"
```bash
# 1. Build the Universal Client
podman build -t abac-client -f Containerfile.abac

# 2. Run App A (Port 8081, Blue)
podman run -d --name client-app \
  --network abac-net \
  -p 8081:8081 \
  -e CLIENT_ID=client-app \
  -e APP_PORT=8081 \
  abac-client
```

## Phase 3: Verification
1. **The Success Case**
    1. Go to `http://localhost:8081`.
    2. Login as `employee`.
    3. Visit `/` -> You see **Department: engineering**.
    4. Visit `/blueprint` -> **Success**: "You have access..."
2. **The Failure Case**
    1. Go to Keycloak -> Users -> `employee` -> Attributes.
    2. Change `department` to `hr`.
    3. **Logout** and **Login** again (Claims are only updated on new login!).
    4. Visit `/blueprint`.
    5. **Result**: `403 Forbidden`.
    
## Summary
You have moved beyond simple Roles. You are now making decisions based on Data.

**RBAC**: "Let them in, they are a Manager."

**ABAC**: "Let them in, they are in Engineering, and have a Clearance Level of 5."


