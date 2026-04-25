# The Valet Key: Breaking Down OAuth 2.0 with Keycloak & .NET
In the early web, if you wanted a new app to access your data (e.g., "Find friends on Gmail"), you had to give that app your **actual password**. This is the "Master Key" pattern, and it is catastrophic.

**OAuth 2.0** introduced the **"Valet Key"** pattern. You give the valet (the app) a key that can only park the car (access specific data), but cannot open the trunk (change password) or drive forever (it expires).

OAuth 2.0 is the industry standard for delegated authorization. Unlike its predecessor (OAuth 1.0a), which required complex cryptographic signing for every request, OAuth 2.0 relies on **HTTPS (TLS)** for transport security and introduces specific "Flows" (Grant Types) optimized for different devices (Server, Mobile, SPA, IoT).

In this detailed lab, we will deploy a production-grade Identity Provider (**Keycloak**), build a .NET client, and manually intercept the "Authorization Code" to understand exactly how the delegation handshake works.

### 1. OAuth 1.0 vs 2.0: Why the change?
- **OAuth 1.0a (The Cryptographic Nightmare):** Designed when HTTPS was rare. It required the client to cryptographically sign every single request with a complex HMAC-SHA1 algorithm. It was incredibly difficult to implement and debug.
- **OAuth 2.0 (The HTTPS Era):** Designed for a world where HTTPS is ubiquitous. It delegates transport security to TLS (SSL). Tokens are "Bearer" tokens (like cash)—whoever holds them can use them, so they must be protected by HTTPS. It also introduced **flows** for mobile and single-page apps, which 1.0 handled poorly.

### 2. The Architecture: The "Authorization Triangle"

We are introducing a third party to our architecture.

- **The Resource Owner:** You (the User).
- **The Client (Port 8081):** Our .NET Web App. It wants to access your data but doesn't want your password.
- **The Auth Server (Port 8080): Keycloak**. The centralized vault that holds user credentials and issues tokens.
- **The Resource Server (Port 8082):** The API holding the data (The "Bank Vault").

### 3. Keycloak Alternatives

Keycloak is the gold standard for open-source Identity and Access Management (IAM). However, many teams use alternatives:

- **SaaS (Cloud):** Auth0, Okta, Azure Entra ID (formerly AD), AWS Cognito.
- **Self-Hosted:** Authentik (Lightweight), Authelia (Simple), Ory Hydra (Headless).
- **Frameworks:** Duende IdentityServer (.NET), OpenIddict (.NET).
***
### Phase 1: The Infrastructure (Podman)
We need a custom network so our containers can talk to each other using internal DNS names (keycloak, client-app, resource-api).
#### 1. Create the Network
```bash
podman network create oauth-net
```
#### 2. Launch Keycloak
We use the official image. We set the admin credentials to admin:admin.
```bash
podman run -d --name keycloak \
  --network oauth-net \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:24.0.1 \
  start-dev
```
Note: Keycloak is heavy (Java-based). Give it 30-60 seconds to boot.
#### 3. Configure Keycloak (The Browser Setup)
Instead of a complex config file, we will configure this via the GUI.
1. Open http://localhost:8080 in your browser.
2. Click **Administration Console** and login (admin / admin).
3. **Create Realm:** Hover over "Master" (top left) -> **Create Realm** -> Name: demo-realm -> Create.
4. **Create User:** Users -> Add user -> Username: student -> Email: student@test.com -> Firstname: student -> Lastname: student -> EmailVerified -> Yes -> Create.
    1. **Set Password:** Credentials Tab -> Set Password -> password123 (Turn off "Temporary").
5. **Create Client:** Clients -> Create client.
    1. Client ID: dotnet-app.
    2. **Next** -> Capability Config: Ensure **Standard Flow** (Authorization Code) is ON.
    3. **Next** -> Valid Redirect URIs: http://localhost:8081/callback.
    4. **Save.**
### Phase 2: The Resource Server (The Bank Vault) (.NET)
This is the resource server .NET API. It has no login page. It simply accepts a Bearer Token and verifies it against Keycloak's public keys.

#### 1. The Application Code (`Program.cs`) - Resource API
Create `api` folder. Create a minimal web project from within the api folder.
```bash
cd api
dotnet new web -n ResourceApi -o .
```
We are going to use `JwtBearerDefaults` from `Microsoft.AspNetCore.Authentication.JwtBearer` nuget package. Add the package now.
```bash
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
```
Replace the entire content of `Program.cs` with the content below. It simulates a banking API and uses the JwtBearer middleware to auto-discover Keycloak's signing keys.

- **The Podman Challenge:** In production, URLs match. In Podman, the token comes from localhost (Browser), but the API talks to Keycloak via http://keycloak:8080 (Internal Network). We must configure the API to trust keys from the internal URL while accepting the external Issuer name.
```csharp
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

```
#### 2. The Containerfile (Containerfile.api)
```dockerfile
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY api/* /src/ResourceApi/
WORKDIR /src/ResourceApi
RUN dotnet publish -c Release /p:GenerateAssemblyInfo=false /p:GenerateTargetFrameworkAttribute=false -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app .
ENTRYPOINT ["dotnet", "ResourceApi.dll"]

```

### Phase 3: The Client (.NET)
We will build a "Client" app that initiates the handshake.
#### 1. The Application Code (`Program.cs`)
Create `client` folder. Create a minimal web project from within the client folder.
```bash
cd client
dotnet new web -n AuthOAuth -o .
```
Replace the content of `Program.cs` with the following code. It constructs the complex URL to redirect you to Keycloak.
```csharp
using System.Net.Http;

var builder = WebApplication.CreateBuilder(args);
// Register HttpClient services
builder.Services.AddHttpClient();
var app = builder.Build();

// CONFIGURATION
var CLIENT_ID = "dotnet-app";
// Internal URL: How the Container talks to Keycloak
var REALM_URL_INTERNAL = "http://keycloak:8080/realms/demo-realm"; 
// External URL: How YOUR BROWSER talks to Keycloak
var REALM_URL_EXTERNAL = "http://localhost:8080/realms/demo-realm"; 
var REDIRECT_URI = "http://localhost:8081/callback";
// INTERNAL URL for the Client Container to talk to the API Container
var API_URL = "http://resource-api:8082/balance";

app.MapGet("/", () => Results.Content("<h1><a href='/login'>Login with Keycloak</a></h1>", "text/html"));

// STEP 1: Redirect the User to the Auth Server
app.MapGet("/login", () =>
{
    var authUrl = $"{REALM_URL_EXTERNAL}/protocol/openid-connect/auth" +
                  $"?client_id={CLIENT_ID}" +
                  $"&response_type=code" +
                  $"&redirect_uri={REDIRECT_URI}" +
                  $"&scope=openid profile" +
                  $"&state=random_security_nonce_123"; 

    return Results.Redirect(authUrl);
});

// STEP 2: Handle the Callback (The "Handshake")
app.MapGet("/callback", async (string code, string state, IHttpClientFactory factory) =>
{
    // BACK-CHANNEL: Exchange the Code for a Token
    // The User (Browser) never sees this request. It happens server-to-server.
    var tokenUrl = $"{REALM_URL_INTERNAL}/protocol/openid-connect/token";
    
    var content = new FormUrlEncodedContent(new[]
    {
        new KeyValuePair<string, string>("grant_type", "authorization_code"),
        new KeyValuePair<string, string>("client_id", CLIENT_ID),
        new KeyValuePair<string, string>("code", code),
        new KeyValuePair<string, string>("redirect_uri", REDIRECT_URI)
    });

    var client = factory.CreateClient();
    var tokenResponse = await client.PostAsync(tokenUrl, content);
    var jsonString = await tokenResponse.Content.ReadAsStringAsync();
    
    // Quick & Dirty JSON Parse to get Access Token
    var jsonNode = System.Text.Json.Nodes.JsonNode.Parse(jsonString);
    var accessToken = jsonNode?["access_token"]?.ToString();

    if (string.IsNullOrEmpty(accessToken))
        return Results.BadRequest("Failed to get token.");

    // 2. USE THE TOKEN (Call the Vault)
    // We attach the token to the Authorization Header
    var apiClient = factory.CreateClient();
    apiClient.DefaultRequestHeaders.Authorization = 
        new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

    var apiResponse = await apiClient.GetAsync(API_URL);
    var apiData = await apiResponse.Content.ReadAsStringAsync();

    // 3. Show Results
    var html = $@"
        <h1>OAuth Complete</h1>
        <h3>Step 1: The Key (Access Token)</h3>
        <textarea rows='5' cols='80'>{accessToken}</textarea>
        
        <h3>Step 2: The Vault (Resource API Response)</h3>
        <pre style='background: #f4f4f4; padding: 10px; border: 1px solid #ccc;'>{apiData}</pre>
        
        <p>Authentication: Keycloak (8080) -> Client (8081) -> API (8082)</p>
    ";

    return Results.Content(html, "text/html");
});

app.Run("http://0.0.0.0:8081");
```
#### 2. The Containerfile (Containerfile.client)
```dockerfile
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY client/* /src/AuthOAuth/
WORKDIR /src/AuthOAuth
RUN dotnet publish -c Release /p:GenerateAssemblyInfo=false /p:GenerateTargetFrameworkAttribute=false -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app .
ENTRYPOINT ["dotnet", "AuthOAuth.dll"]
```
#### 3. Deployment
```bash
# Build & Run api (Port 8082)
podman build -f Containerfile.api -t resource-api .

# Run (Must be on the same network as Keycloak, for this exercise)
podman run -d --name resource-api \
  --network oauth-net \
  -p 8082:8082 \
  resource-api

# Build & Run Client App (Port 8081)
podman build -f Containerfile.client -t auth-client .

# Run (Must be on the same network as Keycloak, for this exercise)
podman run -d --name client-app \
  --network oauth-net \
  -p 8081:8081 \
  auth-client
```
### Phase 3: The Walkthrough (Code Interception)
The "Authorization Code" is a temporary, one-time-use secret. We will intercept it to see how it works.
#### Step 1: Initiate the Flow
Open your browser to http://localhost:8081. Click **"Login with Keycloak"**.
- **Observation:** You are redirected to localhost:8080 (Keycloak). The .NET app is no longer involved. You are strictly talking to the Auth Server.
- **Action:** Log in with student / password123.
#### Step 2: The Intercept
Keycloak will redirect you back to localhost:8081/callback.
**Look at your address bar.** You will see a URL parameter:
?code=af729c...
#### Step 3: The Exchange (What just happened?)
Your browser passed that code to the .NET app. The .NET app took that code, turned around, and messaged Keycloak (Back-Channel): "Hey Keycloak, I have a code from User 'student'. Can I have the access keys?"

If the code is valid, Keycloak responds with the JSON you see on screen:
- **access_token:** The JWT (valid for 5 min).
- **refresh_token:** The Reuse Ticket (valid for 30 min).
- **id_token:** The Identity Card (Name, Email).

The client app uses access token from this response to call the resource api to get the data it needs. The Output Should Look Like:

```json
{
  "message": "Vault Unlocked",
  "user": "student",
  "balance": "$1,000,000",
  "status": "Authorized via Keycloak"
}
```

Notice that the **Resource API (Port 8082)** does not have a database of users. It does not know the password password123. It doesn't even have a "Login" page.

It relies entirely on the **cryptographic signature** of the token. As long as Keycloak signed it, the API trusts it. This is the essence of **Microservices Security**. One Identity Provider can secure 100 different microservices without sharing user credentials with any of them.

#### Step 4: Manual Exchange (The Hacker's Perspective)
If you were an attacker and you tricked a user into clicking a malicious link that leaked their code, you could perform this exchange yourself using `curl`:
```bash
curl -X POST http://localhost:8080/realms/demo-realm/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "client_id=dotnet-app" \
  -d "redirect_uri=http://localhost:8081/callback" \
  -d "code=PASTE_THE_STOLEN_CODE_HERE"
```
Note: This only works if the code hasn't been used yet. Codes self-destruct after one use!

### Conclusion
**Why is this secure?**
1. **Password Isolation:** The .NET app never saw password123.
2. **Short-Lived Codes:** The code in the URL dies almost instantly.
3. **Back-Channel:** The actual tokens are exchanged server-to-server, never exposed in the browser URL bar.

We have successfully retrieved the tokens! However, the **Access Token** is for authorization (what you can do), not authentication (who you are). That is the responsibility of **OpenID Connect (OIDC)**, the thin identity layer that sits on top of OAuth 2.0 to standardize user profiles. We will discuss that in the next lab.