using System.IdentityModel.Tokens.Jwt;
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

    // B. Extract the ID Token
    var idTokenString = jsonNode?["id_token"]?.ToString();
    
    if (string.IsNullOrEmpty(idTokenString))
        return Results.Content("Error: No ID Token. Did you include 'openid' in the scope?");

    // C. Decode the ID Token (The "Passport")
    var handler = new JwtSecurityTokenHandler();
    var jwt = handler.ReadJwtToken(idTokenString);

    // D. Display the Claims
    var claimsHtml = string.Join("", jwt.Claims.Select(c => $"<li><b>{c.Type}:</b> {c.Value}</li>"));

    // 3. Show Results
    var html = $@"
        <h1>OAuth Complete</h1>
        <h3>Step 1: The Key (Access Token)</h3>
        <textarea rows='5' cols='80'>{accessToken}</textarea>
        
        <h3>Step 2: The Vault (Resource API Response)</h3>
        <pre style='background: #f4f4f4; padding: 10px; border: 1px solid #ccc;'>{apiData}</pre>

        <h1>Authentication Successful</h1>
        <h3>User Profile (From ID Token)</h3>
        <ul>{claimsHtml}</ul>
        <hr>
        <h3>Raw Token</h3>
        <textarea rows='4' cols='80'>{idTokenString}</textarea>
        
        <p>Authentication: Keycloak (8080) -> Client (8081) -> API (8082)</p>
    ";

    return Results.Content(html, "text/html");
});

app.Run("http://0.0.0.0:8081");