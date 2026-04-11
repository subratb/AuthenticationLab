# The Glass Door: Hacking Exposed API Keys in .NET

**API Keys** are simple, powerful, and dangerous. They are typically long strings (e.g., sk_live_...) that grant a project access to a service like Google Maps, OpenAI, or Stripe.

Because they look like "configuration," developers often make a fatal mistake: **They embed them in the frontend code.**

In this lab, you will act as a malicious user analyzing a "secure" Stock Ticker application. You will discover that the security is an illusion, find the leaked key in the browser's source code, and use it to raid the API directly.

***

## The Architecture: The "Sidecar" Micro-Range

We continue using our **Podman** architecture. We will deploy a vulnerable .NET application and a Kali Linux attacker in the same pod.

- **Target (Port 8082):** A .NET Web App. It serves a frontend (HTML/JS) that fetches stock data.
- **Attacker:** Your Kali container.
- **The Vulnerability:** The API endpoint /api/stocks is protected by an x-api-key header, but the frontend JavaScript contains the key in plain text to make the call.

***

### Phase 1: Build the Target (.NET)
We will create a Single Page Application (SPA) that violates the cardinal rule of secret management: **Never send secrets to the client.**

#### 1. The Application Code (`Program.cs`)
Create `ApiKeyAuth` folder.
Create `src` folder within `ApiKeyAuth`. Save the following code into a file named `Program.cs` in `src`. It serves a static HTML page containing the vulnerability and the protected API endpoint.
```csharp
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// 1. Serve the Vulnerable Frontend
app.MapGet("/", async (context) => {
    context.Response.ContentType = "text/html";
    // simulating a React/Angular build that bundles secrets
    await context.Response.WriteAsync(@"
    <!DOCTYPE html>
    <html>
    <head>
        <title>Institutional Trading Portal</title>
        <style>body { font-family: sans-serif; background: #111; color: #0f0; }</style>
    </head>
    <body>
        <h1>Market Status: <span id='status'>Disconnected</span></h1>
        
        <script>
            // CRITICAL: The developer hardcoded the key here for convenience.
            // Any user who can load the page has this string.
            const API_KEY = 'sk_live_89238472_critical_infrastructure';
            const ENDPOINT = '/api/stocks';

            async function getStocks() {
                try {
                    const response = await fetch(ENDPOINT, {
                        headers: {
                            'x-api-key': API_KEY
                        }
                    });
                    
                    if(response.ok) {
                        const data = await response.json();
                        document.getElementById('status').innerText = 
                            `${data.symbol}: $${data.price} (Authorized)`;
                    } else {
                        document.getElementById('status').innerText = 'Access Denied';
                    }
                } catch (e) {
                    console.error(e);
                }
            }
            getStocks();
        </script>
    </body>
    </html>
    ");
});

// 2. The Protected API Endpoint
app.MapGet("/api/stocks", (HttpContext context) =>
{
    // The server correctly checks the header...
    // But it doesn't matter if the client gave the key away!
    string apiKey = context.Request.Headers["x-api-key"];

    if (apiKey == "sk_live_89238472_critical_infrastructure")
    {
        return Results.Ok(new { 
            symbol = "MSFT", 
            price = 420.69, 
            message = "Authorized Access. Flag: flag{secrets_in_js_are_public}" 
        });
    }

    return Results.Problem("Invalid API Key", statusCode: 403);
});

app.Run("http://0.0.0.0:8082");

```
#### 2. The Containerfile
Save this as `Containerfile` in `ApiKeyAuth` folder.
```dockerfile
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
RUN dotnet new web -n AuthApiKey
COPY src/Program.cs /src/AuthApiKey/Program.cs
WORKDIR /src/AuthApiKey
RUN dotnet publish -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app .
ENTRYPOINT ["dotnet", "AuthApiKey.dll"]

```
### Phase 2: Deploy the Lab
We will use Podman to spin up the environment. Run these commands in your terminal from `ApiKeyAuth` folder.
```bash
# 1. Build the Target Image
podman build -f Containerfile -t auth-apikey-target .

# 2. Create the Pod (Expose Port 8082)
podman pod create --name auth-pod -p 8082:8082

# 3. Launch the Target
podman run -d --pod auth-pod --name target-apikey auth-apikey-target

# 4. Launch the Attacker (Kali)
podman run -d --pod auth-pod --name attacker kalilinux/kali-rolling sleep infinity

```
###Phase 3: The Attack
**Scenario:** You are targeting the "Institutional Trading Portal." You want to access their premium stock API, but you don't have a subscription.

#### Step 1: Reconnaissance (View Source)

If you were using a browser, you would simply right-click and select "View Page Source." Since we are in the terminal (Kali), we will use curl to fetch the frontend code.
```bash
# Remote into Kali
podman exec -it attacker /bin/bash

# Download the HTML source
curl -s http://localhost:8082/

```
##### Analysis:
Scan the HTML output. Look for the `<script>` block. You should spot the "keys to the castle" immediately:

`const API_KEY = 'sk_live_89238472_critical_infrastructure';`

#### Step 2: Verify the Lock
Try to access the API without the key to confirm it is actually protected.
```bash
curl -v http://localhost:8082/api/stocks
# Result: 403 Forbidden "Invalid API Key"

```

#### Success!

The server responds with the financial data and your capture flag:

`flag{secrets_in_js_are_public}`

### Conclusion
You didn't need advanced hacking tools to break this authentication. You just needed to read the code the server sent you.

#### The Lesson:

Anything sent to the client browser is public information. Obfuscation and minification do **not** hide secrets.

#### The Fix (Backend for Frontend):

1. **Proxy the Request:** The frontend should call its own backend (e.g., /my-api/stocks).

2. **Inject the Secret:** The backend adds the x-api-key and forwards the request to the external service.

3. **Result:** The key never leaves the trusted server environment.