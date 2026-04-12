using System.Text;
using System.Collections.Concurrent;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// --- MOCK DATABASE & SESSION STORE ---
// The "Server Side" State
var sessions = new ConcurrentDictionary<string, string>();

// Simulate Admin logging in at server startup (Session ID "1")
// "MQ==" is Base64 for "1"
sessions["MQ=="] = "admin"; 

// Counter for new users
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

// 1. Login (Gives you a NEW predictable session)
app.MapGet("/login", (HttpContext context) =>
{
    sessionCounter++;
    string rawId = sessionCounter.ToString();
    
    // VULNERABILITY: The ID is just a number encoded in Base64
    string encodedId = Convert.ToBase64String(Encoding.UTF8.GetBytes(rawId));
    
    // Store in memory
    sessions[encodedId] = "student_user";

    // Send Cookie
    context.Response.Cookies.Append("legacy_session_id", encodedId);
    return Results.Ok(new { msg = "Logged in", role = "student_user", session_token = encodedId });
});

// 2. The Protected Admin Panel
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
