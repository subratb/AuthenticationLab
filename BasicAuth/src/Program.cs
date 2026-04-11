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
        // Format: "Basic <Base64String>"
        var encodedValue = authHeader.Substring("Basic ".Length).Trim();
        var decodedBytes = Convert.FromBase64String(encodedValue);
        var credentials = Encoding.UTF8.GetString(decodedBytes).Split(':', 2);

        var username = credentials[0];
        var password = credentials[1];

        // 4. Verification
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
