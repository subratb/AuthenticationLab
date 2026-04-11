var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// 1. Serve Static Files (The Vulnerable Frontend)
// We manually serve the HTML to keep this a single-file example
app.MapGet("/", async (context) => {
    context.Response.ContentType = "text/html";
    await context.Response.WriteAsync(@"
    <!DOCTYPE html>
    <html>
    <head>
        <title>Super Secret Stock Ticker</title>
    </head>
    <body>
        <h1>Market Status: <span id='status'>Loading...</span></h1>
        
        <script>
            // TODO: Rotate this key before production deployment!
            // DEVELOPER NOTE: Do not commit this to GitHub... oops.
            const API_KEY = 'sk_live_89238472_critical_infrastructure';
            const ENDPOINT = '/api/stocks';

            async function getStocks() {
                const response = await fetch(ENDPOINT, {
                    headers: {
                        'x-api-key': API_KEY
                    }
                });
                
                if(response.ok) {
                    const data = await response.json();
                    document.getElementById('status').innerText = data.message;
                } else {
                    document.getElementById('status').innerText = 'Auth Failed';
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
    // Validate the API Key Header
    string apiKey = context.Request.Headers["x-api-key"];

    if (apiKey == "sk_live_89238472_critical_infrastructure")
    {
        return Results.Ok(new { 
            symbol = "MSFT", 
            price = 420.69, 
            message = "Authorized Access. Flag: flag{never_put_secrets_in_javascript}" 
        });
    }

    return Results.Problem("Invalid API Key", statusCode: 403);
});

app.Run("http://0.0.0.0:8082");
