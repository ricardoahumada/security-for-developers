# Pattern 3: .NET Core Implementation

```csharp
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json.Linq;

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(options =>
            {
                options.LoginPath = "/Account/Login";
                options.LogoutPath = "/Account/Logout";
            })
            .AddOAuth("Google", options =>
            {
                options.ClientId = Configuration["Google:ClientId"];
                options.ClientSecret = Configuration["Google:ClientSecret"];
                options.CallbackPath = "/signin-google";
                
                options.AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
                options.TokenEndpoint = "https://oauth2.googleapis.com/token";
                options.UserInformationEndpoint = "https://www.googleapis.com/oauth2/v2/userinfo";
                
                options.SaveTokens = true;
                options.UsePkce = true;
                
                options.Scope.Clear();
                options.Scope.Add("openid");
                options.Scope.Add("email");
                options.Scope.Add("profile");
                
                options.Events = new OAuthEvents
                {
                    OnCreatingTicket = async context =>
                    {
                        // Get user information
                        using (var client = new HttpClient())
                        {
                            var response = await client.GetAsync(context.Options.UserInformationEndpoint,
                                context.HttpContext.RequestAborted);
                            
                            if (response.IsSuccessStatusCode)
                            {
                                var user = JObject.Parse(await response.Content.ReadAsStringAsync());
                                
                                context.RunClaimActions(user);
                            }
                        }
                    },
                    
                    OnRedirectToAuthorizationEndpoint = context =>
                    {
                        // Add custom state parameter if needed
                        context.RedirectUri = context.RedirectUri + "&state=custom_state";
                        return Task.CompletedTask;
                    }
                };
            });
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        app.UseRouting();
        
        app.UseAuthentication();
        app.UseAuthorization();
        
        app.UseEndpoints(endpoints =>
        {
            endpoints.MapGet("/", async context =>
            {
                if (context.User?.Identity?.IsAuthenticated ?? false)
                {
                    var email = context.User.FindFirst("email")?.Value;
                    var name = context.User.FindFirst("name")?.Value;
                    
                    await context.Response.WriteAsync($@"
                        <html>
                            <body>
                                <h1>Welcome {name}!</h1>
                                <p>Email: {email}</p>
                                <a href='/Account/Logout'>Logout</a>
                            </body>
                        </html>");
                }
                else
                {
                    await context.Response.WriteAsync($@"
                        <html>
                            <body>
                                <h1>OAuth 2.0 Demo</h1>
                                <a href='/Account/LoginGoogle'>Login with Google</a>
                            </body>
                        </html>");
                }
            });
        });
    }
}

[Route("[controller]")]
public class AccountController : Controller
{
    [HttpGet("LoginGoogle")]
    public IActionResult LoginGoogle()
    {
        var redirectUri = Url.Action("GoogleCallback", "Account", null, Request.Scheme);
        return Challenge(new AuthenticationProperties { RedirectUri = redirectUri }, "Google");
    }
    
    [HttpGet("GoogleCallback")]
    public async Task<IActionResult> GoogleCallback()
    {
        // Authentication has been handled by the middleware
        return Redirect("/");
    }
    
    [HttpGet("Logout")]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync();
        return Redirect("/");
    }
}
```