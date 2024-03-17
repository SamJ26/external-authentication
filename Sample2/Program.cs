using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace ExternalLogin;

public static class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        {
            var services = builder.Services;
            var configuration = builder.Configuration;

            services
                .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie()
                .AddGoogle(options =>
                {
                    options.ClientId = configuration["Authentication:Google:ClientId"]!;
                    options.ClientSecret = configuration["Authentication:Google:ClientSecret"]!;
                });

            services.AddAuthorization();
        }

        var app = builder.Build();
        {
            app.UseAuthentication();
            app.UseAuthorization();
        }

        app.MapGet("/", (HttpContext httpContext) =>
        {
            return httpContext
                .User
                .Claims
                .Select(x => new { x.Type, x.Value })
                .ToList();
        });

        app.MapGet("/login", () => Results.Challenge(
            new AuthenticationProperties()
            {
                RedirectUri = "https://localhost:5056/"
            },
            authenticationSchemes: ["Google"]));

        // ERROR: I am not able to hit this endpoint
        app.MapGet("/signin-google", (HttpContext httpContext) => { Console.WriteLine("HELLO"); });

        app.Run();
    }
}