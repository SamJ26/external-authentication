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

                    // WARNING: this must be set to true to be able to hit callback endpoint specified by AuthenticationProperties.RedirectUri
                    options.SaveTokens = true;
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
                RedirectUri = "/callback"
            },
            authenticationSchemes: ["Google"]));

        app.MapGet("/callback", (HttpContext httpContext) =>
        {
            Console.WriteLine("Hello from callback");

            // In here, we can do whatever we want with user info

            return Results.Redirect("/");
        });

        app.Run();
    }
}