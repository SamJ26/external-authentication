using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace ExternalLogin;

public static class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        {
            var services = builder.Services;
            var configuration = builder.Configuration;

            services.AddDbContext<AppDbContext>(options => options.UseInMemoryDatabase("app_db"));

            services
                .AddIdentity<IdentityUser, IdentityRole>()
                .AddEntityFrameworkStores<AppDbContext>();

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

        app.MapGet("/", GetUserInfo);
        app.MapGet("/login", ChallengeExternalAuthentication);
        app.MapGet("/callback", SignInCallback);

        app.Run();
    }

    private static IResult GetUserInfo(HttpContext httpContext)
    {
        return Results.Ok(httpContext
            .User
            .Claims
            .Select(x => new { x.Type, x.Value })
            .ToList());
    }

    private static IResult ChallengeExternalAuthentication([FromServices] SignInManager<IdentityUser> signInManager)
    {
        var authenticationProperties = signInManager.ConfigureExternalAuthenticationProperties("Google", "/callback");
        return Results.Challenge(authenticationProperties, authenticationSchemes: ["Google"]);
    }

    private static IResult SignInCallback(HttpContext httpContext)
    {
        Console.WriteLine("Hello from callback");

        // In here, we can do whatever we want with user info

        return Results.Redirect("/");
    }
}