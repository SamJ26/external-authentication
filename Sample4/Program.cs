using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace ExternalLogin;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        {
            var services = builder.Services;

            services.AddDbContext<AppDbContext>(options => options.UseInMemoryDatabase("app_db"));

            services
                .AddIdentity<IdentityUser, IdentityRole>()
                .AddEntityFrameworkStores<AppDbContext>();

            services
                .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie()
                // GoogleOAuthHandler is custom authentication handler which supports dynamic OAuth configuration.
                .AddOAuth<GoogleOptions, GoogleOAuthHandler>("Google", GoogleDefaults.DisplayName, options =>
                {
                    // Real configuration values are loaded using OAuthConfigurationManager during runtime.
                    options.ClientId = "...";
                    options.ClientSecret = "...";
                });

            services.AddTransient<OAuthConfigurationManager>();

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
        const string tenant = "TENANT";

        // We need to specify tenant in callback URI
        var authenticationProperties = signInManager.ConfigureExternalAuthenticationProperties("Google", $"/callback?tenant={tenant}");

        // We need to add tenant information into authentication properties to be able to load proper OAuth configuration during authentication flow
        authenticationProperties.Items.Add("tenant", tenant);

        return Results.Challenge(authenticationProperties, authenticationSchemes: ["Google"]);
    }

    private static async Task<IResult> SignInCallback(
        [FromQuery] string tenant,
        [FromServices] ILogger<Program> logger,
        [FromServices] SignInManager<IdentityUser> signInManager,
        [FromServices] UserManager<IdentityUser> userManager)
    {
        logger.LogInformation("Current tenant: {tenant}", tenant);

        // Get user info from external login provider.
        var info = await signInManager.GetExternalLoginInfoAsync();
        if (info is null)
        {
            throw new Exception("Unable to load user info from Google login provider");
        }

        // Sign in the user with this external login provider if the user already has a login.
        var result = await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
        if (result.Succeeded)
        {
            throw new Exception("Unable to sign in user with Google login provider");
        }

        if (result.IsLockedOut)
        {
            throw new Exception("Unable to sign in user because account is locked out");
        }

        // If the user does not have an account, then ask the user to create an account.
        var user = new IdentityUser
        {
            UserName = string.Concat(info.Principal.Identity?.Name?.Split(" ")!),
            Email = info.Principal.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value
        };

        IdentityResult identityResult;

        identityResult = await userManager.CreateAsync(user);
        if (identityResult.Succeeded)
        {
            identityResult = await userManager.AddLoginAsync(user, info);
            if (identityResult.Succeeded)
            {
                await signInManager.SignInAsync(user, isPersistent: false);

                logger.LogInformation("Created and signed-in new user with id {UserId}.", user.Id);

                // Here you can start email confirmation process by sending an email to specified address.

                return Results.Redirect("/");
            }
        }

        return Results.BadRequest(identityResult.Errors);
    }
}