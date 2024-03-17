using System.Net.Http.Headers;
using System.Text.Json;
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
                // We need to configure default authentication schema otherwise we will get really strange stack overflow error.
                .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                // We also need to configure second authentication schema which is set as a default schema.
                .AddCookie()
                .AddOAuth("github", options =>
                {
                    options.ClientId = configuration["Authentication:Github:ClientId"]!;
                    options.ClientSecret = configuration["Authentication:Github:ClientSecret"]!;

                    // All URLs below are from Github docs: https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
                    options.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
                    options.TokenEndpoint = "https://github.com/login/oauth/access_token";
                    options.UserInformationEndpoint = "https://api.github.com/user";

                    // This can be anything but it must match the path configured on Github.
                    // Note that this value is overriden by AuthenticationProperties.RedirectUri specified in Login endpoint.
                    // QUESTION: endpoint specified by this URL is never invoked and I do not why!
                    options.CallbackPath = "/oauth/github-callback";

                    // If true, access token and refresh token obtained from Github will be stored in the authentication cookie created as the result of the successfull authentication.
                    // Keep this set to false until you really need that.
                    options.SaveTokens = false;

                    // These mappings are used by RunClaimActions method used in event handler below.
                    options.ClaimActions.MapJsonKey("sub", "id");
                    options.ClaimActions.MapJsonKey("name", "login");

                    // Event delegate, which is invoked when creating an authentication cookie.
                    // In here, we fetch user information from Github and add these data into claims principal which is contained in the cookie.
                    options.Events.OnCreatingTicket = async (context) =>
                    {
                        // Prepare request which is going to be send to GitHub
                        using var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
                        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
                        using var response = await context.Backchannel.SendAsync(request);

                        // Process response and fill in cookie with claims for which we have specified mapping above.
                        var user = await response.Content.ReadFromJsonAsync<JsonElement>();
                        context.RunClaimActions(user);
                    };
                });

            services.AddAuthorization();
        }

        var app = builder.Build();
        {
            app.UseAuthentication();
            app.UseAuthorization();
        }

        // Returns claims of the current user
        app.MapGet("/", (HttpContext httpContext) =>
        {
            return httpContext
                .User
                .Claims
                .Select(x => new { x.Type, x.Value })
                .ToList();
        });

        // Triggers external authentication
        app.MapGet("/login", () => Results.Challenge(
            new AuthenticationProperties()
            {
                // URI where user should be redirected after successfull authentication.
                // This should be some home page of your SPA of URL of the endpoint.
                // Note that, this value overrides OAuthOptions.CallbackPath value.
                RedirectUri = "https://localhost:5056/"
            },
            authenticationSchemes: ["github"]));

        // QUESTION: this endpoint is never invoked and I do not why!
        app.MapGet("/oauth/github-callback", (HttpContext httpContext) => { Console.WriteLine("HELLO"); });

        app.Run();
    }
}