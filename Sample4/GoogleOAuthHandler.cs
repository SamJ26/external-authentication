using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.Extensions.Options;

namespace ExternalLogin;

// This handler is created for every incomming request => InitializeHandlerAsync method is invoked for every request.
// Not every request will use functionality of this handler => for these requests, client id and client secret does not have to be valid values.
public sealed class GoogleOAuthHandler : GoogleHandler
{
    private const string InvalidClientId = "client-id";
    private const string InvalidClientSecret = "client-secret";

    private readonly OAuthConfigurationManager _oAuthConfigurationManager;

    [Obsolete("Obsolete")]
    public GoogleOAuthHandler(
        IOptionsMonitor<GoogleOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock,
        OAuthConfigurationManager oAuthConfigurationManager)
        : base(options, logger, encoder, clock)
    {
        _oAuthConfigurationManager = oAuthConfigurationManager;
    }

    public GoogleOAuthHandler(
        IOptionsMonitor<GoogleOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        OAuthConfigurationManager oAuthConfigurationManager)
        : base(options, logger, encoder)
    {
        _oAuthConfigurationManager = oAuthConfigurationManager;
    }

    protected override Task InitializeHandlerAsync()
    {
        var tenant = GetTenantFromRequest();
        if (tenant is null)
        {
            Options.ClientId = InvalidClientId;
            Options.ClientSecret = InvalidClientSecret;
        }
        else
        {
            var configuration = _oAuthConfigurationManager.GetConfiguration(tenant);
            Options.ClientId = configuration.ClientId;
            Options.ClientSecret = configuration.ClientSecret;
        }

        return Task.CompletedTask;
    }

    private string? GetTenantFromRequest()
    {
        string? tenant = null;

        if (Request.Query.TryGetValue("tenant", out var value))
        {
            tenant = value;
        }

        if (Request.Query.TryGetValue("state", out var state))
        {
            tenant = Options.StateDataFormat.Unprotect(state!)!.Items["tenant"]!;
        }

        return tenant;
    }
}