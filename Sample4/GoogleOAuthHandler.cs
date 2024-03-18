using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.Extensions.Options;

namespace ExternalLogin;

public sealed class GoogleOAuthHandler : GoogleHandler
{
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
        Options.ClientId = _oAuthConfigurationManager.GetClientId();
        Options.ClientSecret = _oAuthConfigurationManager.GetClientSecret();

        return Task.CompletedTask;
    }
}