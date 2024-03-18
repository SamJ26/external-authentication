using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace ExternalLogin;

public sealed class GoogleOAuthHandler : OAuthHandler<GoogleOptions>
{
    private readonly OAuthConfigurationManager _oAuthConfigurationManager;

    [Obsolete("ISystemClock is obsolete, use TimeProvider on AuthenticationSchemeOptions instead.")]
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

    protected override async Task<AuthenticationTicket> CreateTicketAsync(
        ClaimsIdentity identity,
        AuthenticationProperties properties,
        OAuthTokenResponse tokens)
    {
        // Get the Google user
        var request = new HttpRequestMessage(HttpMethod.Get, Options.UserInformationEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);

        var response = await Backchannel.SendAsync(request, Context.RequestAborted);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"An error occurred when retrieving Google user information ({response.StatusCode}). Please check if the authentication information is correct.");
        }

        using (var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Context.RequestAborted)))
        {
            var context = new OAuthCreatingTicketContext(
                new ClaimsPrincipal(identity),
                properties,
                Context,
                Scheme,
                Options,
                Backchannel,
                tokens,
                payload.RootElement);

            context.RunClaimActions();
            await Events.CreatingTicket(context);

            return new AuthenticationTicket(context.Principal!, context.Properties, Scheme.Name);
        }
    }

    protected override async Task<OAuthTokenResponse> ExchangeCodeAsync(OAuthCodeExchangeContext context)
    {
        var tokenRequestParameters = new Dictionary<string, string>()
        {
            { "client_id", _oAuthConfigurationManager.GetClientId() },
            { "redirect_uri", context.RedirectUri },
            { "client_secret", _oAuthConfigurationManager.GetClientSecret() },
            { "code", context.Code },
            { "grant_type", "authorization_code" },
        };

        // PKCE https://tools.ietf.org/html/rfc7636#section-4.5, see BuildChallengeUrl
        if (context.Properties.Items.TryGetValue(OAuthConstants.CodeVerifierKey, out var codeVerifier))
        {
            tokenRequestParameters.Add(OAuthConstants.CodeVerifierKey, codeVerifier!);
            context.Properties.Items.Remove(OAuthConstants.CodeVerifierKey);
        }

        var requestContent = new FormUrlEncodedContent(tokenRequestParameters!);

        var requestMessage = new HttpRequestMessage(HttpMethod.Post, Options.TokenEndpoint);
        requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        requestMessage.Content = requestContent;
        requestMessage.Version = Backchannel.DefaultRequestVersion;
        var response = await Backchannel.SendAsync(requestMessage, Context.RequestAborted);
        var body = await response.Content.ReadAsStringAsync(Context.RequestAborted);

        return response.IsSuccessStatusCode switch
        {
            true => OAuthTokenResponse.Success(JsonDocument.Parse(body)),
            false => OAuthTokenResponse.Failed(GetStandardErrorException(JsonDocument.Parse(body)))
        };
    }

    private static Exception GetStandardErrorException(JsonDocument response)
    {
        var root = response.RootElement;
        var error = root.GetString("error");
        if (error is null)
        {
            return null!;
        }

        var result = new StringBuilder("OAuth token endpoint failure: ");
        result.Append(error);

        if (root.TryGetProperty("error_description", out var errorDescription))
        {
            result.Append(";Description=");
            result.Append(errorDescription);
        }

        if (root.TryGetProperty("error_uri", out var errorUri))
        {
            result.Append(";Uri=");
            result.Append(errorUri);
        }

        var exception = new AuthenticationFailureException(result.ToString())
        {
            Data =
            {
                ["error"] = error,
                ["error_description"] = errorDescription.ToString(),
                ["error_uri"] = errorUri.ToString()
            }
        };

        return exception;
    }

    protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
    {
        // Google Identity Platform Manual:
        // https://developers.google.com/identity/protocols/OAuth2WebServer

        // Some query params and features (e.g. PKCE) are handled by the base class but some params have to be modified or added here
        var queryStrings = QueryHelpers.ParseQuery(new Uri(base.BuildChallengeUrl(properties, redirectUri)).Query);

        // Override client_id with value obtained from the database
        var clientId = _oAuthConfigurationManager.GetClientId();
        SetQueryParam(queryStrings, properties, "client_id", clientId);

        SetQueryParam(queryStrings, properties, OAuthChallengeProperties.ScopeKey, FormatScope, Options.Scope);
        SetQueryParam(queryStrings, properties, GoogleChallengeProperties.AccessTypeKey, Options.AccessType);
        SetQueryParam(queryStrings, properties, GoogleChallengeProperties.ApprovalPromptKey);
        SetQueryParam(queryStrings, properties, GoogleChallengeProperties.PromptParameterKey);
        SetQueryParam(queryStrings, properties, GoogleChallengeProperties.LoginHintKey);
        SetQueryParam(queryStrings, properties, GoogleChallengeProperties.IncludeGrantedScopesKey,
            v => v?.ToString(CultureInfo.InvariantCulture).ToLowerInvariant(), (bool?)null);

        // Some properties are removed when setting query params above, so the state has to be reset
        queryStrings["state"] = Options.StateDataFormat.Protect(properties);

        return QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, queryStrings);
    }
    
    private static void SetQueryParam<T>(
        IDictionary<string, StringValues> queryStrings,
        AuthenticationProperties properties,
        string name,
        Func<T, string?> formatter,
        T defaultValue)
    {
        string? value;
        var parameterValue = properties.GetParameter<T>(name);
        if (parameterValue != null)
        {
            value = formatter(parameterValue);
        }
        else if (!properties.Items.TryGetValue(name, out value))
        {
            value = formatter(defaultValue);
        }

        // Remove the parameter from AuthenticationProperties so it won't be serialized into the state
        properties.Items.Remove(name);

        if (value != null)
        {
            queryStrings[name] = value;
        }
    }

    private static void SetQueryParam(
        IDictionary<string, StringValues> queryStrings,
        AuthenticationProperties properties,
        string name,
        string? defaultValue = null)
        => SetQueryParam(queryStrings, properties, name, x => x, defaultValue);
}