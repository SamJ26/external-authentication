namespace ExternalLogin;

public sealed class OAuthConfigurationManager(IConfiguration configuration)
{
    private readonly IConfiguration _configuration = configuration;

    public OAuthConfiguration GetConfiguration(string tenant)
    {
        // Here we would load configuration from database based on value of the tenant parameter

        return new OAuthConfiguration(
            ClientId: _configuration["Authentication:Google:ClientId"]!,
            ClientSecret: _configuration["Authentication:Google:ClientSecret"]!);
    }
}

public record OAuthConfiguration(
    string ClientId,
    string ClientSecret);