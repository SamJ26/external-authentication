namespace ExternalLogin;

public sealed class OAuthConfigurationManager(IConfiguration configuration)
{
    private readonly IConfiguration _configuration = configuration;

    public string GetClientId()
    {
        // Here we could load configuration from database
        return _configuration["Authentication:Google:ClientId"]!;
    }

    public string GetClientSecret()
    {
        // Here we could load configuration from database
        return _configuration["Authentication:Google:ClientSecret"]!;
    }
}