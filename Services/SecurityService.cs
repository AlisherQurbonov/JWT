using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using security.Options;

namespace security.Services;
public class SecurityService
{
    private readonly ILogger<SecurityService> _logger;
    private readonly SecurityOption _options;

    public SecurityService(
        IOptionsMonitor<SecurityOption> options,
        ILogger<SecurityService> logger)
    {
        _logger = logger;
        _options = options.CurrentValue;
    }

    public string GenerateToken(string userName, string role)
    {
        var secret = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_options.IssuerSigningKey));

        var authClaims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, userName),
                new Claim("role", role)
            };
        
        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(authClaims),
            Expires = DateTime.UtcNow.AddDays(7),
            Issuer = _options.ValidIssuer,
            Audience = _options.ValidAudience,
            SigningCredentials = new SigningCredentials(secret, SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    public bool IsValidToken(string token)
    {
        var secret = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_options.IssuerSigningKey));
        var tokenHandler = new JwtSecurityTokenHandler();
        try
        {
            var result = tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = secret
            }, out SecurityToken validatedToken);
        }
        catch
        {
            return false;
        }

        return true;
    }

    public string GetClaim(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var securityToken = tokenHandler.ReadToken(token) as JwtSecurityToken;
        return securityToken.Claims.FirstOrDefault().Value;
    }
}