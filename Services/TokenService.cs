using AuthenticationApi.Config;
using AuthenticationApi.DTOs;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthenticationApi.Services;

public class TokenService : ITokenService
{
    private readonly string _secret;
    private readonly TokenConfiguration _tokenConfiguration;
    public TokenService(string secret, TokenConfiguration tokenConfiguration) {
        this._secret = secret;
        this._tokenConfiguration = tokenConfiguration;
    }
    public TokenDTO GenerateToken(UserDTO user)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.UniqueName, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(_secret));

        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var expiration = DateTime.UtcNow.AddHours(_tokenConfiguration.ExpireHours);

        JwtSecurityToken token = new JwtSecurityToken(
            issuer: _tokenConfiguration.Issuer,
            audience: _tokenConfiguration.Audience,
            claims: claims,
            expires: expiration,
            signingCredentials: credentials
            );


        return new TokenDTO()
        {
            Authenticated = true,
            Token = new JwtSecurityTokenHandler().WriteToken(token),
            Expiration = expiration,
            Message = "Token JWT Ok"
        };
    }
}
