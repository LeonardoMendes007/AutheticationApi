using AuthenticationApi.DTOs;

namespace AuthenticationApi.Services
{
    public interface ITokenService
    {
        public TokenDTO GenerateToken(UserDTO user);
    }
}