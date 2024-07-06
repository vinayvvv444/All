using All.Models.User;
using System.Security.Claims;

namespace All.Contracts
{
    public interface IJwtTokenService
    {
        string GenerateAccessToken(ApplicationUser user);
        string GenerateRefreshToken();
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
    }
}
