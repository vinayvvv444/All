using All.Models.jwt;

namespace All.Contracts.jwt
{
    public interface IRefreshTokenRepository
    {
        Task<RefreshToken> GetRefreshTokenAsync(string token);
        Task AddRefreshTokenAsync(RefreshToken refreshToken);
        Task RemoveRefreshTokenAsync(RefreshToken refreshToken);
    }
}
