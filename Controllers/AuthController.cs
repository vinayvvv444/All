using All.Contracts;
using All.Contracts.jwt;
using All.Models.jwt;
using All.Models.User;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace All.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IJwtTokenService _jwtTokenService;
        private readonly IRefreshTokenRepository _refreshTokenRepository;
        private readonly JwtSettings _jwtSettings;

        public AuthController(UserManager<ApplicationUser> userManager
            , IJwtTokenService jwtTokenService
            , IRefreshTokenRepository refreshTokenRepository
            , IOptions<JwtSettings> jwtSettings)
        {
            _userManager = userManager;
            _jwtTokenService = jwtTokenService;
            _refreshTokenRepository = refreshTokenRepository;
            _jwtSettings = jwtSettings.Value;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    return Ok(new { message = "User registered successfully" });
                }

                return BadRequest(result.Errors);
            }

            return BadRequest(ModelState);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UserModel userModel)
        {
            var user = await _userManager.FindByNameAsync(userModel.Username);
            if (user == null || !await _userManager.CheckPasswordAsync(user, userModel.Password))
            {
                return Unauthorized();
            }
            
            var accessToken = _jwtTokenService.GenerateAccessToken(user);
            var refreshToken = _jwtTokenService.GenerateRefreshToken();

            var refreshTokenEntity = new RefreshToken
            {
                Token = refreshToken,
                UserId = user.Id,
                ExpiryDate = DateTime.Now.AddDays(_jwtSettings.RefreshTokenExpirationDays)
            };

            await _refreshTokenRepository.AddRefreshTokenAsync(refreshTokenEntity);

            return Ok(new
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken
            });
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] TokenRequestModel tokenRequest)
        {
            var principal = _jwtTokenService.GetPrincipalFromExpiredToken(tokenRequest.AccessToken);
            var username = principal.Identity.Name;
            var user = await _userManager.FindByNameAsync(username);

            var savedRefreshToken = await _refreshTokenRepository.GetRefreshTokenAsync(tokenRequest.RefreshToken);
            if (savedRefreshToken == null || savedRefreshToken.UserId != user.Id || savedRefreshToken.ExpiryDate <= DateTime.Now)
            {
                return Unauthorized();
            }

            var newAccessToken = _jwtTokenService.GenerateAccessToken(user);
            var newRefreshToken = _jwtTokenService.GenerateRefreshToken();

            var newRefreshTokenEntity = new RefreshToken
            {
                Token = newRefreshToken,
                UserId = user.Id,
                ExpiryDate = DateTime.Now.AddDays(_jwtSettings.RefreshTokenExpirationDays)
            };

            await _refreshTokenRepository.RemoveRefreshTokenAsync(savedRefreshToken);
            await _refreshTokenRepository.AddRefreshTokenAsync(newRefreshTokenEntity);

            return Ok(new
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken
            });
        }

        [HttpPost("revoke")]
        public async Task<IActionResult> Revoke([FromBody] RevokeTokenRequestModel revokeTokenRequest)
        {
            var savedRefreshToken = await _refreshTokenRepository.GetRefreshTokenAsync(revokeTokenRequest.RefreshToken);
            if (savedRefreshToken == null)
            {
                return NotFound();
            }

            await _refreshTokenRepository.RemoveRefreshTokenAsync(savedRefreshToken);

            return NoContent();
        }

        [HttpDelete("by-username/{username}")]
        public async Task<IActionResult> DeleteUserByUsername(string username)
        {
            var user = await _userManager.FindByNameAsync(username);
            if (user == null)
            {
                return NotFound();
            }

            var result = await _userManager.DeleteAsync(user);
            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            return NoContent();
        }
    }
}
