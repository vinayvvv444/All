using All.Contracts;
using All.Models.jwt;
using All.Models.User;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace All.Services.jwt
{
    public class JwtTokenService : IJwtTokenService
    {
        private readonly IConfiguration _configuration;
        //private readonly JwtSettings _jwtSettings;

        public JwtTokenService(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        //public JwtTokenService(JwtSettings jwtSettings)
        //{
        //    _jwtSettings = jwtSettings;
        //}

        public string GenerateAccessToken(ApplicationUser user)
        {
            // Set current time to IST
            TimeZoneInfo indianZone = TimeZoneInfo.FindSystemTimeZoneById("India Standard Time");
            DateTime indianTime = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, indianZone);

            var claims = new[]
            {
            //new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
            //new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            //new Claim(ClaimTypes.Name, user.UserName),
            new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, DateTime.UtcNow.ToString()),
            new Claim(JwtRegisteredClaimNames.Exp, new DateTimeOffset(DateTime.UtcNow.AddMinutes(30)).ToUnixTimeSeconds().ToString()) // Add the exp claim
        };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                //expires: indianTime.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public string GenerateAccessTokenNew(ApplicationUser user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                //new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                //new Claim(JwtRegisteredClaimNames.UniqueName, user.UserName),
                //new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                new Claim(ClaimTypes.Name, user.UserName)
            }),
                // Expires = DateTime.Now.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
                Expires = DateTime.UtcNow.AddHours(1),
                Issuer = _configuration["Jwt:Issuer"],
                Audience = _configuration["Jwt:Audience"],
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
           // DateTime? datet = GetExpirationTime(token);
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true, // Here we are saying that we don't care about the token's expiration date
                ValidateIssuerSigningKey = true,
                //ValidIssuer = _jwtSettings.Issuer,
                //ValidAudience = _jwtSettings.Audience,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]))
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;

            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;
        }

        public DateTime? GetExpirationTime(string token)
        {
            var handler = new JwtSecurityTokenHandler();

            // Check if the token is in valid JWT format
            if (!handler.CanReadToken(token))
            {
                throw new ArgumentException("Invalid JWT token");
            }

            var jwtToken = handler.ReadJwtToken(token);

            // Extract the exp claim
            var expClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Exp)?.Value;

            if (expClaim != null)
            {
                // Convert exp claim to DateTime
                var exp = long.Parse(expClaim);
                var expirationTime = DateTimeOffset.FromUnixTimeSeconds(exp).UtcDateTime;
                return expirationTime;
            }

            return null;
        }
    }
}
