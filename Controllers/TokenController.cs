//using All.Models.jwt;
//using Microsoft.AspNetCore.Authorization;
//using Microsoft.AspNetCore.Http;
//using Microsoft.AspNetCore.Mvc;
//using Microsoft.IdentityModel.Tokens;
//using System.IdentityModel.Tokens.Jwt;
//using System.Text;

//namespace All.Controllers
//{
//    [Route("api/[controller]")]
//    [ApiController]
//    public class TokenController : ControllerBase
//    {
//        private readonly JwtSettings _jwtSettings;

//        public TokenController(JwtSettings jwtSettings)
//        {
//            _jwtSettings = jwtSettings;
//        }
//        [Authorize]
//        [HttpPost]
//        [Route("validate")]
//        public IActionResult ValidateToken([FromBody] string token)
//        {
//            var key = Encoding.ASCII.GetBytes(_jwtSettings.SecretKey);
//            var tokenHandler = new JwtSecurityTokenHandler();
//            try
//            {
//                tokenHandler.ValidateToken(token, new TokenValidationParameters
//                {
//                    ValidateIssuer = true,
//                    ValidateAudience = false,
//                    ValidateLifetime = true,
//                    ValidateIssuerSigningKey = true,
//                    ValidIssuer = _jwtSettings.Issuer,
//                    ValidAudience = _jwtSettings.Audience,
//                    IssuerSigningKey = new SymmetricSecurityKey(key)
//                }, out SecurityToken validatedToken);

//                return Ok(new { Valid = true });
//            }
//            catch
//            {
//                return Unauthorized();
//            }
//        }
//    }
//}
