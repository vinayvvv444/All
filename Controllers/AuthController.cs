using All.Models;
using All.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace All.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly ITokenService _tokenService;

        public AuthController(ITokenService tokenService)
        {
            _tokenService = tokenService;
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] UserModel user)
        {
            // Validate the user credentials here (this is just a sample)
            if (user.Username == "test" && user.Password == "password")
            {
                var token = _tokenService.GenerateToken(user);
                return Ok(new { token });
            }

            return Unauthorized();
        }

        [HttpGet("protected")]
        [Authorize]
        public IActionResult Protected()
        {
            return Ok("This is a protected endpoint.");
        }
    }
}
