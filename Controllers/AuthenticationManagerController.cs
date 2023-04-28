using AuthenticationApi.DTOs;
using AuthenticationApi.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationApi.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthenticationManagerController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly ITokenService _tokenService;

    public AuthenticationManagerController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, ITokenService tokenService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _tokenService = tokenService;
    }

    [HttpGet]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public async Task<IActionResult> ValidateAutentication()
    {
        return Ok(_userManager.Users);
    }

    [HttpPost("Register")]
    public async Task<IActionResult> UserRegister([FromBody] UserDTO userDto)
    {
        var user = new IdentityUser()
        {
            Email= userDto.Email,
            UserName= userDto.Email,
            EmailConfirmed= true
        };

        var result = await _userManager.CreateAsync(user, userDto.Password);

        if(!result.Succeeded)
        {
            return BadRequest(result.Errors);
        }

        await _signInManager.SignInAsync(user, false);
        return Ok(_tokenService.GenerateToken(userDto));
    }

    [HttpPost("Login")]
    public async Task<IActionResult> UserLogin([FromBody] UserDTO userDto)
    {
        var result = await _signInManager.PasswordSignInAsync(userDto.Email, userDto.Password, isPersistent: false, lockoutOnFailure: false); 

        if(result.Succeeded)
        {
            return Ok(_tokenService.GenerateToken(userDto));
        }
        else
        {
            ModelState.AddModelError(string.Empty, "Login inválido!");
            return BadRequest(ModelState);
        }
    }

    // rota para revogar token
    [HttpPost("revoke")]
    [Authorize]
    public async Task<IActionResult> RevokeToken()
    {
        // pega o token da requisição
        var token = await HttpContext.GetTokenAsync("Authorization");


        return Ok();
    }

}
