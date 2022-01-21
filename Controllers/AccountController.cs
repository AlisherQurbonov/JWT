using Microsoft.AspNetCore.Mvc;
using security.Model;
using security.Services;

namespace security.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AccountController : ControllerBase
{
    private readonly SecurityService _ser;

    public AccountController(SecurityService ser)
    {
        _ser = ser;
    }

    [HttpPost("[action]")]
    public IActionResult Login(LoginModel login)
    {
        var token = _ser.GenerateToken(login.Username, "user");
        return Ok(new{
            token = token,
            user = login.Username
        });
    }
}