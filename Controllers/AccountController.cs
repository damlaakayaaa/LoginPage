using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using STB.MAP.UI.Models;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

public class AccountController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
	private readonly ILogger<AccountController> _logger;

	public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, ILogger<AccountController> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
		_logger = logger;
	}

    [HttpGet]
    public IActionResult Register()
    {
        return View();
    }

	[HttpPost]
	public async Task<IActionResult> Register(RegisterViewModel model)
	{
		if (ModelState.IsValid)
		{
			var user = new ApplicationUser { UserName = model.Username, Email = model.Email };
			var result = await _userManager.CreateAsync(user, model.Password);

			if (result.Succeeded)
			{
				await _signInManager.SignInAsync(user, isPersistent: false);
				return Json(new { success = true, redirectUrl = Url.Action("Login", "Account") });
			}
			else
			{
				var errors = result.Errors.Select(error => error.Description).ToList();
				return Json(new { success = false, message = "Kayıt başarısız", errors });
			}
		}

		return Json(new { success = false, message = "Geçersiz model", errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage) });
	}



	[HttpGet]
    public IActionResult Login()
    {
        return View();
    }


    [HttpPost]
    public async Task<IActionResult> Login([FromBody] LoginViewModel model)
    {
        if (ModelState.IsValid)
        {
            var user = await _userManager.FindByNameAsync(model.Username);

            if (user != null)
            {
                var signInResult = await _signInManager.PasswordSignInAsync(model.Username, model.Password, false, false);

                if (signInResult.Succeeded)
                {
                    var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                    new Claim(ClaimTypes.Name, user.UserName ?? string.Empty),
                    new Claim(ClaimTypes.Email, user.Email ?? string.Empty),
                };

                    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                    var principal = new ClaimsPrincipal(identity);

                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, new AuthenticationProperties
                    {
                        IsPersistent = true,
                        ExpiresUtc = DateTime.UtcNow.AddMinutes(30)
                    });

                    return Json(new { success = true, redirectUrl = Url.Action("Index", "App", new {area="App"}) });

                }
                else if (signInResult.IsLockedOut)
                {
                    return Json(new { success = false, message = "Hesabınız kilitlendi. Lütfen bir süre sonra tekrar deneyin." });
                }
                else if (signInResult.RequiresTwoFactor)
                {
                    return Json(new { success = false, message = "İki faktörlü kimlik doğrulama gerekiyor." });
                }
                else
                {
                    return Json(new { success = false, message = "Geçersiz kullanıcı adı veya şifre." });
                }
            }
            else
            {
                return Json(new { success = false, message = "Kullanıcı bulunamadı. Lütfen doğru kullanıcı adı ve şifre girildiğinden emin olun." });
            }
        }

        var errors = ModelState.Values
            .SelectMany(v => v.Errors)
            .Select(e => e.ErrorMessage);

        return Json(new { success = false, errors = errors });
    }

	[HttpPost]
	[Authorize]
	public async Task<IActionResult> LogOut()
	{
		try
		{
			await HttpContext.SignOutAsync();
			_logger.LogInformation("User logged out.");
			return Json(new { success = true, redirectUrl = Url.Action("Login", "Account"), message = "Çıkış işlemi başarılı." });
		}
		catch (Exception ex)
		{
			_logger.LogError($"Error during logout: {ex.Message}");
			return Json(new { success = false, message = "Error during logout!" });
		}
	}


}












