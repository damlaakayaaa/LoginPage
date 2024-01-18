using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using STB.MAP.UI.Controllers;
using System.Security.Claims;

namespace STB.MAP.UI.Areas.App.Controllers
{
    [Area("App")]

	[Authorize(Policy = "LoggedInUsers")]
	public class AppController : Controller
    {
		private readonly ILogger<AppController> _logger;

		public AppController(ILogger<AppController> logger)
		{
			_logger = logger;
		}
		public IActionResult Index()
        {
			try
			{
				ClaimsPrincipal claimsPrincipal = this.User;

				if (claimsPrincipal != null && claimsPrincipal.Identity != null && claimsPrincipal.Identity.IsAuthenticated)
				{
					string userName = claimsPrincipal.Identity.Name;
					ViewData["UserName"] = userName;
				}
				else
				{
					ViewData["UserName"] = "Bilinmeyen Kullanıcı";
				}

				if (!ModelState.IsValid)
				{
					var errorMessages = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage);
					ViewData["ErrorMessage"] = string.Join(", ", errorMessages);
				}

				return View();
			}
			catch (Exception ex)
			{
				ViewData["ErrorMessage"] = "Bir hata oluştu. Lütfen daha sonra tekrar deneyin.";
				_logger.LogError(ex, "Index sayfasında bir hata oluştu.");
				return View();
			}
		}
    }
}
