using System.Security.Claims;
using IronwallCyber.Models;
using IronwallCyber.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;

namespace IronwallCyber.Controllers;

public class AccountController : Controller
{
    private readonly DataStore _db;
    private readonly IConfiguration _config;

    public AccountController(DataStore db, IConfiguration config)
    {
        _db = db;
        _config = config;
    }

    private string DemoCode => _config["Ironwall:DemoAuthenticatorCode"] ?? "123456";
    private int LockoutAttempts => int.TryParse(_config["Ironwall:LockoutAttempts"], out var v) ? v : 5;
    private int LockoutMinutes => int.TryParse(_config["Ironwall:LockoutMinutes"], out var v) ? v : 15;

    [HttpGet]
    public IActionResult Login(string? returnUrl = null)
    {
        if (User.Identity?.IsAuthenticated == true) return RedirectToLanding(User.FindFirstValue(ClaimTypes.Role));
        return View(new LoginViewModel { ReturnUrl = returnUrl });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        if (!ModelState.IsValid) return View(model);

        var user = _db.FindByEmail(model.Email);

        if (user is null || user.Password != model.Password)
        {
            if (user is not null)
            {
                user.FailedAttempts++;
                if (user.FailedAttempts >= LockoutAttempts)
                {
                    user.Status = AccountStatus.Locked;
                    user.LockedUntil = DateTime.Now.AddMinutes(LockoutMinutes);
                    _db.WriteAudit($"Account locked after {LockoutAttempts} failed attempts", user.Username);
                }
                else
                {
                    _db.WriteAudit("Failed sign-in attempt", user.Username);
                }
            }

            ModelState.AddModelError(string.Empty,
                $"E-mail address or password is not correct. {LockoutAttempts} failed attempts lock the account for {LockoutMinutes} minutes.");
            return View(model);
        }

        if (user.Status == AccountStatus.Locked && user.LockedUntil > DateTime.Now)
        {
            ModelState.AddModelError(string.Empty,
                $"This account is locked until {user.LockedUntil:HH:mm}. Ask an administrator to unlock it.");
            return View(model);
        }

        if (user.Status is AccountStatus.Disabled or AccountStatus.Suspended)
        {
            ModelState.AddModelError(string.Empty, "This account is not active. Contact your administrator.");
            return View(model);
        }

        if (user.MfaEnabled && model.AuthenticatorCode != DemoCode)
        {
            ModelState.AddModelError(nameof(model.AuthenticatorCode),
                "That code is not valid. Codes rotate every 30 seconds.");
            return View(model);
        }

        user.FailedAttempts = 0;
        user.LockedUntil = null;
        if (user.Status == AccountStatus.Locked) user.Status = AccountStatus.Active;
        user.LastSignIn = DateTime.Now;

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, user.Username),
            new(ClaimTypes.Email, user.Email),
            new(ClaimTypes.Role, user.Role),
            new("DisplayName", user.DisplayName),
            new("Initials", user.Initials),
            new("Alerts", user.UnreadAlerts.ToString())
        };

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity),
            new AuthenticationProperties
            {
                IsPersistent = model.RememberMe,
                ExpiresUtc = model.RememberMe ? DateTimeOffset.UtcNow.AddDays(14) : null
            });

        _db.WriteAudit($"Sign-in from {HttpContext.Connection.RemoteIpAddress}", user.Username);

        if (!string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
            return Redirect(model.ReturnUrl);

        return RedirectToLanding(user.Role);
    }

    private IActionResult RedirectToLanding(string? role) => role switch
    {
        Roles.Analyst => RedirectToAction("Index", "Threats"),
        Roles.Administrator => RedirectToAction("Users", "Admin"),
        _ => RedirectToAction("Index", "Dashboard")
    };

    [HttpGet]
    public IActionResult Register() => View(new RegisterViewModel());

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Register(RegisterViewModel model)
    {
        if (_db.FindByEmail(model.Email) is not null)
            ModelState.AddModelError(nameof(model.Email), "An account already uses this e-mail address");

        if (!ModelState.IsValid) return View(model);

        var username = model.Email.Split('@')[0].ToLowerInvariant();
        _db.AddUser(new AppUser
        {
            Username = username,
            Email = model.Email,
            Password = model.Password,
            DisplayName = model.DisplayName,
            Role = Roles.EndUser,
            MfaEnabled = true,
            Status = AccountStatus.Active
        });

        TempData["Flash"] = $"Account created. Sign in with {model.Email} and the demo code 123456.";
        return RedirectToAction(nameof(Login));
    }

    [HttpGet]
    public IActionResult ForgotPassword() => View();

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult ForgotPassword(string email)
    {
        _db.WriteAudit($"Password reset requested for {email}", "system");
        TempData["Flash"] = "If that address has an account, a reset link is on its way.";
        return RedirectToAction(nameof(Login));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SignOutUser()
    {
        var who = User.Identity?.Name ?? "unknown";
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        _db.WriteAudit("Signed out", who);
        return RedirectToAction(nameof(Login));
    }

    public IActionResult Denied() => View();

    public IActionResult Error() => View();
}
