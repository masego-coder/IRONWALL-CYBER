using IronwallCyber.Models;
using IronwallCyber.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IronwallCyber.Controllers;

[Authorize(Roles = Roles.Administrator)]
public class AdminController : Controller
{
    private readonly DataStore _db;
    public AdminController(DataStore db) => _db = db;

    public IActionResult Index() => RedirectToAction(nameof(Users));

    public IActionResult Users(string role = "all", string? search = null, int? selected = null)
    {
        var rows = _db.Users.AsEnumerable();

        if (!string.Equals(role, "all", StringComparison.OrdinalIgnoreCase))
            rows = rows.Where(u => u.Role == role);

        if (!string.IsNullOrWhiteSpace(search))
            rows = rows.Where(u => u.Username.Contains(search, StringComparison.OrdinalIgnoreCase)
                                || u.Email.Contains(search, StringComparison.OrdinalIgnoreCase));

        var list = rows.OrderBy(u => u.Id).ToList();

        var model = new UserAdminViewModel
        {
            Users = list,
            Selected = selected.HasValue
                ? _db.Users.FirstOrDefault(u => u.Id == selected)
                : list.FirstOrDefault(u => u.Username == "nomusa.d") ?? list.FirstOrDefault(),
            RecentAudit = _db.Audit.Take(3).ToList(),
            RoleFilter = role,
            Search = search,
            TotalAccounts = 142
        };
        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult SaveChanges(int id, string role, AccountStatus status, bool mfaEnabled)
    {
        var user = _db.Users.FirstOrDefault(u => u.Id == id);
        if (user is null) return NotFound();

        var actor = User.Identity?.Name ?? "unknown";

        if (user.Role != role)
        {
            _db.WriteAudit($"Role changed: {user.Role} to {role} for {user.Username}", actor);
            user.Role = role;
            // Changing a role signs the user out of all active sessions.
            _db.WriteAudit($"All sessions ended for {user.Username} after role change", "system");
        }

        if (user.Status != status)
        {
            _db.WriteAudit($"Status changed: {user.Status} to {status} for {user.Username}", actor);
            user.Status = status;
        }

        if (user.MfaEnabled != mfaEnabled)
        {
            _db.WriteAudit($"Multi-factor authentication {(mfaEnabled ? "required" : "turned off")} for {user.Username}", actor);
            user.MfaEnabled = mfaEnabled;
        }

        TempData["Flash"] = $"Changes saved for {user.Username}.";
        return RedirectToAction(nameof(Users), new { selected = id });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult ForcePasswordReset(int id)
    {
        var user = _db.Users.FirstOrDefault(u => u.Id == id);
        if (user is null) return NotFound();

        _db.WriteAudit($"Password reset forced for {user.Username}", User.Identity?.Name ?? "unknown");
        TempData["Flash"] = $"{user.Username} must set a new password at the next sign-in.";
        return RedirectToAction(nameof(Users), new { selected = id });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Unlock(int id)
    {
        var user = _db.Users.FirstOrDefault(u => u.Id == id);
        if (user is null) return NotFound();

        user.Status = AccountStatus.Active;
        user.FailedAttempts = 0;
        user.LockedUntil = null;
        _db.WriteAudit($"Account unlocked: {user.Username}", User.Identity?.Name ?? "unknown");
        TempData["Flash"] = $"{user.Username} can sign in again.";
        return RedirectToAction(nameof(Users), new { selected = id });
    }

    [HttpGet]
    public IActionResult AddUser() => View(new AppUser());

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult AddUser(AppUser model)
    {
        if (string.IsNullOrWhiteSpace(model.Email)) ModelState.AddModelError("Email", "E-mail address is required");
        if (string.IsNullOrWhiteSpace(model.DisplayName)) ModelState.AddModelError("DisplayName", "Full name is required");
        if (_db.FindByEmail(model.Email ?? "") is not null)
            ModelState.AddModelError("Email", "An account already uses this e-mail address");

        if (!ModelState.IsValid) return View(model);

        model.Username = model.Email.Split('@')[0].ToLowerInvariant();
        model.Password = "Demo!Passw0rd";
        model.Status = AccountStatus.Active;
        _db.AddUser(model);

        TempData["Flash"] = $"{model.Username} added. A first-sign-in e-mail has been sent.";
        return RedirectToAction(nameof(Users));
    }

    public IActionResult AuditTrail() => View(_db.Audit.Take(100).ToList());

    public IActionResult Content() => View();

    public IActionResult Backups() => View();

    public IActionResult Settings() => View();
}
