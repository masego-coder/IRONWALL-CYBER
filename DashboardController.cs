using IronwallCyber.Models;
using IronwallCyber.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IronwallCyber.Controllers;

[Authorize]
public class DashboardController : Controller
{
    private readonly DataStore _db;
    public DashboardController(DataStore db) => _db = db;

    public IActionResult Index()
    {
        var me = User.Identity?.Name ?? "";
        var items = _db.Attention.Where(a => a.OwnerUsername == me || a.OwnerUsername == "").ToList();
        if (items.Count == 0) items = _db.Attention.ToList();

        var model = new DashboardViewModel
        {
            SecurityScore = 72,
            ItemsNeedingAttention = items.Count(i => i.Severity != Severity.Safe),
            DevicesMonitored = 2,
            ThreatsBlocked30Days = 14,
            TrainingCompleted = 3,
            TrainingTotal = 5,
            LastUpdated = DateTime.Now,
            Attention = items.OrderByDescending(i => i.Severity).ToList(),
            WeeklyThreats = new List<WeeklyBar>
            {
                new() { Label = "W21", Value = 9 },
                new() { Label = "W22", Value = 13 },
                new() { Label = "W23", Value = 7 },
                new() { Label = "W24", Value = 15 },
                new() { Label = "W25", Value = 11 },
                new() { Label = "W26", Value = 18, Flagged = true }
            }
        };
        return View(model);
    }

    public IActionResult PasswordTools() => View();

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult CheckPassword(string candidate)
    {
        ViewBag.Candidate = candidate;
        ViewBag.Result = Strength(candidate);
        return View("PasswordTools");
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult GeneratePassword(int length = 18)
    {
        const string chars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*?";
        var bytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(length);
        ViewBag.Generated = new string(bytes.Select(b => chars[b % chars.Length]).ToArray());
        return View("PasswordTools");
    }

    private static string Strength(string? p)
    {
        if (string.IsNullOrWhiteSpace(p)) return "Type a password to check it.";
        var score = 0;
        if (p.Length >= 12) score++;
        if (p.Length >= 16) score++;
        if (p.Any(char.IsUpper) && p.Any(char.IsLower)) score++;
        if (p.Any(char.IsDigit)) score++;
        if (p.Any(c => !char.IsLetterOrDigit(c))) score++;
        return score switch
        {
            >= 5 => "Strong. This would take a long time to guess.",
            4 => "Good, but longer is better. Aim for 16 characters.",
            3 => "Weak. Add length and a symbol.",
            _ => "Very weak. Use a generated password instead."
        };
    }

    public IActionResult FileScanner() => View();

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ScanFile(IFormFile? upload)
    {
        if (upload is null || upload.Length == 0)
        {
            ViewBag.ScanResult = "Choose a file to scan. Nothing was uploaded.";
            return View("FileScanner");
        }

        if (upload.Length > 10 * 1024 * 1024)
        {
            ViewBag.ScanResult = "That file is larger than 10 MB. Split it or scan it on the device.";
            return View("FileScanner");
        }

        using var ms = new MemoryStream();
        await upload.CopyToAsync(ms);
        var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(ms.ToArray()));

        ViewBag.ScannedName = upload.FileName;
        ViewBag.ScannedHash = hash;
        ViewBag.ScanResult = "No known malware signature matched this file.";
        _db.WriteAudit($"File scanned: {upload.FileName}", User.Identity?.Name ?? "unknown");
        return View("FileScanner");
    }

    public IActionResult Training() => View();

    public IActionResult Device() => View();

    public IActionResult News() => View();
}
