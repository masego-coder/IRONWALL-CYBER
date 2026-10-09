using IronwallCyber.Models;
using IronwallCyber.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IronwallCyber.Controllers;

[Authorize]
public class IncidentsController : Controller
{
    private readonly DataStore _db;
    public IncidentsController(DataStore db) => _db = db;

    public static readonly string[] Categories =
    {
        "Phishing / social engineering",
        "Malware or ransomware",
        "Lost or stolen device",
        "Unauthorised access",
        "Data sent to the wrong person",
        "Something else"
    };

    public static readonly string[] Devices =
    {
        "LAPTOP-TN (192.168.1.14)",
        "PC-FIN-07 (192.168.1.23)",
        "PC-HR-02 (192.168.1.31)",
        "Mobile phone",
        "Not device related"
    };

    public IActionResult Index() => RedirectToAction(nameof(Report));

    [HttpGet]
    public IActionResult Report()
    {
        FillLists();
        return View(new Incident { OccurredAt = DateTime.Now });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Report(Incident model, IFormFile? evidence, string? action)
    {
        var isDraft = string.Equals(action, "draft", StringComparison.OrdinalIgnoreCase);

        if (model.OccurredAt.HasValue && model.OccurredAt > DateTime.Now)
            ModelState.AddModelError(nameof(model.OccurredAt), "Date and time cannot be in the future");

        if (model.Description?.Contains("password", StringComparison.OrdinalIgnoreCase) == true)
            ModelState.AddModelError(nameof(model.Description), "Do not paste passwords. Describe what happened instead.");

        if (evidence is not null && evidence.Length > 0)
        {
            if (evidence.Length > 10 * 1024 * 1024)
                ModelState.AddModelError("evidence", "Evidence must be 10 MB or smaller");
            else
            {
                var ok = new[] { ".png", ".jpg", ".jpeg", ".eml", ".pdf", ".txt" };
                var ext = Path.GetExtension(evidence.FileName).ToLowerInvariant();
                if (!ok.Contains(ext))
                    ModelState.AddModelError("evidence", "Attach a screenshot, PDF, text or .eml file");
                else
                {
                    var folder = Path.Combine(Directory.GetCurrentDirectory(), "App_Data", "evidence");
                    Directory.CreateDirectory(folder);
                    var safeName = $"{Guid.NewGuid():N}{ext}";
                    await using var stream = System.IO.File.Create(Path.Combine(folder, safeName));
                    await evidence.CopyToAsync(stream);
                    model.EvidenceFileName = evidence.FileName;
                }
            }
        }

        if (isDraft)
        {
            // A draft only needs a title, so clear the rest of the validation state.
            foreach (var key in ModelState.Keys.Where(k => k != nameof(Incident.Title)).ToList())
                ModelState.Remove(key);
        }

        if (!ModelState.IsValid)
        {
            FillLists();
            return View(model);
        }

        model.IsDraft = isDraft;
        model.ReportedBy = User.Identity?.Name ?? "unknown";
        var saved = _db.AddIncident(model);

        TempData["Flash"] = isDraft
            ? $"Draft saved as {saved.Reference}. Finish it from My incidents."
            : $"Report {saved.Reference} sent. An analyst is notified and a confirmation e-mail follows.";

        return RedirectToAction(nameof(Confirmation), new { id = saved.Id });
    }

    public IActionResult Confirmation(int id)
    {
        var incident = _db.Incidents.FirstOrDefault(i => i.Id == id);
        if (incident is null) return RedirectToAction(nameof(Report));
        return View(incident);
    }

    public IActionResult Mine() => View(_db.IncidentsFor(User.Identity?.Name ?? ""));

    public IActionResult Resolved() =>
        View("Mine", _db.IncidentsFor(User.Identity?.Name ?? "").Where(i => i.Status == "Resolved").ToList());

    public IActionResult Guidance() => View();

    private void FillLists()
    {
        ViewBag.Categories = Categories;
        ViewBag.Devices = Devices;
    }
}
