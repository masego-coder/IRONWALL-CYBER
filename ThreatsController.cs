using System.Text;
using IronwallCyber.Models;
using IronwallCyber.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IronwallCyber.Controllers;

[Authorize(Policy = "AnalystOrAdmin")]
public class ThreatsController : Controller
{
    private readonly DataStore _db;
    public ThreatsController(DataStore db) => _db = db;

    public IActionResult Index(string severity = "all", string window = "Last 24 hours")
    {
        var rows = _db.Threats.Where(t => !t.Triaged).AsEnumerable();

        if (!string.Equals(severity, "all", StringComparison.OrdinalIgnoreCase) &&
            Enum.TryParse<Severity>(severity, true, out var wanted))
        {
            rows = rows.Where(t => t.Severity >= wanted);
        }

        var list = rows.OrderByDescending(t => t.Severity).ThenByDescending(t => t.Detected).ToList();

        var model = new ThreatMonitorViewModel
        {
            OpenCriticalThreats = _db.Threats.Count(t => !t.Triaged && t.Severity == Severity.Critical),
            EventsAnalysedToday = 412_907,
            PeakEventsPerSecond = 4_780,
            AiAnomalyHits = 27,
            AwaitingReview = _db.Threats.Count(t => !t.Triaged) + 4,
            MeanTimeToDetectSeconds = 2.4,
            MonitoredAssets = 48,
            Window = window,
            SeverityFilter = severity,
            Threats = list
        };
        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Triage(int id)
    {
        _db.MarkTriaged(id, User.Identity?.Name ?? "unknown");
        TempData["Flash"] = "Action applied and written to the audit trail.";
        return RedirectToAction(nameof(Index));
    }

    public IActionResult Export()
    {
        var sb = new StringBuilder();
        sb.AppendLine("Detected,Asset,Type,Severity,AI score,Explanation");
        foreach (var t in _db.Threats.OrderByDescending(t => t.Detected))
        {
            sb.AppendLine($"{t.Detected:yyyy-MM-dd HH:mm:ss},{t.Asset},{t.Type},{t.Severity},{t.AiScore:0.00},\"{t.Explanation}\"");
        }
        _db.WriteAudit("Threat monitor exported to CSV", User.Identity?.Name ?? "unknown");
        return File(Encoding.UTF8.GetBytes(sb.ToString()), "text/csv",
                    $"ironwall-threats-{DateTime.Now:yyyyMMdd-HHmm}.csv");
    }

    public IActionResult Assets() => View(_db.Assets);

    public IActionResult Scans() => View();
}
