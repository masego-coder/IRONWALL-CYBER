using System.Text;
using IronwallCyber.Models;
using IronwallCyber.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IronwallCyber.Controllers;

[Authorize(Policy = "AnalystOrAdmin")]
public class ReportsController : Controller
{
    private readonly DataStore _db;
    public ReportsController(DataStore db) => _db = db;

    public IActionResult Index(DateTime? start, DateTime? end, string? assets, Severity? minimum)
    {
        var periodStart = start ?? new DateTime(2026, 8, 1);
        var periodEnd = end ?? new DateTime(2026, 8, 31);

        if (periodEnd < periodStart)
            ModelState.AddModelError("end", "End date cannot precede start date");

        if ((periodEnd - periodStart).TotalDays > 366)
            ModelState.AddModelError("end", "The range may not exceed 12 months");

        var model = Build(periodStart, periodEnd, assets, minimum);
        return View(model);
    }

    private MonthlyReportViewModel Build(DateTime start, DateTime end, string? assets, Severity? minimum)
    {
        var display = User.FindFirst("DisplayName")?.Value ?? User.Identity?.Name ?? "";
        return new MonthlyReportViewModel
        {
            PeriodStart = start,
            PeriodEnd = end,
            AssetScope = assets ?? "All monitored (48)",
            MinimumSeverity = minimum ?? Severity.Medium,
            Reference = $"RPT-{start:yyyy-MM}-0042",
            GeneratedBy = display,
            GeneratedAt = DateTime.Now,
            ThreatsDetected = 318,
            ChangeOnPreviousMonth = -12,
            CriticalIncidents = 6,
            MeanTimeToResolveMinutes = 41,
            UptimePercent = 99.4,
            ByCategory = new List<CategoryBar>
            {
                new() { Label = "Phishing", Value = 112 },
                new() { Label = "Malware", Value = 88 },
                new() { Label = "Brute force", Value = 54 },
                new() { Label = "Port scan", Value = 34 },
                new() { Label = "Policy", Value = 20 },
                new() { Label = "Other", Value = 10 }
            },
            TopAssets = _db.Assets.OrderByDescending(a => a.ThreatCount).ToList()
        };
    }

    public IActionResult ExportCsv(DateTime? start, DateTime? end)
    {
        var model = Build(start ?? new DateTime(2026, 8, 1), end ?? new DateTime(2026, 8, 31), null, null);

        var sb = new StringBuilder();
        sb.AppendLine($"Ironwall monthly security summary,{model.Reference}");
        sb.AppendLine($"Period,{model.PeriodStart:yyyy-MM-dd},{model.PeriodEnd:yyyy-MM-dd}");
        sb.AppendLine();
        sb.AppendLine("Category,Threats");
        foreach (var c in model.ByCategory) sb.AppendLine($"{c.Label},{c.Value}");
        sb.AppendLine();
        sb.AppendLine("Asset,Type,Threats,Highest severity");
        foreach (var a in model.TopAssets) sb.AppendLine($"{a.Name},{a.Type},{a.ThreatCount},{a.HighestSeverity}");

        _db.WriteAudit($"Report {model.Reference} exported to CSV", User.Identity?.Name ?? "unknown");
        return File(Encoding.UTF8.GetBytes(sb.ToString()), "text/csv",
                    $"ironwall-summary-{model.PeriodStart:yyyyMM}.csv");
    }

    // The print view carries the report header on every page, which is what the
    // browser's "Save as PDF" needs. No third-party PDF library required.
    public IActionResult Print(DateTime? start, DateTime? end)
    {
        var model = Build(start ?? new DateTime(2026, 8, 1), end ?? new DateTime(2026, 8, 31), null, null);
        _db.WriteAudit($"Report {model.Reference} opened for print or PDF", User.Identity?.Name ?? "unknown");
        return View(model);
    }
}
