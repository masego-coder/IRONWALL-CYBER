using System.ComponentModel.DataAnnotations;

namespace IronwallCyber.Models;

public class LoginViewModel
{
    [Required(ErrorMessage = "E-mail address is required")]
    [EmailAddress(ErrorMessage = "Enter a valid e-mail address")]
    [Display(Name = "E-mail address")]
    public string Email { get; set; } = "";

    [Required(ErrorMessage = "Password is required")]
    [DataType(DataType.Password)]
    public string Password { get; set; } = "";

    [Required(ErrorMessage = "Authenticator code is required")]
    [RegularExpression(@"^\d{6}$", ErrorMessage = "The code is 6 digits")]
    [Display(Name = "Authenticator code (6 digits)")]
    public string AuthenticatorCode { get; set; } = "";

    [Display(Name = "Keep me signed in on this device")]
    public bool RememberMe { get; set; }

    public string? ReturnUrl { get; set; }
}

public class RegisterViewModel
{
    [Required(ErrorMessage = "E-mail address is required")]
    [EmailAddress(ErrorMessage = "Enter a valid e-mail address")]
    [Display(Name = "E-mail address")]
    public string Email { get; set; } = "";

    [Required(ErrorMessage = "Full name is required")]
    [Display(Name = "Full name")]
    public string DisplayName { get; set; } = "";

    [Required(ErrorMessage = "Password is required")]
    [StringLength(100, MinimumLength = 10, ErrorMessage = "Use at least 10 characters")]
    [DataType(DataType.Password)]
    public string Password { get; set; } = "";

    [DataType(DataType.Password)]
    [Compare(nameof(Password), ErrorMessage = "The two passwords do not match")]
    [Display(Name = "Confirm password")]
    public string ConfirmPassword { get; set; } = "";
}

public class DashboardViewModel
{
    public int SecurityScore { get; set; }
    public int ItemsNeedingAttention { get; set; }
    public int DevicesMonitored { get; set; }
    public int ThreatsBlocked30Days { get; set; }
    public int TrainingCompleted { get; set; }
    public int TrainingTotal { get; set; }
    public DateTime LastUpdated { get; set; }
    public List<AttentionItem> Attention { get; set; } = new();
    public List<WeeklyBar> WeeklyThreats { get; set; } = new();
}

public class ThreatMonitorViewModel
{
    public int OpenCriticalThreats { get; set; }
    public int EventsAnalysedToday { get; set; }
    public int PeakEventsPerSecond { get; set; }
    public int AiAnomalyHits { get; set; }
    public int AwaitingReview { get; set; }
    public double MeanTimeToDetectSeconds { get; set; }
    public int MonitoredAssets { get; set; }
    public string Window { get; set; } = "Last 24 hours";
    public string SeverityFilter { get; set; } = "all";
    public List<ThreatEvent> Threats { get; set; } = new();
}

public class MonthlyReportViewModel
{
    public string ReportType { get; set; } = "Monthly security summary";
    public DateTime PeriodStart { get; set; }
    public DateTime PeriodEnd { get; set; }
    public string AssetScope { get; set; } = "All monitored (48)";
    public Severity MinimumSeverity { get; set; } = Severity.Medium;
    public string Reference { get; set; } = "";
    public string GeneratedBy { get; set; } = "";
    public DateTime GeneratedAt { get; set; }
    public int ThreatsDetected { get; set; }
    public double ChangeOnPreviousMonth { get; set; }
    public int CriticalIncidents { get; set; }
    public int MeanTimeToResolveMinutes { get; set; }
    public int TargetMinutes { get; set; } = 60;
    public double UptimePercent { get; set; }
    public List<CategoryBar> ByCategory { get; set; } = new();
    public List<Asset> TopAssets { get; set; } = new();
}

public class UserAdminViewModel
{
    public List<AppUser> Users { get; set; } = new();
    public AppUser? Selected { get; set; }
    public List<AuditEntry> RecentAudit { get; set; } = new();
    public string RoleFilter { get; set; } = "all";
    public string? Search { get; set; }
    public int TotalAccounts { get; set; }
}
