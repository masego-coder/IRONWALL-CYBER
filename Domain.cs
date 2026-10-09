using System.ComponentModel.DataAnnotations;

namespace IronwallCyber.Models;

public enum Severity { Safe = 0, Low = 1, Medium = 2, High = 3, Critical = 4 }

public enum AccountStatus { Active, Suspended, Disabled, Locked, Restricted }

public static class Roles
{
    public const string EndUser = "End User";
    public const string Analyst = "Security Analyst";
    public const string Administrator = "Administrator";
    public const string Developer = "Developer";
}

public class AppUser
{
    public int Id { get; set; }
    public string Username { get; set; } = "";
    public string Email { get; set; } = "";
    public string Password { get; set; } = "";
    public string Role { get; set; } = Roles.EndUser;
    public string DisplayName { get; set; } = "";
    public bool MfaEnabled { get; set; } = true;
    public AccountStatus Status { get; set; } = AccountStatus.Active;
    public DateTime? LastSignIn { get; set; }
    public int FailedAttempts { get; set; }
    public DateTime? LockedUntil { get; set; }
    public int UnreadAlerts { get; set; }

    public string Initials =>
        string.Join("", DisplayName.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                                   .Take(2).Select(p => char.ToUpper(p[0])));
}

public class ThreatEvent
{
    public int Id { get; set; }
    public DateTime Detected { get; set; }
    public string Asset { get; set; } = "";
    public string Type { get; set; } = "";
    public double AiScore { get; set; }
    public Severity Severity { get; set; }
    public string Explanation { get; set; } = "";
    public string ActionLabel { get; set; } = "";
    public bool Triaged { get; set; }
}

public class AttentionItem
{
    public int Id { get; set; }
    public Severity Severity { get; set; }
    public string Finding { get; set; } = "";
    public string Advice { get; set; } = "";
    public string ActionLabel { get; set; } = "";
    public string ActionUrl { get; set; } = "#";
    public string OwnerUsername { get; set; } = "";
}

public class Incident
{
    public int Id { get; set; }
    public string Reference { get; set; } = "";

    [Required(ErrorMessage = "Incident title is required")]
    [StringLength(120, MinimumLength = 5, ErrorMessage = "Title must be 5 to 120 characters")]
    [Display(Name = "Incident title")]
    public string Title { get; set; } = "";

    [Required(ErrorMessage = "Category is required")]
    public string Category { get; set; } = "";

    [Required(ErrorMessage = "Severity is required")]
    public Severity Severity { get; set; } = Severity.Medium;

    [Required(ErrorMessage = "Affected device is required")]
    public string AffectedDevice { get; set; } = "";

    [Required(ErrorMessage = "Date and time is required")]
    [DisplayFormat(DataFormatString = "{0:yyyy-MM-ddTHH:mm}", ApplyFormatInEditMode = true)]
    [Display(Name = "When did it happen?")]
    public DateTime? OccurredAt { get; set; }

    [Required(ErrorMessage = "Description is required")]
    [StringLength(2000, MinimumLength = 20, ErrorMessage = "Description must be 20 to 2000 characters")]
    [Display(Name = "What happened?")]
    public string Description { get; set; } = "";

    public string? EvidenceFileName { get; set; }
    public string Status { get; set; } = "New";
    public string ReportedBy { get; set; } = "";
    public DateTime ReportedAt { get; set; } = DateTime.Now;
    public bool IsDraft { get; set; }
}

public class Asset
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public string Type { get; set; } = "";
    public int ThreatCount { get; set; }
    public Severity HighestSeverity { get; set; }
}

public class AuditEntry
{
    public DateTime When { get; set; }
    public string Action { get; set; } = "";
    public string Actor { get; set; } = "";
}

public class WeeklyBar
{
    public string Label { get; set; } = "";
    public int Value { get; set; }
    public bool Flagged { get; set; }
}

public class CategoryBar
{
    public string Label { get; set; } = "";
    public int Value { get; set; }
}
