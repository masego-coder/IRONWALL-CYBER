using IronwallCyber.Models;

namespace IronwallCyber.Services;

/// <summary>
/// In-memory data store used for the prototype. Swap this for an EF Core DbContext
/// when you are ready to persist to SQL Server: the controllers only talk to the
/// methods below, so the change stays in this one file.
/// </summary>
public class DataStore
{
    private readonly object _lock = new();
    private int _nextIncidentId = 1;

    public List<AppUser> Users { get; } = new();
    public List<ThreatEvent> Threats { get; } = new();
    public List<AttentionItem> Attention { get; } = new();
    public List<Incident> Incidents { get; } = new();
    public List<Asset> Assets { get; } = new();
    public List<AuditEntry> Audit { get; } = new();

    public DataStore()
    {
        SeedUsers();
        SeedThreats();
        SeedAttention();
        SeedAssets();
        SeedAudit();
    }

    // ---------- users ----------

    private void SeedUsers()
    {
        Users.AddRange(new[]
        {
            new AppUser { Id = 1, Username = "thando.n", Email = "thando.n@example.co.za", Password = "Demo!Passw0rd",
                          Role = Roles.EndUser, DisplayName = "Thando N.", MfaEnabled = true,
                          Status = AccountStatus.Active, LastSignIn = new DateTime(2026, 8, 29, 21, 4, 0), UnreadAlerts = 3 },
            new AppUser { Id = 2, Username = "nomusa.d", Email = "nomusa@dlaminitrading.co.za", Password = "Demo!Passw0rd",
                          Role = Roles.EndUser, DisplayName = "Nomusa D.", MfaEnabled = false,
                          Status = AccountStatus.Active, LastSignIn = new DateTime(2026, 8, 29, 18, 22, 0), UnreadAlerts = 1 },
            new AppUser { Id = 3, Username = "s.mkhize", Email = "s.mkhize@ironwall.co.za", Password = "Demo!Passw0rd",
                          Role = Roles.Analyst, DisplayName = "S. Mkhize", MfaEnabled = true,
                          Status = AccountStatus.Active, LastSignIn = new DateTime(2026, 8, 29, 20, 59, 0), UnreadAlerts = 9 },
            new AppUser { Id = 4, Username = "sipho.m", Email = "sipho.m@example.co.za", Password = "Demo!Passw0rd",
                          Role = Roles.EndUser, DisplayName = "Sipho M.", MfaEnabled = true,
                          Status = AccountStatus.Locked, LastSignIn = new DateTime(2026, 8, 27, 9, 14, 0) },
            new AppUser { Id = 5, Username = "a.nkosi", Email = "a.nkosi@ironwall.co.za", Password = "Demo!Passw0rd",
                          Role = Roles.Administrator, DisplayName = "A. Nkosi", MfaEnabled = true,
                          Status = AccountStatus.Active, LastSignIn = new DateTime(2026, 8, 29, 21, 6, 0), UnreadAlerts = 2 },
            new AppUser { Id = 6, Username = "dev.build", Email = "dev@ironwall.co.za", Password = "Demo!Passw0rd",
                          Role = Roles.Developer, DisplayName = "Dev Build", MfaEnabled = true,
                          Status = AccountStatus.Restricted, LastSignIn = new DateTime(2026, 8, 28, 16, 40, 0) }
        });
    }

    public AppUser? FindByEmail(string email) =>
        Users.FirstOrDefault(u => string.Equals(u.Email, email, StringComparison.OrdinalIgnoreCase));

    public AppUser? FindByUsername(string username) =>
        Users.FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase));

    public AppUser AddUser(AppUser user)
    {
        lock (_lock)
        {
            user.Id = Users.Count == 0 ? 1 : Users.Max(u => u.Id) + 1;
            Users.Add(user);
            WriteAudit($"Account created: {user.Username}", "system");
            return user;
        }
    }

    // ---------- threats ----------

    private void SeedThreats()
    {
        var today = DateTime.Today;
        Threats.AddRange(new[]
        {
            new ThreatEvent { Id = 1, Detected = today.AddHours(21).AddMinutes(3).AddSeconds(41), Asset = "SRV-DB-01",
                Type = "Brute force", AiScore = 0.96, Severity = Severity.Critical,
                Explanation = "412 failed logins from one address in 90 seconds", ActionLabel = "Block IP" },
            new ThreatEvent { Id = 2, Detected = today.AddHours(20).AddMinutes(58).AddSeconds(12), Asset = "LAPTOP-N14",
                Type = "Malware", AiScore = 0.94, Severity = Severity.Critical,
                Explanation = "Known ransomware signature found in a download", ActionLabel = "Quarantine" },
            new ThreatEvent { Id = 3, Detected = today.AddHours(20).AddMinutes(41).AddSeconds(7), Asset = "FW-EDGE",
                Type = "Port scan", AiScore = 0.81, Severity = Severity.High,
                Explanation = "Sequential probing of 1 024 ports from one host", ActionLabel = "Investigate" },
            new ThreatEvent { Id = 4, Detected = today.AddHours(20).AddMinutes(22).AddSeconds(55), Asset = "PC-FIN-07",
                Type = "Phishing link", AiScore = 0.63, Severity = Severity.Medium,
                Explanation = "User opened a look-alike banking domain", ActionLabel = "Notify user" },
            new ThreatEvent { Id = 5, Detected = today.AddHours(19).AddMinutes(55).AddSeconds(30), Asset = "PC-HR-02",
                Type = "Policy", AiScore = 0.28, Severity = Severity.Low,
                Explanation = "USB storage used outside approved hours", ActionLabel = "Log only" }
        });
    }

    public void MarkTriaged(int id, string actor)
    {
        lock (_lock)
        {
            var t = Threats.FirstOrDefault(x => x.Id == id);
            if (t is null) return;
            t.Triaged = true;
            WriteAudit($"{t.ActionLabel} applied to {t.Asset} ({t.Type})", actor);
        }
    }

    // ---------- attention items (end user dashboard) ----------

    private void SeedAttention()
    {
        Attention.AddRange(new[]
        {
            new AttentionItem { Id = 1, Severity = Severity.Critical, Finding = "Password reused on 3 sites",
                Advice = "Change it and store a unique one", ActionLabel = "Fix now",
                ActionUrl = "/Dashboard/PasswordTools", OwnerUsername = "thando.n" },
            new AttentionItem { Id = 2, Severity = Severity.Medium, Finding = "Windows update pending on LAPTOP-TN",
                Advice = "Restart to install security patches", ActionLabel = "View",
                ActionUrl = "/Dashboard/Device", OwnerUsername = "thando.n" },
            new AttentionItem { Id = 3, Severity = Severity.Medium, Finding = "Phishing module not completed",
                Advice = "10-minute lesson plus short quiz", ActionLabel = "Start",
                ActionUrl = "/Dashboard/Training", OwnerUsername = "thando.n" },
            new AttentionItem { Id = 4, Severity = Severity.Safe, Finding = "Weekly malware scan clean",
                Advice = "No action needed", ActionLabel = "", ActionUrl = "#", OwnerUsername = "thando.n" }
        });
    }

    // ---------- incidents ----------

    public Incident AddIncident(Incident incident)
    {
        lock (_lock)
        {
            incident.Id = _nextIncidentId++;
            incident.Reference = $"INC-{DateTime.Now:yyyyMM}-{incident.Id:D4}";
            incident.ReportedAt = DateTime.Now;
            incident.Status = incident.IsDraft ? "Draft" : "New";
            Incidents.Add(incident);
            WriteAudit($"Incident {incident.Reference} recorded ({incident.Status})", incident.ReportedBy);
            return incident;
        }
    }

    public List<Incident> IncidentsFor(string username) =>
        Incidents.Where(i => i.ReportedBy == username)
                 .OrderByDescending(i => i.ReportedAt).ToList();

    // ---------- assets and reporting ----------

    private void SeedAssets()
    {
        Assets.AddRange(new[]
        {
            new Asset { Id = 1, Name = "SRV-DB-01",  Type = "Server",      ThreatCount = 64, HighestSeverity = Severity.Critical },
            new Asset { Id = 2, Name = "FW-EDGE",    Type = "Firewall",    ThreatCount = 51, HighestSeverity = Severity.High },
            new Asset { Id = 3, Name = "PC-FIN-07",  Type = "Workstation", ThreatCount = 38, HighestSeverity = Severity.Medium },
            new Asset { Id = 4, Name = "LAPTOP-N14", Type = "Laptop",      ThreatCount = 29, HighestSeverity = Severity.Critical },
            new Asset { Id = 5, Name = "PC-HR-02",   Type = "Workstation", ThreatCount = 17, HighestSeverity = Severity.Low }
        });
    }

    // ---------- audit ----------

    private void SeedAudit()
    {
        var today = DateTime.Today;
        Audit.AddRange(new[]
        {
            new AuditEntry { When = today.AddHours(21).AddMinutes(2), Action = "Role changed: End User to Analyst", Actor = "a.nkosi" },
            new AuditEntry { When = today.AddHours(20).AddMinutes(47), Action = "Account unlocked after 15-minute lockout", Actor = "system" },
            new AuditEntry { When = today.AddHours(18).AddMinutes(22), Action = "Sign-in from 41.13.x.x (Durban, ZA)", Actor = "nomusa.d" }
        });
    }

    public void WriteAudit(string action, string actor)
    {
        lock (_lock)
        {
            Audit.Insert(0, new AuditEntry { When = DateTime.Now, Action = action, Actor = actor });
            if (Audit.Count > 200) Audit.RemoveRange(200, Audit.Count - 200);
        }
    }
}
