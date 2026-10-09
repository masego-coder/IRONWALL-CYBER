using IronwallCyber.Models;
using Microsoft.AspNetCore.Html;

namespace IronwallCyber.Services;

/// <summary>
/// Severity is never shown by colour alone: every pill carries a shape and a word,
/// so the interface still reads correctly for colour-blind users and screen readers.
/// </summary>
public static class Ui
{
    public static string Shape(Severity s) => s switch
    {
        Severity.Critical => "\u25CF",   // filled circle
        Severity.High => "\u25B2",       // triangle
        Severity.Medium => "\u25B2",
        Severity.Low => "\u25A0",        // square
        _ => "\u25A0"
    };

    public static string Tone(Severity s) => s switch
    {
        Severity.Critical => "danger",
        Severity.High => "warning",
        Severity.Medium => "warning",
        Severity.Low => "safe",
        _ => "safe"
    };

    public static string Word(Severity s) => s switch
    {
        Severity.Critical => "Critical",
        Severity.High => "High",
        Severity.Medium => "Medium",
        Severity.Low => "Low",
        _ => "Safe"
    };

    public static IHtmlContent Pill(Severity s, string? label = null)
    {
        var text = label ?? Word(s);
        var html = $"<span class=\"pill pill-{Tone(s)}\"><span aria-hidden=\"true\">{Shape(s)}</span> {text}</span>";
        return new HtmlString(html);
    }

    public static IHtmlContent StatusPill(AccountStatus status)
    {
        var tone = status switch
        {
            AccountStatus.Active => "safe",
            AccountStatus.Locked => "warning",
            AccountStatus.Restricted => "warning",
            AccountStatus.Suspended => "warning",
            _ => "danger"
        };
        var shape = status == AccountStatus.Active ? "\u25A0" : status == AccountStatus.Disabled ? "\u25CF" : "\u25B2";
        return new HtmlString($"<span class=\"pill pill-{tone}\"><span aria-hidden=\"true\">{shape}</span> {status}</span>");
    }
}
