package com.example.scanner;

/**
 * A single result from a scan check: what was found, how serious it is,
 * and — critically — what the user should manually do about it.
 * This app never auto-remediates; it reports and instructs.
 */
public class Finding {

    public enum Severity { INFO, WARNING, CRITICAL }

    public final String title;
    public final String detail;
    public final Severity severity;
    public final String remediationSteps;

    public Finding(String title, String detail, Severity severity, String remediationSteps) {
        this.title = title;
        this.detail = detail;
        this.severity = severity;
        this.remediationSteps = remediationSteps;
    }
}
