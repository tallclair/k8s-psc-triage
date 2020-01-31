# Kubernetes PSC Triage

Handles triage for the Kubernetes PSC.

## Features

### Managed Labels

`needs-cve` is added if the issue is missing the line:
```
CVE: CVE-YYYY-#####
```
Or the assigned CVE is `TBD`.

The severity is scraped from the line:
```
Severity: {Critical, High, Medium, Low}
```
If the severity is missing or not set to one of those values, the `needs-severity` label is applied. Otherwise, the appropriate `severity/{level}` label is applied.