# Security policy

## Supported version

Security fixes are applied to the latest version on the `main` branch.

## Reporting a vulnerability

Use GitHub private vulnerability reporting from the repository's **Security** tab. Do not publish process paths, private addresses, internal firewall rule names, Group Policy details, or working exploits in a public issue.

Include the affected commit or version, reproduction steps, expected and actual behavior, impact, and any suggested mitigation.

## Intended security boundary

`ruletrace` is a local, read-only diagnostic. It queries Windows networking and firewall information through built-in PowerShell cmdlets. It does not request elevation, make external requests, execute downloaded content, write files, start or stop processes, or modify firewall rules, services, the registry, or system configuration.

The output is evidence, not a complete firewall verdict. Ruletrace marks partial firewall queries instead of treating inaccessible data as an absence of rules. Rule applicability can also depend on application, service, package, interface, address, IPsec, policy merging, third-party filters, and the remote network path.

## Privacy

Terminal output can contain local addresses, process names, process identifiers, application paths, firewall rule names, address scopes, and policy sources. Review and redact output before sharing it.

## Execution policy

Review `ruletrace.ps1` before running it. The documented `-ExecutionPolicy Bypass` command affects only the new PowerShell process and does not change persistent user or machine policy.
