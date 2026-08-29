<h1 align="center">Ruletrace</h1>

<p align="center">
  A compact, read-only Windows Firewall port diagnostic.
</p>

---

Ruletrace shows which local TCP or UDP ports are bound and helps identify the process and inbound Windows Firewall rules associated with a selected port.

## Install

You need Windows and PowerShell with the built-in NetTCPIP, NetConnection, and NetSecurity modules.

```powershell
git clone https://github.com/delriscotechnologies/ruletrace.git
cd ruletrace
.\ruletrace.ps1 443
```

## What it does

1. Finds local TCP listeners or UDP endpoints.
2. Resolves the owning process when available.
3. Detects the active Windows network profile.
4. Finds inbound firewall rules that explicitly match the selected port.
5. Shows rule action, profile, application, remote scope, and policy source.

## Output

A specific-port query shows the local socket and matching inbound firewall rules.

Using -All displays a compact inventory of local TCP listeners and UDP endpoints.

## Demo

Check TCP port 443:

```powershell
.\ruletrace.ps1 443
```

Check UDP port 53:

```powershell
.\ruletrace.ps1 53 -Protocol UDP
```

List local endpoints:

```powershell
.\ruletrace.ps1 -All
```

## Scope and limits

- Read-only local diagnostic.
- Does not change firewall rules or test remote computers.
- Firewall visibility can depend on permissions.
- Rule presence does not guarantee that a connection will be allowed or blocked.
- Protected process details may be unavailable.

See [SECURITY.md](SECURITY.md) for security guidance.

## License

Ruletrace is available under the [MIT License](LICENSE).
