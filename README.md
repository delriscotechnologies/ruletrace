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

A specific-port query looks like this:

```text
      ####   #   #  #      #####
      #   #  #   #  #      #
      ####   #   #  #      ####
      #  #   #   #  #      #
      #   #   ###   #####  #####

 #####  ####    ###    ####  #####
   #    #   #  #   #  #     #
   #    ####   #####  #     ####
   #    #  #   #   #  #     #
   #    #   #  #   #   #### #####
+-----------------------------------+
|       DEL RISCO TECHNOLOGIES      |
+-----------------------------------+
Target     : 443/TCP
Profiles   : Public
Firewall   : Public = Enabled

LOCAL SOCKET
Address  PID  Process
-------  ---  -------
0.0.0.0 4820 nginx

EXPLICIT INBOUND RULES
[ALLOW] Local HTTPS
  State/Profile : Enabled / Public (current: Yes)
  Program       : C:\Apps\nginx.exe
  Remote scope  : Any
  Source        : Local
```

Using -All produces a compact inventory:

```text
Protocol Port Process   PID  Firewall         Address
-------- ---- -------   ---  --------         -------
TCP       135 svchost  1700  Allow rule       ::,0.0.0.0
TCP       445 System      4  Other profile    ::
TCP      8080 node     5420  No explicit rule 127.0.0.1
```

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
