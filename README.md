<h1 align="center">Ruletrace</h1>

<p align="center">
  A compact, read-only Windows Firewall port diagnostic.
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#output">Output</a> &middot;
  <a href="#how-it-works">How It Works</a> &middot;
  <a href="#scope-and-safeguards">Scope</a> &middot;
  <a href="SECURITY.md">Security</a>
</p>

---

Ruletrace answers two local troubleshooting questions: which TCP and UDP ports are currently bound, and what process and inbound Windows Firewall rules are associated with a specific port?

It correlates the local endpoint, owning process, active network profile, rule state, action, application scope, remote-address scope, and policy source. It does not change firewall rules or test a remote computer.

## Quick Start

Ruletrace requires Windows PowerShell 5.1 or later and the built-in `NetTCPIP`, `NetConnection`, and `NetSecurity` modules. Administrator rights are not normally required, although protected process or firewall details can be unavailable. Ruletrace warns when its firewall results may be incomplete; if authorized, rerun it from an elevated shell for a fuller view.

```powershell
git clone https://github.com/delriscotechnologies/ruletrace.git
cd ruletrace
.\ruletrace.ps1 443
```

Check a UDP port:

```powershell
.\ruletrace.ps1 53 -Protocol UDP
```

List every local TCP listener and UDP endpoint:

```powershell
.\ruletrace.ps1 -All
```

If execution policy blocks local scripts, review the source first and use a process-only bypass:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ruletrace.ps1 443
```

## Output

`-All` produces a compact inventory. `Firewall` summarizes accessible rules that apply to the active profile; `Allow rule` and `Block rule` report rule presence rather than a definitive connection verdict. `Other profile` means an enabled rule exists but does not apply to the current profile.

```text
Protocol Port Process   PID  Firewall         Address
-------- ---- -------   ---  --------         -------
TCP       135 svchost  1700  Allow rule       ::,0.0.0.0
TCP       445 System      4  Other profile    ::
TCP      8080 node     5420  No explicit rule 127.0.0.1
```

A specific-port query provides the underlying rule details:

```text
RULETRACE
--------------------------------------------------
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

## How It Works

1. Validate the selected mode, port, and protocol.
2. Find local TCP listeners or UDP endpoints and resolve their owning processes.
3. Detect active Windows network profiles.
4. Search the effective firewall policy for inbound rules whose local-port filter explicitly contains the requested port or a matching range.
5. Display the rule state, action, profile relevance, program, remote scope, and policy source.

## Scope and Safeguards

Ruletrace is deliberately narrow:

- current Windows computer only
- either all bound local ports or one detailed port per execution
- TCP listeners or UDP endpoints
- explicit local-port values and ranges; rules using `Any` are not listed
- inbound rules only
- no port scanning, packet capture, external requests, telemetry, or saved reports
- no firewall, process, registry, service, or system changes
- no simulation of the complete Windows Filtering Platform decision

A listener and an allow rule do not prove that a remote connection will succeed. Interfaces, IPsec, service and package filters, third-party security software, routers, NAT, and the rest of the network path can still affect reachability.

Ruletrace is an independent implementation inspired by the diagnostic idea in [Windows-Port-Firewall-Inspector](https://github.com/hasanuassan/Windows-Port-Firewall-Inspector); its source code was not copied.

See [SECURITY.md](SECURITY.md) for the trust boundary and reporting guidance.

## License

Ruletrace source code is available under the [MIT License](LICENSE).
