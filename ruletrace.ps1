[CmdletBinding(DefaultParameterSetName = 'Port')]
param(
    [Parameter(Mandatory, Position = 0, ParameterSetName = 'Port')][ValidateRange(1, 65535)][int]$Port,
    [Parameter(Mandatory, ParameterSetName = 'All')][switch]$All,
    [Parameter(ParameterSetName = 'Port')][ValidateSet('TCP', 'UDP')][string]$Protocol = 'TCP'
)
Set-StrictMode -Version Latest; $ErrorActionPreference = 'Stop'
function Test-PortSpec {
    param([string[]]$Values, [int]$Target)
    foreach ($value in $Values) {
        foreach ($part in ($value -split ',')) {
            $part = $part.Trim()
            if ($part -eq 'Any') { return $true }
            if ($part -match '^\d+$' -and [int]$part -eq $Target) { return $true }
            if ($part -match '^(\d+)-(\d+)$' -and $Target -ge [int]$Matches[1] -and $Target -le [int]$Matches[2]) { return $true }
        }
    }
    return $false
}
function Test-RuleProfile {
    param([string]$RuleProfile, [string[]]$ActiveProfiles)
    if ($ActiveProfiles.Count -eq 0) { return 'Unknown' }
    if ($RuleProfile -eq 'Any') { return 'Yes' }
    foreach ($name in ($RuleProfile -split ',')) {
        if ($ActiveProfiles -contains $name.Trim()) { return 'Yes' }
    }
    return 'No'
}
$processNames = @{}
function Convert-Socket {
    param($Items, [string]$Name)
    foreach ($item in $Items) {
        $processId = [int]$item.OwningProcess
        if (-not $processNames.ContainsKey($processId)) {
            $owner = Get-Process -Id $processId -ErrorAction SilentlyContinue; $processNames[$processId] = if ($owner) { $owner.ProcessName } else { 'Unavailable' }; if ($owner) { $owner.Dispose() }
        }
        [pscustomobject]@{
            Protocol = $Name
            Port = [int]$item.LocalPort
            Address = [string]$item.LocalAddress
            PID = $processId
            Process = $processNames[$processId]
        }
    }
}
try {
    $queryErrors = @(); $socketErrors = @()
    $activeProfiles = @(
        Get-NetConnectionProfile -ErrorAction SilentlyContinue -ErrorVariable +queryErrors |
            Where-Object { $_.IPv4Connectivity -ne 'Disconnected' -or $_.IPv6Connectivity -ne 'Disconnected' } |
            ForEach-Object { $name = [string]$_.NetworkCategory; if ($name -eq 'DomainAuthenticated') { 'Domain' } else { $name } } |
            Select-Object -Unique
    )
    $profileDetails = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction SilentlyContinue -ErrorVariable +queryErrors | Where-Object { $activeProfiles -contains [string]$_.Name })
    $tcp = @(); $udp = @()
    if ($All -or $Protocol -eq 'TCP') {
        $tcp = @(if ($All) { Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue -ErrorVariable +socketErrors } else { Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue -ErrorVariable +socketErrors })
    }
    if ($All -or $Protocol -eq 'UDP') {
        $udp = @(if ($All) { Get-NetUDPEndpoint -ErrorAction SilentlyContinue -ErrorVariable +socketErrors } else { Get-NetUDPEndpoint -LocalPort $Port -ErrorAction SilentlyContinue -ErrorVariable +socketErrors })
    }
    $queryErrors += @($socketErrors | Where-Object { $_.CategoryInfo.Category -ne 'ObjectNotFound' })
    $socketRows = @(Convert-Socket $tcp 'TCP'; Convert-Socket $udp 'UDP')
    $targets = @(if ($All) { $socketRows | Select-Object Protocol, Port -Unique } else { [pscustomobject]@{ Protocol = $Protocol; Port = $Port } })
    $portFilters = @(Get-NetFirewallPortFilter -PolicyStore ActiveStore -ErrorAction SilentlyContinue -ErrorVariable +queryErrors)
    $protocolCodes = @{ TCP = '6'; UDP = '17' }; $ruleMetadata = @{}
    $ruleRows = @(
        foreach ($filter in $portFilters) {
            $filterProtocol = [string]$filter.Protocol
            $matchedTargets = @($targets | Where-Object {
                $filterProtocol -in @('Any', $_.Protocol, $protocolCodes[$_.Protocol]) -and
                (Test-PortSpec -Values @($filter.LocalPort) -Target $_.Port)
            })
            if (-not $matchedTargets.Count) { continue }
            foreach ($rule in @($filter | Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -ErrorAction SilentlyContinue -ErrorVariable +queryErrors)) {
                if ([string]$rule.Direction -ne 'Inbound') { continue }
                $key = [string]$rule.Name
                if (-not $ruleMetadata.ContainsKey($key)) {
                    $apps = @($rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue -ErrorVariable +queryErrors); $addresses = @($rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue -ErrorVariable +queryErrors)
                    $ruleMetadata[$key] = [pscustomobject]@{ Program = if ($apps.Count -and $apps[0].Program) { $apps.Program -join ', ' } else { 'Any' }; Remote = if ($addresses.Count -and $addresses[0].RemoteAddress) { $addresses.RemoteAddress -join ', ' } else { 'Any' } }
                }
                $metadata = $ruleMetadata[$key]
                foreach ($target in $matchedTargets) {
                    $ruleProfile = [string]$rule.Profile
                    [pscustomobject]@{ Id = $key; Port = $target.Port; Protocol = $target.Protocol
                        Rule = [string]$rule.DisplayName; Action = [string]$rule.Action
                        State = if ([string]$rule.Enabled -eq 'True') { 'Enabled' } else { 'Disabled' }
                        Profile = $ruleProfile; Applies = Test-RuleProfile $ruleProfile $activeProfiles
                        Program = $metadata.Program
                        Remote = $metadata.Remote
                        Source = [string]$rule.PolicyStoreSourceType }
                }
            }
        }
    )
    $ruleRows = @($ruleRows | Sort-Object Protocol, Port, Id -Unique)
}
catch { throw "Ruletrace could not query Windows networking data: $($_.Exception.Message)" }
$banner = "      ####   #   #  #      #####`n      #   #  #   #  #      #`n      ####   #   #  #      ####`n      #  #   #   #  #      #`n      #   #   ###   #####  #####`n`n #####  ####    ###    ####  #####`n   #    #   #  #   #  #     #`n   #    ####   #####  #     ####`n   #    #  #   #   #  #     #`n   #    #   #  #   #   #### #####"
$displayWidth = [Math]::Max(37, [int]$Host.UI.RawUI.WindowSize.Width); Write-Host
$leftPad = ' ' * [Math]::Max(0, [int](($displayWidth - 37) / 2))
foreach ($line in ($banner -split "`r?`n")) { Write-Host "$leftPad$line" -ForegroundColor Cyan }
foreach ($line in ("+-----------------------------------+`n|       DEL RISCO TECHNOLOGIES      |`n+-----------------------------------+" -split "`n")) { Write-Host "$leftPad$line" -ForegroundColor DarkGray }
Write-Host ("Target     : {0}" -f $(if ($All) { 'All local TCP/UDP ports' } else { "$Port/$Protocol" }))
Write-Host ("Profiles   : {0}" -f $(if ($activeProfiles.Count) { $activeProfiles -join ', ' } else { 'Unknown' }))
foreach ($profile in $profileDetails) { Write-Host ("Firewall   : {0} = {1}" -f $profile.Name, $(if ([string]$profile.Enabled -eq 'True') { 'Enabled' } else { 'Disabled' })) }
if ($queryErrors.Count) { Write-Host 'Warning    : Some networking or firewall data was unavailable; results may be incomplete.' -ForegroundColor Yellow }
if ($All) {
    Write-Host "`nLOCAL PORTS" -ForegroundColor Cyan
    $summaryRows = @(
        foreach ($group in ($socketRows | Group-Object Protocol, Port, PID, Process)) {
            $socket = $group.Group[0]
            $matches = @($ruleRows | Where-Object { $_.Protocol -eq $socket.Protocol -and $_.Port -eq $socket.Port })
            $current = @($matches | Where-Object { $_.State -eq 'Enabled' -and $_.Applies -ne 'No' })
            $status = if (@($current | Where-Object Action -eq 'Block').Count) { 'Block candidate' }
                elseif (@($current | Where-Object Action -eq 'Allow').Count) { 'Allow candidate' }
                elseif (@($matches | Where-Object State -eq 'Enabled').Count) { 'Other-profile candidate' }
                elseif ($matches.Count) { 'Disabled candidate' } else { if ($queryErrors.Count) { 'No accessible rule' } else { 'No port candidate' } }
            [pscustomobject]@{ Protocol = $socket.Protocol; Port = $socket.Port
                Address = @($group.Group.Address | Select-Object -Unique) -join ','
                Process = $socket.Process; PID = $socket.PID; Firewall = $status }
        }
    )
    if ($summaryRows.Count) { $summaryRows | Sort-Object Protocol, Port | Format-Table Protocol, Port, Process, PID, Firewall, Address -AutoSize -Wrap }
    else { Write-Host 'No local TCP listeners or UDP endpoints were found.' -ForegroundColor Yellow }
    Write-Host ("{0} local socket group(s) found." -f $summaryRows.Count)
    return
}
Write-Host "`nLOCAL SOCKET" -ForegroundColor Cyan
if ($socketRows.Count) { $socketRows | Select-Object Address, PID, Process | Format-Table -AutoSize }
else { Write-Host "No local $Protocol endpoint was found on port $Port." -ForegroundColor Yellow }
Write-Host 'CANDIDATE INBOUND RULES' -ForegroundColor Cyan
if (-not $ruleRows.Count) {
    Write-Host $(if ($queryErrors.Count) { 'No candidate rule was found in the accessible policy data.' } else { 'No inbound rule has a port and protocol filter that includes this target.' })
}
foreach ($item in ($ruleRows | Sort-Object Action, Rule)) {
    Write-Host ("[{0}] {1}" -f $item.Action.ToUpperInvariant(), $item.Rule) -ForegroundColor $(if ($item.Action -eq 'Block') { 'Red' } else { 'Green' })
    Write-Host ("  State/Profile : {0} / {1} (current: {2})" -f $item.State, $item.Profile, $item.Applies)
    Write-Host ("  Program       : {0}`n  Remote scope  : {1}`n  Source        : {2}" -f $item.Program, $item.Remote, $item.Source)
}
