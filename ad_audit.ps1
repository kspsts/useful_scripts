<#
.SYNOPSIS
  Аудит сервисных УЗ в OU (read-only, без админских прав). Консоль — в приоритете.
.DESCRIPTION
  Собирает SPN, делегацию, UAC-флаги, группы (в т.ч. вложенные), базовые даты.
  Выводит сводку/детали; CSV/JSON по флагу -ExportCsv.
#>

param(
  [string]$ServiceOU    = "OU=Service,DC=company,DC=local",
  [string]$ExportFolder = "C:\temp",
  [switch]$ExportCsv
)

Set-StrictMode -Version Latest

# ---------------- УТИЛИТЫ ----------------
function Ensure-Folder($p){ if(-not (Test-Path $p)){ New-Item -Path $p -ItemType Directory -Force | Out-Null } }
function Try-ImportAD { try { Import-Module ActiveDirectory -ErrorAction Stop; return $true } catch { return $false } }

function SafeCount($x){
  if ($null -eq $x) { return 0 }
  if ($x -is [array]) { return $x.Count }
  if ($x -is [System.Collections.IEnumerable] -and -not ($x -is [string])) { return @($x).Count }
  return 1
}

function Decode-UAC([int]$uac){
  [ordered]@{
    ACCOUNTDISABLE         = [bool]($uac -band 0x2)
    DONT_EXPIRE_PASSWORD   = [bool]($uac -band 0x10000)
    SMARTCARD_REQUIRED     = [bool]($uac -band 0x40000)
    TRUSTED_FOR_DELEGATION = [bool]($uac -band 0x80000)
  }
}

# ---------------- ЧТЕНИЕ ПОЛЬЗОВАТЕЛЕЙ ----------------
function Get-UsersFromOU_ADSI {
  param([string]$OUPath)
  $list = @()
  try {
    $q = [ADSI]("LDAP://{0}" -f $OUPath)
    $q.Children | Where-Object { $_.SchemaClassName -eq "user" } | ForEach-Object {
      $list += [PSCustomObject]@{
        Sam  = $_.Properties["sAMAccountName"][0]
        DN   = $_.Properties["distinguishedName"][0]
        ADSI = $_
      }
    }
  } catch {
    Write-Warning "ADSI: не удалось прочитать $OUPath: $($_.Exception.Message)"
  }
  return $list
}

# ---------------- ГРУППЫ (ADSI tokenGroups) ----------------
function Get-TokenGroupNames_ADSI {
  param([System.DirectoryServices.DirectoryEntry]$DE)
  $names = @()
  try {
    $tg = $DE.Properties["tokenGroups"]
    if($tg){
      foreach($sidBytes in $tg){
        try{
          $sid = New-Object System.Security.Principal.SecurityIdentifier ($sidBytes, 0)
          $nt  = $sid.Translate([System.Security.Principal.NTAccount])
          $names += $nt.Value  # DOMAIN\Group или BUILTIN\Administrators
        } catch { }
      }
    }
  } catch { }
  return $names
}

function Get-GroupsForUser($obj,$useAD){
  if($useAD){
    try {
      return (Get-ADPrincipalGroupMembership -Identity $obj.SamAccountName -ErrorAction Stop).Name
    } catch { return @() }
  } else {
    # 1) Все группы через tokenGroups (учтёт вложенность)
    $all = @()
    if($obj.ADSI){
      $all = Get-TokenGroupNames_ADSI -DE $obj.ADSI
      $short = @()
      foreach($n in $all){ if($n){ $short += ($n -replace '^[^\\]+\\','') } }  # убираем DOMAIN\
      if((SafeCount $short) -gt 0){ return $short }
    }
    # 2) fallback: прямые группы
    $r=@()
    try { $obj.ADSI.Groups() | ForEach-Object { $r += $_.Name } } catch {
      if($obj.MemberOf){ $obj.MemberOf -split ';' | ForEach-Object { $r += ($_ -replace '^CN=([^,]+).*$','$1') } }
    }
    return $r
  }
}

# ---------------- АГРЕГАТОР ----------------
function AggregateInfo($sam,$adsi,$useAD){
  $out = [ordered]@{
    SamAccountName        = $sam
    Timestamp             = (Get-Date).ToString("s")
    DisplayName           = $null
    ServicePrincipalNames = ''
    AllowedToDelegateTo   = ''
    TrustedForDelegation  = $false
    UserAccountControl    = 0
    UAC                   = (Decode-UAC 0)
    WhenCreated           = $null
    PasswordLastSet       = $null
    Mail                  = $null
    HomeDirectory         = $null
    LogonWorkstations     = $null
    MemberOf              = ''
    Groups                = ''
    RiskScore             = 0
    RiskLevel             = 'LOW'
    Flag_SPNS             = $false
    Flag_Delegation       = $false
    Flag_DontExpire       = $false
    Flag_PrivGroup        = $false
    Error                 = $null
  }

  try{
    if($useAD){
      $u = Get-ADUser -Identity $sam -Properties servicePrincipalName,msDS-AllowedToDelegateTo,msDS-TrustedForDelegation,UserAccountControl,whenCreated,PasswordLastSet,mail,homeDirectory,logonWorkstations,memberOf -ErrorAction Stop
      $out.DisplayName           = $u.DisplayName
      $out.ServicePrincipalNames = ($u.servicePrincipalName -join '; ')
      $out.AllowedToDelegateTo   = ($u.'msDS-AllowedToDelegateTo' -join '; ')
      $out.TrustedForDelegation  = [bool]$u.'msDS-TrustedForDelegation'
      $out.UserAccountControl    = [int]$u.UserAccountControl
      $out.UAC                   = (Decode-UAC $out.UserAccountControl)
      $out.WhenCreated           = $u.whenCreated
      $out.PasswordLastSet       = $u.PasswordLastSet
      $out.Mail                  = $u.Mail
      $out.HomeDirectory         = $u.HomeDirectory
      $out.LogonWorkstations     = $u.LogonWorkstations
      $out.MemberOf              = ($u.MemberOf -join '; ')
      $out.Groups                = (Get-GroupsForUser -obj $u -useAD $true) -join '; '
    } else {
      if(-not $adsi){ throw "ADSI DirectoryEntry is null for $sam" }
      $p = $adsi.Properties
      $out.DisplayName           = $p["displayName"][0]
      $out.ServicePrincipalNames = ($p["servicePrincipalName"] -join '; ')
      $out.AllowedToDelegateTo   = ($p["msDS-AllowedToDelegateTo"] -join '; ')
      $out.TrustedForDelegation  = [bool]$p["msDS-TrustedForDelegation"][0]
      $out.UserAccountControl    = [int]($p["userAccountControl"][0] | ForEach-Object {$_})
      $out.UAC                   = (Decode-UAC $out.UserAccountControl)
      $out.WhenCreated           = $p["whenCreated"][0]
      $out.PasswordLastSet       = $p["pwdLastSet"][0]
      $out.Mail                  = $p["mail"][0]
      $out.HomeDirectory         = $p["homeDirectory"][0]
      $out.LogonWorkstations     = $p["logonWorkstations"][0]
      $out.MemberOf              = ($p["memberOf"] -join '; ')

      $adsiProxy = [PSCustomObject]@{
        SamAccountName = $sam
        MemberOf       = $out.MemberOf
        ADSI           = $adsi
      }
      $out.Groups = (Get-GroupsForUser -obj $adsiProxy -useAD $false) -join '; '
    }

    # --- риск-скоры ---
    $score = 0
    if($out.ServicePrincipalNames){ $score += 40 }
    if($out.AllowedToDelegateTo){   $score += 40 }
    if($out.UAC.DONT_EXPIRE_PASSWORD){ $score += 20 }

    $priv = @(
      'Domain Admins','Enterprise Admins','Schema Admins',
      'Administrators','Account Operators','Backup Operators',
      'Server Operators','Print Operators','Group Policy Creator Owners'
    )
    $hasPriv = $false
    if($out.Groups){
      $grpArr = @($out.Groups -split ';') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
      foreach($g in $priv){
        if($grpArr -contains $g -or ($grpArr | Where-Object { $_ -like "*\$g" })) { $hasPriv = $true; $score += 50; break }
      }
    }

    $out.RiskScore       = $score
    $out.RiskLevel       = if($score -ge 70){"HIGH"} elseif($score -ge 40){"MEDIUM"} else {"LOW"}
    $out.Flag_SPNS       = [bool]$out.ServicePrincipalNames
    $out.Flag_Delegation = [bool]($out.AllowedToDelegateTo -or $out.TrustedForDelegation)
    $out.Flag_DontExpire = [bool]$out.UAC.DONT_EXPIRE_PASSWORD
    $out.Flag_PrivGroup  = $hasPriv
  }
  catch {
    $out.Error = $_.Exception.Message
  }

  return [PSCustomObject]$out
}

# ---------------- ПЕЧАТЬ ----------------
function Print-Account($obj){
  $title = "$($obj.SamAccountName) — $($obj.DisplayName)"
  Write-Host "`n" + ("-" * ([Math]::Min(80,$title.Length + 4))) -ForegroundColor DarkCyan
  Write-Host "$title" -ForegroundColor Cyan
  Write-Host ("-" * ([Math]::Min(80,$title.Length + 4))) -ForegroundColor DarkCyan

  switch ($obj.RiskLevel) {
    "HIGH"   { $color = 'Red' }
    "MEDIUM" { $color = 'Yellow' }
    default  { $color = 'Green' }
  }
  Write-Host ("Risk: {0}  (score: {1})" -f $obj.RiskLevel, $obj.RiskScore) -ForegroundColor $color

  $flags = @()
  if($obj.Flag_SPNS)       { $flags += "SPN" }
  if($obj.Flag_Delegation) { $flags += "DELEG" }
  if($obj.Flag_DontExpire) { $flags += "DONT_EXPIRE" }
  if($obj.Flag_PrivGroup)  { $flags += "PRIV_GRP" }
  Write-Host ("Flags: {0}" -f (($flags -join ', '))) -ForegroundColor Gray

  Write-Host ("Created: {0} | LastPwdSet: {1} | Mail: {2}" -f ($obj.WhenCreated,$obj.PasswordLastSet,$obj.Mail)) -ForegroundColor DarkGray
  if($obj.LogonWorkstations){ Write-Host ("LogonWorkstations: {0}" -f $obj.LogonWorkstations) -ForegroundColor DarkGray }
  if($obj.HomeDirectory){ Write-Host ("HomeDirectory: {0}" -f $obj.HomeDirectory) -ForegroundColor DarkGray }

  if($obj.ServicePrincipalNames){
    Write-Host "ServicePrincipalNames:" -ForegroundColor Yellow
    @($obj.ServicePrincipalNames -split ';') | ForEach-Object { if($_){ Write-Host "  $_" -ForegroundColor Yellow } }
  }
  if($obj.AllowedToDelegateTo){
    Write-Host "AllowedToDelegateTo:" -ForegroundColor Yellow
    @($obj.AllowedToDelegateTo -split ';') | ForEach-Object { if($_){ Write-Host "  $_" -ForegroundColor Yellow } }
  }
  if($obj.TrustedForDelegation){ Write-Host ("TrustedForDelegation: {0}" -f $obj.TrustedForDelegation) -ForegroundColor Yellow }

  if($obj.Groups){
    $grp = @($obj.Groups -split ';')
    if((SafeCount $grp) -gt 0){
      Write-Host "Groups (first 6):" -ForegroundColor Gray
      $grp | Where-Object { $_ } | Select-Object -First 6 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
      if((SafeCount $grp) -gt 6){
        Write-Host ("  ...(+" + ((SafeCount $grp)-6) + " more)") -ForegroundColor DarkGray
      }
    }
  }

  if($obj.Error){ Write-Host "ERROR: $($obj.Error)" -ForegroundColor Red }
}

# ---------------- MAIN ----------------
Ensure-Folder $ExportFolder
$useAD = Try-ImportAD

$users   = @()
$adsiList= @()
$adsiMap = @{}

if($useAD){
  try {
    $users = Get-ADUser -Filter * -SearchBase $ServiceOU -SearchScope Subtree -Properties samAccountName |
             Select-Object -ExpandProperty SamAccountName
    $users = @($users)
  } catch {
    Write-Warning "Get-ADUser failed: $($_.Exception.Message). Falling back to ADSI"
    $useAD = $false
  }
}

if(-not $useAD){
  $adsiList = Get-UsersFromOU_ADSI -OUPath $ServiceOU
  $users    = @($adsiList | Select-Object -ExpandProperty Sam)
  foreach($x in $adsiList){ if($x.Sam){ $adsiMap[$x.Sam] = $x.ADSI } }
}

if(-not $users -or (SafeCount $users) -eq 0){
  Write-Host "Не найдено учетных записей в $ServiceOU" -ForegroundColor Yellow
  return
}

$report=@()
$i=0; $total = (SafeCount $users)
foreach($s in $users){
  $i++; Write-Progress -Activity "Collecting" -Status "$i/$total $s" -PercentComplete (($i/$total)*100)
  try{
    if($useAD){
      $info = AggregateInfo -sam $s -adsi $null -useAD $true
    } else {
      $adObj = $adsiMap[$s]
      if(-not $adObj){ Write-Warning "ADSI not found for $s" }
      $info = AggregateInfo -sam $s -adsi $adObj -useAD $false
    }
    $report += $info
  } catch {
    Write-Warning "Ошибка при агрегации $s: $($_.Exception.Message)"
  }
}
$report = @($report)

# --- Сводка и подробности ---
$sorted = @($report | Sort-Object @{Expression={$_.RiskScore};Descending=$true}, @{Expression={$_.WhenCreated};Descending=$false})

Write-Host "`nSUMMARY (prioritized):" -ForegroundColor Cyan
$sorted |
  Select-Object SamAccountName,DisplayName,
                @{n='RiskLevel';e={$_.RiskLevel}},
                @{n='RiskScore';e={$_.RiskScore}},
                @{n='SPN';e={$_.Flag_SPNS}},
                @{n='Deleg';e={$_.Flag_Delegation}},
                @{n='DontExpire';e={$_.Flag_DontExpire}},
                @{n='PrivGrp';e={$_.Flag_PrivGroup}} |
  Format-Table -AutoSize

Write-Host "`nDETAILED (HIGH & MEDIUM first):" -ForegroundColor Cyan
$sorted | Where-Object { $_.RiskLevel -in @("HIGH","MEDIUM") } | ForEach-Object { Print-Account $_ }

$low = @($sorted | Where-Object { $_.RiskLevel -eq "LOW" })
if((SafeCount $low) -gt 0){
  Write-Host "`nLOW risk accounts (brief):" -ForegroundColor Green
  $low | Select-Object SamAccountName,DisplayName,RiskScore | Format-Table -AutoSize
}

# --- Экспорт (по флагу) ---
if($ExportCsv){
  $csv = Join-Path $ExportFolder ("ServiceAccounts_{0}.csv"  -f (Get-Date -Format "yyyyMMdd_HHmmss"))
  $json= Join-Path $ExportFolder ("ServiceAccounts_{0}.json" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
  try{
    $report | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    $report | ConvertTo-Json -Depth 6 | Out-File -FilePath $json -Encoding UTF8
    Write-Host "`nExports saved: $csv`n$json" -ForegroundColor Green
  } catch {
    Write-Warning "Export failed: $($_.Exception.Message)"
    $report | Format-Table -AutoSize
  }
} else {
  Write-Host "`nCSV/JSON не запрошен. Используй -ExportCsv для сохранения." -ForegroundColor DarkGray
}

Write-Host "`nDone. Processed: $(SafeCount $report) accounts." -ForegroundColor Cyan
