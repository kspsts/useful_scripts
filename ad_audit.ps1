<#
.AUDIT
  Сервисные УЗ: консольный отчёт, детекция привилегий через SID→DN + LDAP recursive.
  Read-only. Экспорт CSV/JSON по -ExportCsv.
#>

param(
  [string]$ServiceOU    = "OU=Service,DC=company,DC=local",
  [string]$ExportFolder = "C:\temp",
  [switch]$ExportCsv
)

Set-StrictMode -Version Latest

# --------- УТИЛИТЫ ---------
function Ensure-Folder($p){ if(-not (Test-Path $p)){ New-Item -Path $p -ItemType Directory -Force | Out-Null } }
function Try-ImportAD { try { Import-Module ActiveDirectory -ErrorAction Stop; return $true } catch { return $false } }
function SafeCount($x){ if($null -eq $x){0} elseif($x -is [array]){$x.Count} elseif($x -is [System.Collections.IEnumerable] -and -not ($x -is [string])){@($x).Count} else {1} }
function Decode-UAC([int]$uac){ [ordered]@{
  ACCOUNTDISABLE=[bool]($uac -band 0x2)
  DONT_EXPIRE_PASSWORD=[bool]($uac -band 0x10000)
  SMARTCARD_REQUIRED=[bool]($uac -band 0x40000)
  TRUSTED_FOR_DELEGATION=[bool]($uac -band 0x80000)
} }

# --------- СЕРВИС AD ---------
function Get-DefaultNC { ([ADSI]"LDAP://RootDSE").defaultNamingContext }
function Get-ConfigNC  { ([ADSI]"LDAP://RootDSE").configurationNamingContext }

function Get-DomainSID {
  try {
    $nc = Get-DefaultNC
    $de = [ADSI]("LDAP://$nc")
    $sidBytes = $de.Properties["objectSid"][0]
    $sid = New-Object System.Security.Principal.SecurityIdentifier ($sidBytes,0)
    return $sid.Value
  } catch { return $null }
}

function Find-ObjectDN-BySID([string]$sidStr){
  try{
    $nc = Get-DefaultNC
    $sr = New-Object System.DirectoryServices.DirectorySearcher
    $sr.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry ("LDAP://$nc")
    $sr.PageSize = 1
    $sr.Filter = "(&(objectClass=group)(objectSid=$sidStr))"
    $res = $sr.FindOne()
    if($res){ return $res.Properties["distinguishedname"][0] }
  } catch {}
  return $null
}

# Привилегированные группы: доменные (RID к domainSID) + BUILTIN (фиксированные SID)
function Resolve-PrivGroupDNs {
  $domainSid = Get-DomainSID
  $result = [ordered]@{}
  $domRIDs = @{
    DomainAdmins             = 512
    EnterpriseAdmins         = 519
    SchemaAdmins             = 518
    GroupPolicyCreatorOwners = 520
  }
  $builtin = @{
    Administrators   = 'S-1-5-32-544'
    AccountOperators = 'S-1-5-32-548'
    ServerOperators  = 'S-1-5-32-549'
    PrintOperators   = 'S-1-5-32-550'
    BackupOperators  = 'S-1-5-32-551'
  }

  foreach($k in $domRIDs.Keys){
    $sid = if($domainSid){ "$domainSid-$($domRIDs[$k])" } else { $null }
    $result[$k] = if($sid){ Find-ObjectDN-BySID $sid } else { $null }
  }
  foreach($k in $builtin.Keys){
    $result[$k] = Find-ObjectDN-BySID $builtin[$k]
  }
  return $result
}

# LDAP recursive membership check (matching-rule-in-chain)
function Test-MemberOfRecursive {
  param(
    [string]$Sam,
    [string]$GroupDN
  )
  if([string]::IsNullOrEmpty($GroupDN)){ return $false }
  try{
    $nc = Get-DefaultNC
    $sr = New-Object System.DirectoryServices.DirectorySearcher
    $sr.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry ("LDAP://$nc")
    $sr.PageSize = 1
    $sr.Filter = "(&(objectClass=user)(sAMAccountName=$Sam)(memberOf:1.2.840.113556.1.4.1941:=$GroupDN))"
    $res = $sr.FindOne()
    return ($res -ne $null)
  } catch { return $false }
}

# --------- ПОЛЬЗОВАТЕЛИ ---------
function Get-UsersFromOU_AD {
  param([string]$ou)
  try {
    return Get-ADUser -Filter * -SearchBase $ou -SearchScope Subtree -Properties samAccountName
  } catch { return @() }
}
function Get-UsersFromOU_ADSI {
  param([string]$OUPath)
  $list = @()
  try{
    $q = [ADSI]("LDAP://{0}" -f $OUPath)
    $q.Children | Where-Object { $_.SchemaClassName -eq "user" } | ForEach-Object {
      $list += [PSCustomObject]@{
        Sam  = $_.Properties["sAMAccountName"][0]
        DN   = $_.Properties["distinguishedName"][0]
        ADSI = $_
      }
    }
  } catch { Write-Warning "ADSI: не удалось прочитать $OUPath: $($_.Exception.Message)" }
  return $list
}

# (опционально) tokenGroups → имена (для печати), если доступно; логика риска от этого не зависит
function Try-GetGroupNames-ForPrint-AD([string]$Sam){
  try{
    $u = Get-ADUser -Identity $Sam -Properties tokenGroups,tokenGroupsGlobalAndUniversal
    $names=@()
    foreach($prop in @('tokenGroups','tokenGroupsGlobalAndUniversal')){
      foreach($v in @($u.$prop)){
        try{
          if($v -is [byte[]]){ $sid = New-Object System.Security.Principal.SecurityIdentifier ($v,0) }
          elseif($v -is [System.Security.Principal.SecurityIdentifier]){ $sid = $v } else { $sid = $null }
          if($sid){
            $nt = $sid.Translate([System.Security.Principal.NTAccount]).Value
            $names += ($nt -replace '^[^\\]+\\','')
          }
        } catch {}
      }
    }
    return ($names | Select-Object -Unique) -join '; '
  } catch { return '' }
}
function Try-GetGroupNames-ForPrint-ADSI($adsi){
  try{
    $names=@()
    $tg = $adsi.Properties["tokenGroups"]
    foreach($b in @($tg)){
      try{
        $sid = New-Object System.Security.Principal.SecurityIdentifier ($b,0)
        $nt  = $sid.Translate([System.Security.Principal.NTAccount]).Value
        $names += ($nt -replace '^[^\\]+\\','')
      } catch {}
    }
    if((SafeCount $names) -gt 0){ return ($names | Select-Object -Unique) -join '; ' }
  } catch {}
  # fallback прямые
  $r=@()
  try { $adsi.Groups() | ForEach-Object { $r += $_.Name } } catch {
    $m = $adsi.Properties["memberOf"]
    if($m){ $m | ForEach-Object { $r += ($_ -replace '^CN=([^,]+).*$','$1') } }
  }
  return ($r -join '; ')
}

# --------- АГРЕГАТОР ---------
function AggregateInfo {
  param(
    [string]$Sam,
    [System.DirectoryServices.DirectoryEntry]$ADSI,
    [bool]$UseAD,
    [hashtable]$PrivDNs
  )

  $out = [ordered]@{
    SamAccountName        = $Sam
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
    Groups                = ''     # печать
    RiskScore             = 0
    RiskLevel             = 'LOW'
    Flag_SPNS             = $false
    Flag_Delegation       = $false
    Flag_DontExpire       = $false
    Flag_PrivGroup        = $false
    Error                 = $null
  }

  try{
    if($UseAD){
      $u = Get-ADUser -Identity $Sam -Properties servicePrincipalName,msDS-AllowedToDelegateTo,msDS-TrustedForDelegation,UserAccountControl,whenCreated,PasswordLastSet,mail,homeDirectory,logonWorkstations -ErrorAction Stop
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
      $out.Groups                = Try-GetGroupNames-ForPrint-AD $Sam
    } else {
      if(-not $ADSI){ throw "ADSI DirectoryEntry is null for $Sam" }
      $p = $ADSI.Properties
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
      $out.Groups                = Try-GetGroupNames-ForPrint-ADSI $ADSI
    }

    # --- риск ---
    $score = 0
    if($out.ServicePrincipalNames){ $score += 40 }
    if($out.AllowedToDelegateTo){   $score += 40 }
    if($out.UAC.DONT_EXPIRE_PASSWORD){ $score += 20 }

    # Привилегии через LDAP-recursive по DN (локализация не важна)
    $hasPriv = $false
    foreach($k in $PrivDNs.Keys){
      $dn = $PrivDNs[$k]
      if($dn -and (Test-MemberOfRecursive -Sam $Sam -GroupDN $dn)){ $hasPriv = $true; break }
    }
    if($hasPriv){ $score += 50 }

    $out.RiskScore       = $score
    $out.RiskLevel       = if($score -ge 70){"HIGH"} elseif($score -ge 40){"MEDIUM"} else {"LOW"}
    $out.Flag_SPNS       = [bool]$out.ServicePrincipalNames
    $out.Flag_Delegation = [bool]($out.AllowedToDelegateTo -or $out.TrustedForDelegation)
    $out.Flag_DontExpire = [bool]$out.UAC.DONT_EXPIRE_PASSWORD
    $out.Flag_PrivGroup  = $hasPriv
  }
  catch { $out.Error = $_.Exception.Message }

  return [PSCustomObject]$out
}

# --------- ПЕЧАТЬ ---------
function Print-Account($obj){
  $title = "$($obj.SamAccountName) — $($obj.DisplayName)"
  Write-Host "`n" + ("-" * ([Math]::Min(80,$title.Length + 4))) -ForegroundColor DarkCyan
  Write-Host "$title" -ForegroundColor Cyan
  Write-Host ("-" * ([Math]::Min(80,$title.Length + 4))) -ForegroundColor DarkCyan
  switch ($obj.RiskLevel) { "HIGH"{$c='Red'} "MEDIUM"{$c='Yellow'} default{$c='Green'} }
  Write-Host ("Risk: {0}  (score: {1})" -f $obj.RiskLevel,$obj.RiskScore) -ForegroundColor $c

  $flags=@(); if($obj.Flag_SPNS){$flags+='SPN'}; if($obj.Flag_Delegation){$flags+='DELEG'}; if($obj.Flag_DontExpire){$flags+='DONT_EXPIRE'}; if($obj.Flag_PrivGroup){$flags+='PRIV_GRP'}
  Write-Host ("Flags: {0}" -f ($flags -join ', ')) -ForegroundColor Gray

  Write-Host ("Created: {0} | LastPwdSet: {1} | Mail: {2}" -f ($obj.WhenCreated,$obj.PasswordLastSet,$obj.Mail)) -ForegroundColor DarkGray
  if($obj.LogonWorkstations){ Write-Host ("LogonWorkstations: {0}" -f $obj.LogonWorkstations) -ForegroundColor DarkGray }
  if($obj.HomeDirectory){ Write-Host ("HomeDirectory: {0}" -f $obj.HomeDirectory) -ForegroundColor DarkGray }

  if($obj.ServicePrincipalNames){ Write-Host "ServicePrincipalNames:" -ForegroundColor Yellow; @($obj.ServicePrincipalNames -split ';') | ForEach-Object { if($_){ Write-Host "  $_" -ForegroundColor Yellow } } }
  if($obj.AllowedToDelegateTo){   Write-Host "AllowedToDelegateTo:"   -ForegroundColor Yellow; @($obj.AllowedToDelegateTo -split ';') | ForEach-Object { if($_){ Write-Host "  $_" -ForegroundColor Yellow } } }
  if($obj.TrustedForDelegation){  Write-Host ("TrustedForDelegation: {0}" -f $obj.TrustedForDelegation) -ForegroundColor Yellow }

  if($obj.Groups){
    $grp = @($obj.Groups -split ';') | Where-Object { $_ }
    if((SafeCount $grp) -gt 0){
      Write-Host "Groups (first 6):" -ForegroundColor Gray
      $grp | Select-Object -First 6 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
      if((SafeCount $grp) -gt 6){ Write-Host ("  ...(+" + ((SafeCount $grp)-6) + " more)") -ForegroundColor DarkGray }
    }
  }
  if($obj.Error){ Write-Host "ERROR: $($obj.Error)" -ForegroundColor Red }
}

# --------- MAIN ---------
Ensure-Folder $ExportFolder
$useAD = Try-ImportAD

# Разрешаем DN привилегированных групп (по SID) один раз
$PrivDNs = Resolve-PrivGroupDNs

$users=@(); $adsiList=@(); $adsiMap=@{}

if($useAD){
  $users = @((Get-UsersFromOU_AD -ou $ServiceOU) | Select-Object -ExpandProperty SamAccountName)
  if((SafeCount $users) -eq 0){ $useAD = $false }
}
if(-not $useAD){
  $adsiList = Get-UsersFromOU_ADSI -OUPath $ServiceOU
  $users    = @($adsiList | Select-Object -ExpandProperty Sam)
  foreach($x in $adsiList){ if($x.Sam){ $adsiMap[$x.Sam] = $x.ADSI } }
}

if((SafeCount $users) -eq 0){
  Write-Host "Не найдено учетных записей в $ServiceOU" -ForegroundColor Yellow
  return
}

$report=@(); $i=0; $total=(SafeCount $users)
foreach($s in $users){
  $i++; Write-Progress -Activity "Collecting" -Status "$i/$total $s" -PercentComplete (($i/$total)*100)
  try{
    if($useAD){ $info = AggregateInfo -Sam $s -ADSI $null           -UseAD $true  -PrivDNs $PrivDNs }
    else      { $info = AggregateInfo -Sam $s -ADSI $adsiMap[$s]    -UseAD $false -PrivDNs $PrivDNs }
    $report += $info
  } catch { Write-Warning "Ошибка при агрегации $s: $($_.Exception.Message)" }
}
$report = @($report)

# Сводка/детали
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
