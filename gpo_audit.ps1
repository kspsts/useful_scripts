# gpo_audit.ps1 — PS 5.1, наглядный вывод с подсветкой и шагами исправления

[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string]$Path,
  [string]$Out = "gpo_audit",
  [ValidateSet('Table','Csv','Md')] [string]$Format = 'Table',
  [switch]$OnlyIssues,
  [switch]$IncludeNotFound,
  [switch]$ShowFullPath,
  [switch]$ScanAll,
  [switch]$SummaryPerRule,
  [switch]$Pretty # цветной консольный вывод (рекомендуется)
)

function Remove-Html {
  param([string]$Html)
  $t = $Html -replace '(?s)<script.*?</script>','' -replace '(?s)<style.*?</style>',''
  $t = $t -replace '(?s)<[^>]+>',' ' -replace '&nbsp;',' ' -replace '&amp;','&'
  $t = $t -replace '\s+',' '
  return $t.Trim()
}

function New-Result {
  param($File,$Rule,$Status,$FoundValue,$Note,$DisplayName)
  [pscustomobject]@{
    File            = $DisplayName
    FilePath        = $File
    RuleId          = $Rule.Id
    Category        = $Rule.Category
    Title           = $Rule.Title
    Desired         = ($Rule.Desired -join ' | ')
    Found           = $FoundValue
    Status          = $Status
    Severity        = $Rule.Severity
    Recommendation  = $Rule.Recommendation
    Fix             = $Rule.Fix
    Note            = $Note
  }
}

function Show-PrettyConsole {
  param([array]$Items)
  $byFile = $Items | Group-Object File
  foreach($g in $byFile){
    Write-Host ("`n=== {0} ===" -f $g.Name) -ForegroundColor Cyan
    foreach($r in $g.Group){
      $icon = '✅'; $col = 'Green'
      if($r.Status -eq 'Не ОК'){ $icon='⛔'; $col='Red' }
      elseif($r.Status -eq 'Не найдено'){ $icon='⚠️'; $col='Yellow' }
      Write-Host ("$icon [$($r.Severity)] $($r.Category) — $($r.Title)") -ForegroundColor $col
      if($r.Status -ne 'OK'){
        if($r.Found){ Write-Host ("  Найдено: {0}" -f $r.Found) -ForegroundColor $col }
        if($r.Desired){ Write-Host ("  Ожидается: {0}" -f $r.Desired) -ForegroundColor $col }
        if($r.Recommendation){ Write-Host ("  Рекомендация: {0}" -f $r.Recommendation) -ForegroundColor DarkYellow }
        if($r.Fix){ Write-Host ("  Как исправить: {0}" -f $r.Fix) -ForegroundColor DarkYellow }
      }
      else{
        # кратко подтверждаем OK без лишнего шума
        # Write-Host ("  OK") -ForegroundColor DarkGreen
      }
      Write-Host ""
    }
  }
}

# -------------------- Правила (RU/EN + шаги исправления) --------------------
$Rules = @(
  @{
    Id='NTLM.Outbound.Restrict'; Category='Аутентификация'; Severity='High'
    Title='Сетевая безопасность: ограничения NTLM: исходящий трафик NTLM к удаленным серверам'
    Patterns=@(
      'Сетевая безопасность:\s*ограничения NTLM:\s*исходящий трафик NTLM к удаленным серверам\s*[:\-]\s*([^\.;\r\n<]+)',
      'Network security:\s*Restrict NTLM:\s*Outgoing NTLM traffic to remote servers\s*[:\-]\s*([^\.;\r\n<]+)'
    )
    Desired=@('deny all','audit all','deny all accounts','audit all accounts','блокировать весь трафик','аудит всего трафика')
    Normalize = { param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
    Recommendation='Ограничить/аудировать исходящий NTLM; исключения — через список исключений.'
    Fix='GPMC: Конфигурация компьютера → Параметры Windows → Параметры безопасности → Локальные политики → Параметры безопасности → 
         «Restrict NTLM: Outgoing NTLM traffic to remote servers (…исходящий трафик…)» → значение: "Deny all" или "Audit all".'
  },
  @{
    Id='LMCompatibility'; Category='Аутентификация'; Severity='High'
    Title='Сетевая безопасность: уровень проверки подлинности LAN Manager'
    Patterns=@(
      'Сетевая безопасность:\s*уровень проверки подлинности LAN Manager\s*[:\-]\s*([^\.;\r\n<]+)',
      'Network security:\s*LAN Manager authentication level\s*[:\-]\s*([^\.;\r\n<]+)'
    )
    Desired=@(
      'send ntlmv2 response only. refuse lm & ntlm',
      'только ответ ntlmv2; запрещены lm и ntlm',
      'только отправка ответа ntlmv2; отклонять lm и ntlm'
    )
    Normalize = { param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
    Recommendation='Выставить «Send NTLMv2 response only. Refuse LM & NTLM».'
    Fix='GPMC: ПК → Параметры Windows → Параметры безопасности → Локальные политики → Параметры безопасности → 
         «LAN Manager authentication level» → "Send NTLMv2 response only. Refuse LM & NTLM".'
  },
  @{
    Id='SMB.Sign.Server'; Category='SMB'; Severity='High'
    Title='Microsoft network server: Digitally sign communications (always)'
    Patterns=@(
      'Сетевой доступ.*цифровая подпись.*сообщений.*\(всегда\)\s*[:\-]\s*([^\.;\r\n<]+)',
      'Microsoft network server:\s*Digitally sign communications\s*\(always\)\s*[:\-]\s*([^\.;\r\n<]+)'
    )
    Desired=@('enabled','включено')
    Normalize = { param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
    Recommendation='Обязательная подпись SMB на сервере.'
    Fix='GPMC: ПК → Параметры Windows → Параметры безопасности → Локальные политики → Параметры безопасности → 
         «Microsoft network server: Digitally sign communications (always)» → Enabled.'
  },
  @{
    Id='SMB.Sign.Client'; Category='SMB'; Severity='Medium'
    Title='Microsoft network client: Digitally sign communications (always)'
    Patterns=@(
      'Клиент.*цифровая подпись.*сообщений.*\(всегда\)\s*[:\-]\s*([^\.;\r\n<]+)',
      'Microsoft network client:\s*Digitally sign communications\s*\(always\)\s*[:\-]\s*([^\.;\r\n<]+)'
    )
    Desired=@('enabled','включено')
    Normalize = { param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
    Recommendation='Обязательная подпись SMB на клиенте.'
    Fix='GPMC: ПК → Параметры Windows → Параметры безопасности → Локальные политики → Параметры безопасности → 
         «Microsoft network client: Digitally sign communications (always)» → Enabled.'
  },
  @{
    Id='LDAP.Sign.Client'; Category='LDAP'; Severity='High'
    Title='LDAP-клиент: требовать подпись (Require signing)'
    Patterns=@(
      'Службы каталогов:\s*LDAP.*требовать.*подпис(ь|и)\s*[:\-]\s*([^\.;\r\n<]+)',
      'Network security:\s*LDAP client signing requirements\s*[:\-]\s*([^\.;\r\n<]+)'
    )
    Desired=@('require signing','требовать подпись','require')
    Normalize = { param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
    Recommendation='Включить «Require signing» для LDAP-клиента.'
    Fix='GPMC: ПК → Параметры Windows → Параметры безопасности → Локальные политики → Параметры безопасности → 
         «Network security: LDAP client signing requirements» → Require signing.'
  },
  @{
    Id='RDP.NLA'; Category='RDP'; Severity='High'
    Title='Удалённый рабочий стол: требовать NLA'
    Patterns=@(
      'Службы удалённых рабочих столов.*уровн(я|е) сети.*проверку подлинности\s*[:\-]\s*([^\.;\r\n<]+)',
      'Require user authentication for remote connections by using Network Level Authentication\s*[:\-]\s*([^\.;\r\n<]+)'
    )
    Desired=@('enabled','включено')
    Normalize = { param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
    Recommendation='Требовать NLA для RDP-подключений.'
    Fix='GPMC: ПК → Административные шаблоны → Компоненты Windows → Службы удалённых рабочих столов → Узел сеансов удалённых рабочих столов → Безопасность → 
         «Требовать проверку подлинности на уровне сети» → Enabled.'
  },
  @{
    Id='CachedLogons'; Category='Интерактивный вход'; Severity='Medium'
    Title='Интерактивный вход: количество кэшируемых предыдущих входов'
    Patterns=@(
      'Интерактивный вход.*количество предыдущих подключений к кэшу.*[:\-]\s*([0-9]+)',
      'Interactive logon:\s*Number of previous logons to cache.*[:\-]\s*([0-9]+)'
    )
    Desired=@('0','1')
    Normalize = { param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
    Recommendation='Рекомендуется 0 (максимум 1) кэшируемый вход.'
    Fix='GPMC: ПК → Параметры Windows → Параметры безопасности → Локальные политики → Параметры безопасности → 
         «Interactive logon: Number of previous logons to cache…» → 0 (или 1).'
  },
  @{
    Id='WinRM.DisableBasic'; Category='WinRM'; Severity='Medium'
    Title='WinRM: запрет Basic аутентификации'
    Patterns=@(
      'Windows Remote Management \(WinRM\).*Basic Authentication\s*[:\-]\s*([^\.;\r\n<]+)',
      'WinRM.*Basic Authentication\s*[:\-]\s*([^\.;\r\n<]+)'
    )
    Desired=@('disabled','отключено')
    Normalize = { param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
    Recommendation='Отключить Basic; использовать Kerberos/NTLMv2.'
    Fix='GPMC: ПК → Административные шаблоны → Компоненты Windows → Windows Remote Management (WinRM) → 
         WinRM Client / WinRM Service → «Allow Basic authentication» → Disabled.'
  },
  @{
    Id='LMNR.Disable'; Category='Имя/Разрешение'; Severity='Low'
    Title='Отключение LLMNR'
    Patterns=@(
      'Разрешение имен.*LLMNR.*[:\-]\s*([^\.;\r\n<]+)',
      'Turn off Multicast Name Resolution\s*[:\-]\s*([^\.;\r\n<]+)'
    )
    Desired=@('enabled','включено','on')
    Normalize = { param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
    Recommendation='Включить «Turn off Multicast Name Resolution».'
    Fix='GPMC: ПК → Административные шаблоны → Сеть → Клиент DNS → «Отключить многоадресное разрешение имён (LLMNR) / Turn off MNR» → Enabled.'
  }
)

# -------------------- Сканирование --------------------
$files = Get-ChildItem -Path $Path -Filter *.htm* -Recurse -ErrorAction Stop
if(-not $files){ Write-Error "HTM файлы не найдены в $Path"; exit 1 }

$results = @()

foreach($f in $files){
  $raw = Get-Content -LiteralPath $f.FullName -Raw
  $txt = Remove-Html -Html $raw
  $displayName = if($ShowFullPath){ $f.FullName } else { $f.Name }

  # селективный набор правил по наличию паттернов
  $applicable = @()
  if($ScanAll){
    $applicable = $Rules
  } else {
    foreach($rule in $Rules){
      $hit = $false
      foreach($pat in $rule.Patterns){
        if([regex]::IsMatch($txt, $pat, 'IgnoreCase')){ $hit = $true; break }
      }
      if($hit){ $applicable += $rule }
    }
  }
  if(-not $applicable -or $applicable.Count -eq 0){ continue }

  foreach($rule in $applicable){
    $found = $null
    foreach($pat in $rule.Patterns){
      $m = [regex]::Match($txt, $pat, 'IgnoreCase')
      if($m.Success){ $found = if($m.Groups.Count -gt 1){ $m.Groups[1].Value } else { $m.Value }; break }
    }

    if([string]::IsNullOrWhiteSpace($found)){
      if($IncludeNotFound){
        $results += New-Result -File $f.FullName -Rule $rule -Status 'Не найдено' -FoundValue '' -Note 'Параметр не обнаружен' -DisplayName $displayName
      }
      continue
    }

    $norm = & $rule.Normalize $found
    $desired = $rule.Desired | ForEach-Object { (& $rule.Normalize $_) }
    $ok = $false
    foreach($d in $desired){ if($norm -like "*$d*"){ $ok = $true; break } }

    $status = if($ok){ 'OK' } else { 'Не ОК' }
    if($OnlyIssues -and $status -eq 'OK'){ continue }

    $note = if($ok){ '' } else { 'Значение отличается от рекомендуемого' }
    $results += New-Result -File $f.FullName -Rule $rule -Status $status -FoundValue $found -Note $note -DisplayName $displayName
  }
}

if(-not $results){
  Write-Host "Проблем не обнаружено (по выбранным правилам/файлам)." -ForegroundColor Green
  return
}

# -------------------- Вывод --------------------
if($Format -eq 'Table'){
  if($Pretty){
    Show-PrettyConsole -Items $results
  } else {
    $results | Sort-Object Severity, Category, Title, File |
      Format-Table File,Category,Title,Desired,Found,Status,Severity -AutoSize
  }
}
elseif($Format -eq 'Csv'){
  $csv = Join-Path (Resolve-Path .) "$Out.csv"
  $results | Sort-Object FilePath, RuleId | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
  Write-Host "CSV сохранён: $csv" -ForegroundColor Green
}
elseif($Format -eq 'Md'){
  $md = Join-Path (Resolve-Path .) "$Out.md"
  "# GPO Audit Report`n`nДата: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" | Out-File -FilePath $md -Encoding UTF8

  if($SummaryPerRule){
    "## Сводка по правилам`n" | Out-File -FilePath $md -Append -Encoding UTF8
    $byRule = $results | Group-Object RuleId
    foreach($g in $byRule){
      $title = $g.Group[0].Title
      $bad = ($g.Group | Where-Object Status -eq 'Не ОК')
      $okc = ($g.Group | Where-Object Status -eq 'OK').Count
      "### $title`n- OK: $okc; Не ОК: $($bad.Count)`n" | Out-File -FilePath $md -Append -Encoding UTF8
      if($bad.Count -gt 0){
        "| Файл | Найдено | Рекомендация / Шаги |`n|---|---|---|" | Out-File -FilePath $md -Append -Encoding UTF8
        foreach($r in $bad){
          "| $($r.File) | $($r.Found) | $($r.Recommendation) — $($r.Fix) |" | Out-File -FilePath $md -Append -Encoding UTF8
        }
        "`n" | Out-File -FilePath $md -Append -Encoding UTF8
      }
    }
  } else {
    "## По файлам`n" | Out-File -FilePath $md -Append -Encoding UTF8
    $byFile = $results | Sort-Object File, Severity, Category | Group-Object File
    foreach($g in $byFile){
      "### $($g.Name)`n| Категория | Параметр | Рекомендовано | Найдено | Статус | Шаги исправления |`n|---|---|---|---|---|---|" |
        Out-File -FilePath $md -Append -Encoding UTF8
      foreach($r in $g.Group){
        $st = if($r.Status -eq 'OK'){'OK'} else {'Не ОК'}
        "| $($r.Category) | $($r.Title) | $($r.Desired) | $($r.Found) | $st | $($r.Fix) |" |
          Out-File -FilePath $md -Append -Encoding UTF8
      }
      "`n" | Out-File -FilePath $md -Append -Encoding UTF8
    }
  }
  Write-Host "Markdown сохранён: $md" -ForegroundColor Green
}

$counts = $results | Group-Object Status | Select-Object Name,Count
Write-Host ("Итог: {0}" -f (($counts | ForEach-Object { "$($_.Name): $($_.Count)" }) -join '; ')) -ForegroundColor Cyan

