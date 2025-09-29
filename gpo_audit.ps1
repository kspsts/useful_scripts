<# 
.SYNOPSIS
  GPO HTM аудит по лучшим практикам (RU/EN названия параметров).

.USAGE
  .\gpo_audit.ps1 -Path 'C:\GPO\export' [-Out 'report'] [-Format 'Table|Csv|Md']

.NOTES
  Минимально самодостаточно, без внешних модулей. Правила легко расширять внутри $Rules.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [string]$Path,
  [string]$Out = "gpo_audit",
  [ValidateSet('Table','Csv','Md')]
  [string]$Format = 'Table'
)

# -------------------- Utils --------------------
function Remove-Html {
  param([string]$Html)
  $t = $Html -replace '(?s)<script.*?</script>','' -replace '(?s)<style.*?</style>',''
  $t = $t -replace '(?s)<[^>]+>',' ' -replace '&nbsp;',' ' -replace '&amp;','&'
  $t = $t -replace '\s+',' ' 
  return $t.Trim()
}

function New-Result {
  param($File,$Rule,$Status,$FoundValue,$Note)
  [pscustomobject]@{
    File        = [IO.Path]::GetFileName($File)
    RuleId      = $Rule.Id
    Category    = $Rule.Category
    Title       = $Rule.Title
    Desired     = ($Rule.Desired -join ' | ')
    Found       = $FoundValue
    Status      = $Status
    Severity    = $Rule.Severity
    Recommendation = $Rule.Recommendation
    Note        = $Note
  }
}

# -------------------- Правила --------------------
# Каждое правило: несколько regex под RU/EN, Desired = допустимые значения (после нормализации к lower).
$Rules = @(
  @{
    Id='NTLM.Outbound.Restrict'
    Category='Аутентификация'
    Severity='High'
    Title='Сетевая безопасность: ограничения NTLM: исходящий трафик NTLM к удаленным серверам'
    Patterns=@(
      'Сетевая безопасность:\s*ограничения NTLM:\s*исходящий трафик NTLM к удаленным серверам\s*[:\-]\s*([^\.;\r\n<]+)',
      'Network security:\s*Restrict NTLM:\s*Outgoing NTLM traffic to remote servers\s*[:\-]\s*([^\.;\r\n<]+)'
    )
    Desired=@('deny all','audit all','deny all accounts','audit all accounts','блокировать весь трафик','аудит всего трафика')
    Normalize = { param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
    Recommendation='Ограничить или аудировать исходящий NTLM; исключения — через список исключений.'
  },
  @{
    Id='LMCompatibility'
    Category='Аутентификация'
    Severity='High'
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
    Recommendation='Установить: «Только отправка ответа NTLMv2; отклонять LM и NTLM».'
  },
  @{
    Id='SMB.Sign.Server'
    Category='SMB'
    Severity='High'
    Title='Microsoft network server: Digitally sign communications (always)'
    Patterns=@(
      'Сетевой доступ к ресурсам Майкрософт:\s*цифровая подпись\s*сообщений\s*\(всегда\)\s*[:\-]\s*([^\.;\r\n<]+)',
      'Microsoft network server:\s*Digitally sign communications\s*\(always\)\s*[:\-]\s*([^\.;\r\n<]+)'
    )
    Desired=@('enabled','включено')
    Normalize = { param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
    Recommendation='Включить обязательную цифровую подпись SMB на стороне сервера.'
  },
  @{
    Id='SMB.Sign.Client'
    Category='SMB'
    Severity='Medium'
    Title='Microsoft network client: Digitally sign communications (always)'
    Patterns=@(
      'Клиент сетевого доступа Майкрософт:\s*цифровая подпись\s*сообщений\s*\(всегда\)\s*[:\-]\s*([^\.;\r\n<]+)',
      'Microsoft network client:\s*Digitally sign communications\s*\(always\)\s*[:\-]\s*([^\.;\r\n<]+)'
    )
    Desired=@('enabled','включено')
    Normalize = { param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
    Recommendation='Включить обязательную цифровую подпись SMB на стороне клиента.'
  },
  @{
    Id='LDAP.Sign.Client'
    Category='LDAP'
    Severity='High'
    Title='LDAP-клиент: требовать подпись (Require signing)'
    Patterns=@(
      'Службы каталогов:\s*LDAP.*требовать.*подпис(ь|и)\s*[:\-]\s*([^\.;\r\n<]+)',
      'Network security:\s*LDAP client signing requirements\s*[:\-]\s*([^\.;\r\n<]+)'
    )
    Desired=@('require signing','требовать подпись','require')
    Normalize = { param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
    Recommendation='Установить «Require signing» для LDAP-клиента.'
  },
  @{
    Id='RDP.NLA'
    Category='RDP'
    Severity='High'
    Title='Удалённый рабочий стол: требовать NLA'
    Patterns=@(
      'Службы удалённых рабочих столов.*требовать.*проверку подлинности на уровне сети\s*[:\-]\s*([^\.;\r\n<]+)',
      'Require user authentication for remote connections by using Network Level Authentication\s*[:\-]\s*([^\.;\r\n<]+)'
    )
    Desired=@('enabled','включено')
    Normalize = { param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
    Recommendation='Включить NLA для RDP.'
  },
  @{
    Id='CachedLogons'
    Category='Интерактивный вход'
    Severity='Medium'
    Title='Интерактивный вход: количество кэшируемых предыдущих входов'
    Patterns=@(
      'Интерактивный вход.*количество предыдущих подключений к кэшу.*[:\-]\s*([0-9]+)',
      'Interactive logon:\s*Number of previous logons to cache.*[:\-]\s*([0-9]+)'
    )
    Desired=@('0','1') # строгая рекомендация — 0; допускаем 1
    Normalize = { param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
    Recommendation='Установить 0 (или максимум 1) кэшируемый вход.'
  },
  @{
    Id='WinRM.DisableBasic'
    Category='WinRM'
    Severity='Medium'
    Title='WinRM: запрет Basic аутентификации'
    Patterns=@(
      'Windows Remote Management \(WinRM\).*Basic Authentication\s*[:\-]\s*([^\.;\r\n<]+)',
      'WinRM.*Basic Authentication\s*[:\-]\s*([^\.;\r\n<]+)'
    )
    Desired=@('disabled','отключено')
    Normalize = { param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
    Recommendation='Отключить Basic для WinRM; использовать Kerberos/NTLMv2.'
  },
  @{
    Id='LMNR.Disable'
    Category='Имя/Разрешение'
    Severity='Low'
    Title='Отключение LLMNR'
    Patterns=@(
      'Разрешение имен.*LLMNR.*[:\-]\s*([^\.;\r\n<]+)',
      'Turn off Multicast Name Resolution\s*[:\-]\s*([^\.;\r\n<]+)'
    )
    Desired=@('enabled','включено','on')
    Normalize = { param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
    Recommendation='Включить политику «Отключить мультикаст-разрешение имён (LLMNR)».'
  }
)

# -------------------- Поиск и оценка --------------------
$files = Get-ChildItem -Path $Path -Filter *.htm* -Recurse -ErrorAction Stop
if(-not $files){ Write-Error "HTM файлы не найдены в $Path"; exit 1 }

$results = New-Object System.Collections.Generic.List[object]

foreach($f in $files){
  $raw = Get-Content -LiteralPath $f.FullName -Raw
  $txt = Remove-Html -Html $raw

  foreach($rule in $Rules){
    $found = $null
    foreach($pat in $rule.Patterns){
      $m = [regex]::Match($txt, $pat, 'IgnoreCase')
      if($m.Success){
        # Берём первую захваченную группу как значение
        $found = if($m.Groups.Count -gt 1){ $m.Groups[1].Value } else { $m.Value }
        break
      }
    }

    if($null -eq $found){
      $results.Add( (New-Result -File $f.FullName -Rule $rule -Status 'Не найдено' -FoundValue '' -Note 'Параметр не обнаружен') ) | Out-Null
      continue
    }

    $norm = & $rule.Normalize $found
    $desired = $rule.Desired | ForEach-Object { (& $rule.Normalize $_) }

    $ok = $false
    foreach($d in $desired){
      if($norm -like "*$d*"){ $ok = $true; break }
    }

    $status = if($ok){ 'OK' } else { 'Не ОК' }
    $note = if($ok){ '' } else { 'Значение отличается от рекомендуемого' }

    $results.Add( (New-Result -File $f.FullName -Rule $rule -Status $status -FoundValue=$found -Note=$note) ) | Out-Null
  }
}

# -------------------- Вывод --------------------
switch($Format){
  'Table' {
    $results | Sort-Object Severity, Category, Title | Format-Table File,Category,Title,Desired,Found,Status,Severity -AutoSize
  }
  'Csv' {
    $csv = Join-Path (Resolve-Path .) "$Out.csv"
    $results | Sort-Object File, RuleId | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    Write-Host "CSV сохранён: $csv" -ForegroundColor Green
  }
  'Md' {
    $md = Join-Path (Resolve-Path .) "$Out.md"
    "# GPO Audit Report`n`nДата: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n`n" | Out-File -FilePath $md -Encoding UTF8
    ($results | Sort-Object File, Severity, Category | ForEach-Object {
      $st = if($_.Status -eq 'OK'){'✅ OK'} elseif($_.Status -eq 'Не ОК'){'❌ Не ОК'} else {'⚠️ Не найдено'}
      "| $($_.File) | $($_.Category) | $($_.Title) | $($_.Desired) | $($_.Found) | $st | $($_.Severity) |" 
    }) | ForEach-Object { $_ } | Out-File -FilePath $md -Append -Encoding UTF8
    # Заголовок таблицы
    $content = Get-Content $md
    $header = @(
      "# GPO Audit Report",
      "",
      "Дата: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
      "",
      "| Файл | Категория | Параметр | Рекомендовано | Найдено | Статус | Критичность |",
      "|---|---|---|---|---|---|---|"
    )
    $header + $content[4..($content.Length-1)] | Set-Content -Path $md -Encoding UTF8
    Write-Host "Markdown сохранён: $md" -ForegroundColor Green
  }
}

# Итоговая сводка
$counts = $results | Group-Object Status | Select-Object Name,Count
Write-Host ("Итог: {0}" -f (($counts | ForEach-Object { "$($_.Name): $($_.Count)" }) -join '; ')) -ForegroundColor Cyan

