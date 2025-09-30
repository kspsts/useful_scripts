<# 
gpo_audit.ps1 — Аудит HTM-выгрузок GPO по лучшим практикам (PS 5.1)

Параметры:
  -Path <dir>            Папка с *.htm* файлами GPO-выгрузки
  -Out <name>            Имя отчёта (без расширения), по умолчанию gpo_audit
  -Format Table|Csv|Md   Формат вывода (Table по умолчанию)
  -OnlyIssues            Показывать только "Не ОК" (и "Не найдено" если -IncludeNotFound)
  -IncludeNotFound       Включать "Не найдено"
  -ShowFullPath          Печатать полный путь к файлам
  -ScanAll               Проверять все правила для всех файлов (отключает селективный режим)
  -SummaryPerRule        В Md-отчёте выводить сводку по правилам
  -Pretty                Цветной консольный вывод с рекомендациями
  -Profiles <string[]>   Отбор блоков правил: DC, TLS, Firewall, Print, LAPS, Office, Browser, Defender, PowerShell, AppLocker, Base
#>

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
  [switch]$Pretty,
  [string[]]$Profiles
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
  param($File,$Rule,$Status,$FoundValue,$Note,$DisplayName)
  [pscustomobject]@{
    File            = $DisplayName
    FilePath        = $File
    RuleId          = $Rule.Id
    Category        = $Rule.Category
    Title           = $Rule.Title
    Desired         = if($Rule.PSObject.Properties.Name -contains 'DesiredText' -and $Rule.DesiredText){ $Rule.DesiredText } else { ($Rule.Desired -join ' | ') }
    Found           = if($FoundValue -and $FoundValue.Length -gt 400){ ($FoundValue.Substring(0,400).Trim() + ' …') } else { $FoundValue }
    Status          = $Status
    Severity        = $Rule.Severity
    Recommendation  = $Rule.Recommendation
    Fix             = $Rule.Fix
    Note            = $Note
  }
}

function Show-PrettyConsole {
  param(
    [array]$Items,
    [switch]$IncludeNotFound
  )

  if(-not $Items -or $Items.Count -eq 0){
    Write-Host "Нет записей для отображения." -ForegroundColor Green
    return
  }

  $severityWeight = @{ High = 0; Medium = 1; Low = 2; Info = 3 }
  $statusWeight   = @{ 'Не ОК' = 0; 'Не найдено' = 1; 'OK' = 2 }

  $sorted = $Items | Sort-Object @{ Expression = { if($statusWeight.ContainsKey($_.Status)){ $statusWeight[$_.Status] } else { 99 } } }, @{ Expression = { if($severityWeight.ContainsKey($_.Severity)){ $severityWeight[$_.Severity] } else { 9 } } }, 'File','Category','Title'

  $currentFile = $null
  foreach($r in $sorted){
    if($currentFile -ne $r.File){
      Write-Host ("`n=== {0} ===" -f $r.File) -ForegroundColor Cyan
      $currentFile = $r.File
    }

    $icon = '✅'; $col = 'Green'; $state = '[OK]'
    if($r.Status -eq 'Не ОК'){
      $icon = '⛔'; $col = 'Red'; $state = '[ISSUE]'
    }
    elseif($r.Status -eq 'Не найдено'){
      if(-not $IncludeNotFound){ continue }
      $icon = '⚠️'; $col = 'Yellow'; $state = '[WARN]'
    }

    Write-Host ("$icon $state [$($r.Severity)] $($r.Category) - $($r.Title)") -ForegroundColor $col
    Write-Host ("  Правило: $($r.RuleId)") -ForegroundColor DarkGray

    if($r.Status -ne 'OK'){
      if($r.Found){ Write-Host ("  Найдено:   {0}" -f $r.Found.Trim()) -ForegroundColor DarkGray }
      if($r.Desired){ Write-Host ("  Ожидается: {0}" -f $r.Desired.Trim()) -ForegroundColor DarkGray }
      if($r.Recommendation){ Write-Host ("  Рекомендация: {0}" -f $r.Recommendation) -ForegroundColor Magenta }
      if($r.Fix){ Write-Host ("  Как исправить: {0}" -f $r.Fix) -ForegroundColor DarkYellow }
      if($r.Note){ Write-Host ("  Примечание: {0}" -f $r.Note) -ForegroundColor DarkCyan }
    }

    if($r.Status -eq 'OK' -and $r.Note){
      Write-Host ("  Примечание: {0}" -f $r.Note) -ForegroundColor DarkCyan
    }

    Write-Host ""
  }
}

function Get-FirstInt { param([string]$s) $m=[regex]::Match($s,'\d+'); if($m.Success){[int]$m.Value} else {$null} }

function Resolve-ReportPath {
  param(
    [Parameter(Mandatory=$true)][string]$Base,
    [Parameter(Mandatory=$true)][string]$Extension
  )

  $target = $Base
  $ext = [System.IO.Path]::GetExtension($target)
  if([string]::IsNullOrWhiteSpace($ext)){
    $target = "{0}.{1}" -f $target, $Extension
  }
  elseif($ext.TrimStart('.') -ne $Extension){
    $target = [System.IO.Path]::ChangeExtension($target, $Extension)
  }

  if(-not [System.IO.Path]::IsPathRooted($target)){
    $target = Join-Path -Path (Get-Location) -ChildPath $target
  }

  return [System.IO.Path]::GetFullPath($target)
}

function Select-OutputItems {
  param(
    [array]$Source,
    [switch]$IncludeNotFound,
    [switch]$OnlyIssues
  )

  if(-not $Source){ return @() }

  $items = $Source
  if($OnlyIssues){
    $items = $items | Where-Object { $_.Status -ne 'OK' }
  }
  if(-not $IncludeNotFound){
    $items = $items | Where-Object { $_.Status -ne 'Не найдено' }
  }

  return @($items)
}

function Escape-Markdown {
  param([string]$Value)

  if([string]::IsNullOrWhiteSpace($Value)){ return '' }

  $escaped = $Value.Replace('|','\|')
  $escaped = $escaped -replace "\r?\n", '<br>'
  return $escaped.Trim()
}

# -------------------- Правила --------------------
# Принцип: Patterns (RU/EN), Desired (или DesiredText), Normalize, опционально Compare, Fix, Profiles.
# Если Profiles не задан — правило относится к Base.

$Rules = @(
  # ======== Аутентификация / NTLM / LDAP / Kerberos ========
  @{ Id='NTLM.Outbound.Restrict'; Category='Аутентификация'; Severity='High'; Profiles=@('Base')
     Title='Restrict NTLM: исходящий трафик к удалённым серверам'
     Patterns=@(
       'Сетевая безопасность:\s*ограничения NTLM:\s*исходящий трафик NTLM к удаленным серверам\s*[:\-]\s*([^\.;\r\n<]+)',
       'Network security:\s*Restrict NTLM:\s*Outgoing NTLM traffic to remote servers\s*[:\-]\s*([^\.;\r\n<]+)'
     )
     Desired=@('deny all','audit all','deny all accounts','audit all accounts','блокировать весь трафик','аудит всего трафика')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Ограничить/аудировать исходящий NTLM; исключения — через список исключений.'
     Fix='ПК → Параметры Windows → Параметры безопасности → Локальные политики → Параметры безопасности → «Restrict NTLM: Outgoing NTLM traffic…» → Deny all/Audit all.'
  },
  @{ Id='LMCompatibility'; Category='Аутентификация'; Severity='High'; Profiles=@('Base')
     Title='LAN Manager authentication level'
     Patterns=@(
       'Сетевая безопасность:\s*уровень проверки подлинности LAN Manager\s*[:\-]\s*([^\.;\r\n<]+)',
       'Network security:\s*LAN Manager authentication level\s*[:\-]\s*([^\.;\r\n<]+)'
     )
     Desired=@('send ntlmv2 response only. refuse lm & ntlm','только ответ ntlmv2; запрещены lm и ntlm','только отправка ответа ntlmv2; отклонять lm и ntlm')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Выставить «Send NTLMv2 response only. Refuse LM & NTLM».'
     Fix='ПК → Параметры Windows → Параметры безопасности → Локальные политики → Параметры безопасности → «LAN Manager authentication level» → нужное значение.'
  },
  @{ Id='LDAP.Client.Signing'; Category='LDAP'; Severity='High'; Profiles=@('Base')
     Title='LDAP client signing requirements'
     Patterns=@(
       'Службы каталогов:\s*LDAP.*требовать.*подпис(ь|и)\s*[:\-]\s*([^\.;\r\n<]+)',
       'Network security:\s*LDAP client signing requirements\s*[:\-]\s*([^\.;\r\n<]+)'
     )
     Desired=@('require signing','требовать подпись','require')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Включить «Require signing» для LDAP-клиента.'
     Fix='ПК → Параметры Windows → Параметры безопасности → Локальные политики → Параметры безопасности → «LDAP client signing requirements» → Require.'
  },
  @{ Id='LDAP.Server.Signing'; Category='LDAP'; Severity='High'; Profiles=@('DC')
     Title='Domain controller: LDAP server signing requirements'
     Patterns=@(
       'Domain controller:\s*LDAP server signing requirements\s*[:\-]\s*([^\r\n<]+)',
       'Контроллер домена:\s*требования к подписи сервера LDAP\s*[:\-]\s*([^\r\n<]+)'
     )
     Desired=@('Require signing','Требовать подпись')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='На КД требовать подпись LDAP.'
     Fix='ПК → Параметры Windows → Параметры безопасности → Локальные политики → Параметры безопасности → «Domain controller: LDAP server signing requirements» → Require.'
  },
  @{ Id='LDAP.Server.CBT'; Category='LDAP'; Severity='High'; Profiles=@('DC')
     Title='Domain controller: LDAP server channel binding'
     Patterns=@(
       'Domain controller:\s*LDAP server channel binding\s*[:\-]\s*([^\r\n<]+)',
       'Контроллер домена:\s*привязка каналов сервера LDAP\s*[:\-]\s*([^\r\n<]+)'
     )
     Desired=@('required','требуется')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Включить LDAP Channel Binding (CBT) на КД.'
     Fix='ПК → Параметры Windows → Параметры безопасности → «Domain controller: LDAP server channel binding» → Required.'
  },
  @{ Id='Kerberos.EnforceUserLogonRestrictions'; Category='Kerberos'; Severity='Medium'; Profiles=@('DC')
     Title='Kerberos: Enforce user logon restrictions'
     Patterns=@(
       'Enforce user logon restrictions\s*[:\-]\s*([^\r\n<]+)',
       'Обеспечивать ограничения входа пользователя\s*[:\-]\s*([^\r\n<]+)'
     )
     Desired=@('Enabled','Включено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Включить проверку ограничений входа Kerberos.'
     Fix='ПК → Параметры Windows → Параметры безопасности → Политики Kerberos → «Enforce user logon restrictions» → Enabled.'
  },

  # ======== SMB / Гости / Аноним ========
  @{ Id='SMB.Sign.Server'; Category='SMB'; Severity='High'; Profiles=@('Base')
     Title='Microsoft network server: Digitally sign communications (always)'
     Patterns=@(
       'Сетевой доступ.*цифровая подпись.*сообщений.*\(всегда\)\s*[:\-]\s*([^\.;\r\n<]+)',
       'Microsoft network server:\s*Digitally sign communications\s*\(always\)\s*[:\-]\s*([^\.;\r\n<]+)'
     )
     Desired=@('enabled','включено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Обязательная подпись SMB на сервере.'
     Fix='ПК → Параметры безопасности → «Microsoft network server: Digitally sign communications (always)» → Enabled.'
  },
  @{ Id='SMB.Sign.Client'; Category='SMB'; Severity='Medium'; Profiles=@('Base')
     Title='Microsoft network client: Digitally sign communications (always)'
     Patterns=@(
       'Клиент.*цифровая подпись.*сообщений.*\(всегда\)\s*[:\-]\s*([^\.;\r\n<]+)',
       'Microsoft network client:\s*Digitally sign communications\s*\(always\)\s*[:\-]\s*([^\.;\r\n<]+)'
     )
     Desired=@('enabled','включено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Обязательная подпись SMB на клиенте.'
     Fix='ПК → Параметры безопасности → «Microsoft network client: Digitally sign communications (always)» → Enabled.'
  },
  @{ Id='SMB.Guest.Insecure'; Category='SMB'; Severity='High'; Profiles=@('Base')
     Title='Enable insecure guest logons (должно быть Disabled)'
     Patterns=@(
       'Enable insecure guest logons\s*[:\-]\s*([^\r\n<]+)',
       'Разрешить небезопасные гостевые входы\s*[:\-]\s*([^\r\n<]+)'
     )
     Desired=@('Disabled','Отключено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Запретить небезопасные гостевые входы SMB.'
     Fix='ПК → Адм. шаблоны → Сеть → Lanman Workstation → «Enable insecure guest logons» → Disabled.'
  },
  @{ Id='SMBv1.Disable'; Category='SMB'; Severity='Critical'; Profiles=@('Base')
     Title='Отключение SMBv1'
     Patterns=@(
       'Value name\s*SMB1\s*Value type\s*REG_DWORD\s*Value data\s*([0-9x ()]+)',
       'Lanman(?:Server|Workstation).*?(?:SMB1|SMB 1\.0).*?(?:value data|=)?\s*([0-9x ()]+)',
       'Включить протокол SMB 1\.0.*?[:\-]?\s*([^\r\n<]+)'
     )
     Desired=@('Disabled','Отключено','0','0x0')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Полностью отключить SMBv1 (клиент и сервер).'
     Fix='Отключить компонент «SMB 1.0/CIFS», проверить реестр: HKLM\SYSTEM\CCS\Services\LanmanServer\Parameters\SMB1=0.'
     Compare={
       param($found)
       $norm = ($found -replace '\s+',' ').Trim().ToLowerInvariant()
       if($norm -match '(?<![0-9a-z])0x0(?![0-9a-z])'){ return $true }
       if($norm -match '(?<![0-9a-z])0(?![0-9a-z])'){ return $true }
       if($norm -match 'disabled'){ return $true }
       if($norm -match 'отключ'){ return $true }
       return $false
     }
  },
  @{ Id='Anonymous.SAM'; Category='Security Options'; Severity='High'; Profiles=@('Base')
     Title='Network access: Do not allow anonymous enumeration of SAM accounts'
     Patterns=@(
       'Network access:\s*Do not allow anonymous enumeration of SAM accounts\s*[:\-]\s*([^\r\n<]+)',
       'Сетевой доступ:\s*запретить анонимное перечисление учетных записей SAM\s*[:\-]\s*([^\r\n<]+)'
     )
     Desired=@('Enabled','Включено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Запретить анонимное перечисление SAM.'
     Fix='ПК → Параметры безопасности → «Do not allow anonymous enumeration of SAM accounts» → Enabled.'
  },
  @{ Id='Anonymous.SAMShares'; Category='Security Options'; Severity='High'; Profiles=@('Base')
     Title='Network access: Do not allow anonymous enumeration of SAM accounts and shares'
     Patterns=@(
       'Do not allow anonymous enumeration of SAM accounts and shares\s*[:\-]\s*([^\r\n<]+)',
       'запретить анонимное перечисление учетных записей SAM и ресурсов\s*[:\-]\s*([^\r\n<]+)'
     )
     Desired=@('Enabled','Включено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Запретить анонимное перечисление SAM и расшаренных ресурсов.'
     Fix='ПК → Параметры безопасности → соответствующий параметр → Enabled.'
  },
  @{ Id='NoLMHash'; Category='Security Options'; Severity='High'; Profiles=@('Base')
     Title='Network security: Do not store LAN Manager hash value on next password change'
     Patterns=@(
       'Do not store LAN Manager hash value.*[:\-]\s*([^\r\n<]+)',
       'Не сохранять значение хэша LAN Manager.*[:\-]\s*([^\r\n<]+)'
     )
     Desired=@('Enabled','Включено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Не хранить LM-хэш паролей.'
     Fix='ПК → Параметры безопасности → «Do not store LAN Manager hash value…» → Enabled.'
  },

  # ======== RDP ========
  @{ Id='RDP.NLA'; Category='RDP'; Severity='High'; Profiles=@('Base')
     Title='Требовать NLA для RDP'
     Patterns=@(
       'Службы удалённых рабочих столов.*уровн(я|е) сети.*проверку подлинности\s*[:\-]\s*([^\.;\r\n<]+)',
       'Require user authentication for remote connections by using Network Level Authentication\s*[:\-]\s*([^\.;\r\n<]+)'
     )
     Desired=@('enabled','включено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Требовать NLA для RDP-подключений.'
     Fix='ПК → Адм. шаблоны → RDP → Безопасность → «Требовать NLA» → Enabled.'
  },
  @{ Id='RDP.MinEncryptionLevel'; Category='RDP'; Severity='High'; Profiles=@('Base')
     Title='RDP: минимальный уровень шифрования'
     Patterns=@(
       'Set client connection encryption level\s*[:\-]\s*([^\r\n<]+)',
       'Уровень шифрования подключения.*[:\-]\s*([^\r\n<]+)'
     )
     DesiredText='High или FIPS'
     Desired=@()
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Требовать High (или FIPS) для RDP.'
     Fix='ПК → Адм. шаблоны → RDP → Безопасность → «Уровень шифрования…».'
     Compare={ param($found) $n=($found -replace '\s+',' ').ToLowerInvariant(); ($n -match 'high' -or $n -match 'высок' -or $n -match 'fips') }
  },
  @{ Id='RDP.Session.Limit'; Category='RDP'; Severity='Low'; Profiles=@('Base')
     Title='Ограничение параллельных RDP-сессий'
     Patterns=@(
       'Limit number of connections\s*[:\-]\s*([0-9]+)',
       'Ограничение количества подключений\s*[:\-]\s*([0-9]+)'
     )
     DesiredText='не более 2'
     Desired=@()
     Normalize={ param($s) $s }
     Recommendation='Ограничить одновременные RDP-соединения.'
     Fix='ПК → Адм. шаблоны → RDP → Подключения → «Ограничить число подключений».'
     Compare={ param($found) $v=Get-FirstInt $found; $v -le 2 }
  },

  # ======== WinRM / LLMNR ========
  @{ Id='WinRM.DisableBasic'; Category='WinRM'; Severity='Medium'; Profiles=@('Base')
     Title='WinRM: запрет Basic аутентификации'
     Patterns=@(
       'Windows Remote Management \(WinRM\).*Basic Authentication\s*[:\-]\s*([^\.;\r\n<]+)',
       'WinRM.*Basic Authentication\s*[:\-]\s*([^\.;\r\n<]+)'
     )
     Desired=@('disabled','отключено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Отключить Basic; использовать Kerberos/NTLMv2.'
     Fix='ПК → Адм. шаблоны → WinRM Client/Service → «Allow Basic authentication» → Disabled.'
  },
  @{ Id='LLMNR.Disable'; Category='Сеть'; Severity='Medium'; Profiles=@('Base')
     Title='Отключение LLMNR'
     Patterns=@(
       'Разрешение имен.*LLMNR.*[:\-]\s*([^\.;\r\n<]+)',
       'Turn off Multicast Name Resolution\s*[:\-]\s*([^\.;\r\n<]+)'
     )
     Desired=@('enabled','включено','on')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Включить «Turn off Multicast Name Resolution».'
     Fix='ПК → Адм. шаблоны → Сеть → Клиент DNS → «Turn off Multicast Name Resolution» → Enabled.'
  },

  # ======== Пароли / Блокировки ========
  @{ Id='Password.Complexity'; Category='Пароли'; Severity='High'; Profiles=@('Base')
     Title='Пароль должен соответствовать требованиям сложности'
     Patterns=@(
       'Password must meet complexity requirements\s*[:\-]\s*([^\r\n<]+)',
       'Пароль должен соответствовать требованиям сложности\s*[:\-]\s*([^\r\n<]+)'
     )
     Desired=@('Enabled','Включено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Включить требования сложности для паролей.'
     Fix='ПК → Параметры безопасности → Политика паролей → «Требовать сложность паролей» → Включено.'
  },
  @{ Id='Account.Lockout.Duration'; Category='Учетные записи'; Severity='High'; Profiles=@('Base')
     Title='Длительность блокировки учетной записи (мин)'
     Patterns=@(
       'Account lockout duration\s*[:\-]\s*([0-9]+)',
       'Длительность блокировки учетной записи\s*[:\-]\s*([0-9]+)'
     )
     DesiredText='15–60 минут'
     Desired=@()
     Normalize={ param($s) $s }
     Recommendation='Рекомендуется 15–60 минут.'
     Fix='ПК → Параметры безопасности → Политика блокировки учетных записей → «Длительность блокировки».'
     Compare={ param($found) $v=Get-FirstInt $found; ($v -ge 15 -and $v -le 60) }
  },
  @{ Id='CachedLogons'; Category='Интерактивный вход'; Severity='Medium'; Profiles=@('Base')
     Title='Кэш предыдущих входов (рекомендуемо 0–1)'
     Patterns=@(
       'Интерактивный вход.*количество предыдущих подключений к кэшу.*[:\-]\s*([0-9]+)',
       'Interactive logon:\s*Number of previous logons to cache.*[:\-]\s*([0-9]+)'
     )
     DesiredText='0 (допустимо 1)'
     Desired=@()
     Normalize={ param($s) $s }
     Recommendation='Минимизировать кэш входов.'
     Fix='ПК → Параметры безопасности → «Interactive logon: Number of previous logons to cache…» → 0 (или 1).'
     Compare={ param($found) $v=Get-FirstInt $found; $v -le 1 }
  },

  # ======== BitLocker / Шифрование ========
  @{ Id='BitLocker.RemovableDrives'; Category='Шифрование'; Severity='High'; Profiles=@('Base')
     Title='BitLocker: шифрование съёмных дисков'
     Patterns=@(
       'BitLocker.*removable drives\s*[:\-]?\s*([^\r\n<]+)',
       'Шифрование съёмных дисков.*[:\-]?\s*([^\r\n<]+)'
     )
     Desired=@('Enabled','Включено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Требовать шифрование USB-носителей.'
     Fix='ПК → Адм. шаблоны → Компоненты Windows → BitLocker → Съёмные диски → «Требовать шифрование…» → Enabled.'
  },

  # ======== TLS / Schannel (через реестр в Preferences) ========
  @{ Id='TLS10.Disable'; Category='TLS'; Severity='High'; Profiles=@('TLS')
     Title='TLS 1.0: Server/Client Enabled = 0'
     Patterns=@(
       'Protocols\\TLS 1\.0\\(Client|Server)\\Enabled.*[:\-]\s*(0)',
       'SCHANNEL.*TLS 1\.0.*Enabled.*[:\-]\s*0'
     )
     Desired=@('0')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Отключить TLS 1.0 на клиенте и сервере.'
     Fix='Preferences → Windows Settings → Registry: ...\SCHANNEL\Protocols\TLS 1.0\(Client|Server)\Enabled=0 (DWORD).'
  },
  @{ Id='TLS11.Disable'; Category='TLS'; Severity='High'; Profiles=@('TLS')
     Title='TLS 1.1: Server/Client Enabled = 0'
     Patterns=@(
       'Protocols\\TLS 1\.1\\(Client|Server)\\Enabled.*[:\-]\s*(0)',
       'SCHANNEL.*TLS 1\.1.*Enabled.*[:\-]\s*0'
     )
     Desired=@('0')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Отключить TLS 1.1 на клиенте и сервере.'
     Fix='Preferences → Windows Settings → Registry: ...\SCHANNEL\Protocols\TLS 1.1\(Client|Server)\Enabled=0 (DWORD).'
  },
  @{ Id='TLS.CipherSuiteOrder'; Category='TLS'; Severity='Medium'; Profiles=@('TLS')
     Title='SSL Cipher Suite Order (должно быть включено)'
     Patterns=@(
       'SSL Cipher Suite Order\s*[:\-]\s*([^\r\n<]+)',
       'Порядок наборов шифров SSL\s*[:\-]\s*([^\r\n<]+)'
     )
     Desired=@('Enabled','Включено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Задать упорядоченный безопасный список шифров.'
     Fix='ПК → Параметры безопасности → «SSL Cipher Suite Order» → Enabled (со списком).'
  },

  # ======== Брандмауэр ========
  @{ Id='Firewall.Domain.On'; Category='Firewall'; Severity='High'; Profiles=@('Firewall')
     Title='Windows Defender Firewall (Domain) = On'
     Patterns=@(
       'Windows Defender Firewall: Domain Profile: State\s*[:\-]\s*([^\r\n<]+)',
       'Брандмауэр Защитника Windows: профиль домена: состояние\s*[:\-]\s*([^\r\n<]+)'
     )
     Desired=@('On','Вкл','Enabled','Включено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Брандмауэр должен быть включён в доменном профиле.'
     Fix='ПК → Параметры Windows → Параметры безопасности → Брандмауэр → Профиль домена → Включить.'
  },
  @{ Id='Firewall.Private.On'; Category='Firewall'; Severity='High'; Profiles=@('Firewall')
     Title='Windows Defender Firewall (Private) = On'
     Patterns=@(
       'Windows Defender Firewall: Private Profile: State\s*[:\-]\s*([^\r\n<]+)',
       'Брандмауэр.*частный профиль.*состояние\s*[:\-]\s*([^\r\n<]+)'
     )
     Desired=@('On','Вкл','Enabled','Включено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Брандмауэр должен быть включён в частном профиле.'
     Fix='ПК → Брандмауэр → Частный профиль → Включить.'
  },
  @{ Id='Firewall.Public.On'; Category='Firewall'; Severity='High'; Profiles=@('Firewall')
     Title='Windows Defender Firewall (Public) = On'
     Patterns=@(
       'Windows Defender Firewall: Public Profile: State\s*[:\-]\s*([^\r\n<]+)',
       'Брандмауэр.*общедоступный профиль.*состояние\s*[:\-]\s*([^\r\n<]+)'
     )
     Desired=@('On','Вкл','Enabled','Включено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Брандмауэр должен быть включён в общедоступном профиле.'
     Fix='ПК → Брандмауэр → Общедоступный профиль → Включить.'
  },
  @{ Id='Firewall.LogDrops'; Category='Firewall'; Severity='Medium'; Profiles=@('Firewall')
     Title='Firewall: Log dropped packets = Yes'
     Patterns=@(
       'Logging:\s*Log dropped packets\s*[:\-]\s*([^\r\n<]+)',
       'Журналы:\s*Записывать отброшенные пакеты\s*[:\-]\s*([^\r\n<]+)'
     )
     Desired=@('Yes','Да','Enabled','Включено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Включить логирование отброшенных пакетов.'
     Fix='ПК → Профиль брандмауэра → Журналы → Log dropped packets → Yes.'
  },
  @{ Id='Firewall.LogSize'; Category='Firewall'; Severity='Low'; Profiles=@('Firewall')
     Title='Firewall: Log file size (KB) >= 16384'
     Patterns=@(
       'Log file size \(KB\)\s*[:\-]\s*([0-9]+)',
       'Размер файла журнала.*\(КБ\)\s*[:\-]\s*([0-9]+)'
     )
     DesiredText='≥ 16384 KB'
     Desired=@()
     Normalize={ param($s) $s }
     Recommendation='Увеличить размер файла журнала.'
     Fix='ПК → Профиль брандмауэра → Журналы → Размер файла.'
     Compare={ param($found) $v=Get-FirstInt $found; $v -ge 16384 }
  },

  # ======== Печать / PrintNightmare ========
  @{ Id='Print.PointAndPrint.Restrictions'; Category='PrintNightmare'; Severity='High'; Profiles=@('Print')
     Title='Point and Print Restrictions = Enabled'
     Patterns=@(
       'Point and Print Restrictions\s*[:\-]\s*([^\r\n<]+)',
       'Ограничения Point and Print\s*[:\-]\s*([^\r\n<]+)'
     )
     Desired=@('Enabled','Включено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Включить ограничения и использовать только утверждённые сервера.'
     Fix='ПК → Адм. шаблоны → Принтеры → «Point and Print Restrictions» → Enabled; Warning + Elevation.'
  },
  @{ Id='Print.ApprovedServers'; Category='PrintNightmare'; Severity='High'; Profiles=@('Print')
     Title='Package Point and Print – Approved servers (список не пустой)'
     Patterns=@(
       'Package Point and Print.*Approved servers.*[:\-]\s*([^\r\n<]+)',
       'Утверждённые серверы Point and Print.*[:\-]\s*([^\r\n<]+)'
     )
     DesiredText='Непустой список доверенных серверов'
     Desired=@()
     Normalize={ param($s) $s }
     Recommendation='Указать явный список доверенных принт-серверов.'
     Fix='ПК → Адм. шаблоны → Принтеры → «Package Point and Print – Approved servers».'
     Compare={
       param($found)
       $clean = ($found -replace '\s+',' ').Trim()
       if($clean -match '(?i)enter fully qualified server names\s*(?:separated by semicolons)?\s*([\w\d\.\\-]+(?:[;\s,]+[\w\d\.\\-]+)*)'){
         $list = $matches[1].Trim(' ;,')
         return (-not [string]::IsNullOrWhiteSpace($list))
       }
       return $false
     }
  },

  # ======== LAPS ========
  @{ Id='LAPS.Enable'; Category='LAPS'; Severity='High'; Profiles=@('LAPS')
     Title='Windows LAPS: включён и делает бэкап'
     Patterns=@(
       'Enable password backup for LAPS\s*[:\-]\s*([^\r\n<]+)',
       'Включить резервное копирование пароля LAPS\s*[:\-]\s*([^\r\n<]+)'
     )
     Desired=@('Enabled','Включено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Включить Windows LAPS и настроить ACL на чтение паролей.'
     Fix='ПК → Адм. шаблоны → Система → LAPS → включить политики (backup, rotation).'
  },

  # ======== Office / Browser ========
  @{ Id='Office.Macros.BlockInternet'; Category='Office'; Severity='High'; Profiles=@('Office')
     Title='Block macros from running in Office files from the Internet'
     Patterns=@(
       'Block macros from running in Office files from the Internet\s*[:\-]\s*([^\r\n<]+)',
       'Блокировать макросы из файлов Office из Интернета\s*[:\-]\s*([^\r\n<]+)'
     )
     Desired=@('Enabled','Включено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Блокировать макросы из Интернета.'
     Fix='Политики Office (Word/Excel) → Block macros from running in Office files from the Internet → Enabled.'
  },
  @{ Id='Office.DDE.Disable'; Category='Office'; Severity='Medium'; Profiles=@('Office')
     Title='Отключить DDE'
     Patterns=@(
       'Disable DDE\s*[:\-]\s*([^\r\n<]+)',
       'Отключить DDE\s*[:\-]\s*([^\r\n<]+)'
     )
     Desired=@('Enabled','Включено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Отключить DDE в Office.'
     Fix='Политики Office → Disable DDE → Enabled.'
  },
  @{ Id='Office.ProtectedView.Internet'; Category='Office'; Severity='Medium'; Profiles=@('Office')
     Title='Protected View для файлов из Интернета'
     Patterns=@(
       'Enable Protected View for files originating from the Internet\s*[:\-]\s*([^\r\n<]+)',
       'Включить защищенный режим просмотра для файлов из Интернета\s*[:\-]\s*([^\r\n<]+)'
     )
     Desired=@('Enabled','Включено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Включить Protected View.'
     Fix='Политики Office → Protected View → Enable for Internet files.'
  },
  @{ Id='Browser.SmartScreen'; Category='Browser'; Severity='Medium'; Profiles=@('Browser')
     Title='Configure Microsoft Defender SmartScreen (Edge) = Enabled'
     Patterns=@(
       'Configure Microsoft Defender SmartScreen\s*[:\-]\s*([^\r\n<]+)',
       'Настроить Microsoft Defender SmartScreen\s*[:\-]\s*([^\r\n<]+)'
     )
     Desired=@('Enabled','Включено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Включить SmartScreen в Edge.'
     Fix='Адм. шаблоны → Microsoft Edge → SmartScreen → Enabled.'
  },

  # ======== PowerShell / Defender ========
  @{ Id='PowerShell.ScriptBlockLogging'; Category='PowerShell'; Severity='High'; Profiles=@('PowerShell')
     Title='PowerShell: Script Block Logging'
     Patterns=@(
       'Turn on PowerShell Script Block Logging\s*[:\-]?\s*([^\r\n<]+)',
       'Логирование блоков скриптов\s*[:\-]?\s*([^\r\n<]+)'
     )
     Desired=@('Enabled','Включено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Включить логирование блоков скриптов.'
     Fix='ПК → Адм. шаблоны → Windows PowerShell → «Turn on PowerShell Script Block Logging».'
  },
  @{ Id='PowerShell.ModuleLogging'; Category='PowerShell'; Severity='Medium'; Profiles=@('PowerShell')
     Title='PowerShell: Module Logging'
     Patterns=@(
       'Turn on Module Logging\s*[:\-]\s*([^\r\n<]+)',
       'Включить ведение журнала модулей\s*[:\-]\s*([^\r\n<]+)'
     )
     Desired=@('Enabled','Включено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Включить логирование модулей PowerShell.'
     Fix='ПК → Адм. шаблоны → Windows PowerShell → «Turn on Module Logging».'
  },
  @{ Id='PowerShell.Transcription'; Category='PowerShell'; Severity='Low'; Profiles=@('PowerShell')
     Title='PowerShell: Transcription'
     Patterns=@(
       'Turn on PowerShell Transcription\s*[:\-]\s*([^\r\n<]+)',
       'Включить транскрипцию PowerShell\s*[:\-]\s*([^\r\n<]+)'
     )
     Desired=@('Enabled','Включено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Включить транскрипцию для расследований.'
     Fix='ПК → Адм. шаблоны → Windows PowerShell → «Turn on PowerShell Transcription».'
  },
  @{ Id='Defender.ASR'; Category='Defender'; Severity='Medium'; Profiles=@('Defender')
     Title='Attack Surface Reduction rules'
     Patterns=@(
       'ASR rules.*[:\-]?\s*([^\r\n<]+)',
       'Правила сокращения поверхности атак.*[:\-]?\s*([^\r\n<]+)'
     )
     DesiredText='Enabled / Block'
     Desired=@()
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Включить критичные правила ASR.'
     Fix='ПК → Адм. шаблоны → Microsoft Defender Antivirus → ASR.'
     Compare={ param($found) $n=($found -replace '\s+',' ').ToLowerInvariant(); ($n -match 'enabled' -or $n -match 'включ' -or $n -match 'block' -or $n -match 'блок') }
  },

  # ======== Контроль ПО ========
  @{ Id='AppLocker.Exe.Enforce'; Category='AppLocker'; Severity='High'; Profiles=@('AppLocker')
     Title='AppLocker: Enforcement for Executable rules = Enforced'
     Patterns=@(
       'AppLocker.*Enforcement mode for Executable rules\s*[:\-]\s*([^\r\n<]+)',
       'AppLocker.*Режим применения для правил исполняемых файлов\s*[:\-]\s*([^\r\n<]+)'
     )
     Desired=@('Enforced','Принудительно','Да')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Включить применение правил AppLocker (Executable).'
     Fix='ПК → Параметры безопасности → Политики контроля приложений → AppLocker → Режим применения → Enforced.'
  },

  # ======== Пользовательские сеансы ========
  @{ Id='ScreenSaver.Timeout'; Category='Сессии'; Severity='Medium'; Profiles=@('Base')
     Title='Таймаут хранителя экрана (сек)'
     Patterns=@(
       'Screen saver timeout\s*[:\-]\s*([0-9]+)',
       'Время ожидания хранителя экрана\s*[:\-]\s*([0-9]+)'
     )
     DesiredText='900/1200/1800 сек (15–30 мин)'
     Desired=@()
     Normalize={ param($s) $s }
     Recommendation='Не более 15–30 минут простоя.'
     Fix='Пользователь → Адм. шаблоны → Персонализация → «Тайм-аут хранителя экрана».'
     Compare={ param($found) $v=Get-FirstInt $found; @(900,1200,1800) -contains $v }
  },
  @{ Id='User.CantChangePassword'; Category='Учетные записи'; Severity='Low'; Profiles=@('Base')
     Title='Пользователь не может менять пароль (должно быть Отключено)'
     Patterns=@(
       'User cannot change password\s*[:\-]\s*([^\r\n<]+)',
       'Пользователь не может изменить пароль\s*[:\-]\s*([^\r\n<]+)'
     )
     Desired=@('Disabled','Отключено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Разрешить смену пароля пользователем (если нет исключений).'
     Fix='ADUC/GPMC: убрать флаг «User cannot change password».'
  },

  # ======== Современные защиты учётных данных ========
  @{ Id='Credential.Guard'; Category='Virtualization'; Severity='High'; Profiles=@('Base')
     Title='Credential Guard'
     Patterns=@(
       'Credential Guard\s*[:\-]?\s*([^\r\n<]+)',
       'Защита учетных данных\s*[:\-]?\s*([^\r\n<]+)',
       'Virtualization Based Security\s*[:\-]?\s*([^\r\n<]+)'
     )
     Desired=@('Enabled','Включено')
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Включить Credential Guard (VBS).'
     Fix='ПК → Адм. шаблоны → Система → Device Guard/VBS → Turn On VBS (с CredGuard).'
  },
  @{ Id='LSA.Protection'; Category='Безопасность'; Severity='High'; Profiles=@('Base')
     Title='LSA Protection (RunAsPPL)'
     Patterns=@(
       'LSA Protection\s*[:\-]?\s*([^\r\n<]+)',
       'Run as LSA.*[:\-]?\s*([^\r\n<]+)',
       'RunAsPPL.*[:\-]?\s*([^\r\n<]+)'
     )
     DesiredText='Enabled / RunAsPPL=1'
     Desired=@()
     Normalize={ param($s) ($s -replace '\s+',' ').ToLowerInvariant() }
     Recommendation='Запустить LSASS как защищённый процесс.'
     Fix='ПК → Адм. шаблоны → Система → «Configure LSASS to run as a protected process» или реестр HKLM\SYSTEM\...\Lsa → RunAsPPL=1.'
     Compare={ param($found) $n=($found -replace '\s+',' ').ToLowerInvariant(); ($n -match 'enabled' -or $n -match 'включ' -or $n -match 'runasppl' -or $n -match '\b1\b') }
  },

  # ======== Аудит ========
  @{ Id='Audit.ProcessTracking'; Category='Аудит'; Severity='High'; Profiles=@('Base')
     Title='Аудит: отслеживание процессов'
     Patterns=@(
       'Audit(?:\s+|.*)process tracking\s*[:\-]?\s*([^\r\n<]+)',
       'Отслеживание процессов\s*[:\-]?\s*([^\r\n<]+)'
     )
     DesiredText='Успех (минимум), лучше Успех и Отказ'
     Desired=@()
     Normalize={ param($s) ($s -replace '\s+',' ' -replace ',',' ').ToLowerInvariant() }
     Recommendation='Включить аудит запуска процессов.'
     Fix='ПК → Параметры безопасности → Локальная политика аудита → «Отслеживание процессов» → Успех (и Отказ).'
     Compare={ param($found) $n=($found -replace '\s+',' ' -replace ',',' ').ToLowerInvariant(); ($n -match 'успех' -or $n -match 'success') }
  },
  @{ Id='Audit.PrivilegeUse'; Category='Аудит'; Severity='High'; Profiles=@('Base')
     Title='Аудит: использование привилегий'
     Patterns=@(
       'Audit(?:\s+|.*)privilege use\s*[:\-]?\s*([^\r\n<]+)',
       'Использование привилегий\s*[:\-]?\s*([^\r\n<]+)'
     )
     DesiredText='Успех (минимум), лучше Успех и Отказ'
     Desired=@()
     Normalize={ param($s) ($s -replace '\s+',' ' -replace ',',' ').ToLowerInvariant() }
     Recommendation='Аудит использования чувствительных привилегий.'
     Fix='ПК → Параметры безопасности → Локальная политика аудита → «Использование привилегий».'
     Compare={ param($found) $n=($found -replace '\s+',' ' -replace ',',' ').ToLowerInvariant(); ($n -match 'успех' -or $n -match 'success') }
  }
)

# -------------------- Отбор правил по профилям --------------------
if($Profiles -and $Profiles.Count -gt 0){
  $active = $Profiles
  $Rules = $Rules | Where-Object {
    if($_.PSObject.Properties.Name -notcontains 'Profiles'){ return $true } # Base по умолчанию
    ($_.Profiles | Where-Object { $active -contains $_ }).Count -gt 0
  }
}

# -------------------- Сканирование --------------------
$files = Get-ChildItem -Path $Path -Filter *.htm* -Recurse -ErrorAction Stop
if(-not $files){ Write-Error "HTM файлы не найдены в $Path"; exit 1 }

$results = @()

foreach($f in $files){
  $raw = Get-Content -LiteralPath $f.FullName -Raw
  $txt = Remove-Html -Html $raw
  $displayName = if($ShowFullPath){ $f.FullName } else { $f.Name }

  # селективный выбор правил: если нет совпадений паттернов — правило для файла не применяется
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
      if($m.Success){
        $found = if($m.Groups.Count -gt 1){ $m.Groups[1].Value } else { $m.Value }
        break
      }
    }

    if([string]::IsNullOrWhiteSpace($found)){
      if($IncludeNotFound){
        $results += New-Result -File $f.FullName -Rule $rule -Status 'Не найдено' -FoundValue '' -Note 'Параметр не обнаружен' -DisplayName $displayName
      }
      continue
    }

    # --- сравнение ---
    $ok = $false
    if($rule.PSObject.Properties.Name -contains 'Compare' -and $null -ne $rule.Compare){
      $ok = & $rule.Compare $found
    } else {
      $norm = if($rule.PSObject.Properties.Name -contains 'Normalize' -and $null -ne $rule.Normalize){ & $rule.Normalize $found } else { ($found -replace '\s+',' ').ToLowerInvariant() }
      $desired = @()
      if($rule.PSObject.Properties.Name -contains 'Desired' -and $rule.Desired){
        $desired = $rule.Desired | ForEach-Object { 
          if($rule.PSObject.Properties.Name -contains 'Normalize' -and $null -ne $rule.Normalize){ (& $rule.Normalize $_) } else { ($_ -replace '\s+',' ').ToLowerInvariant() }
        }
      }
      foreach($d in $desired){ if($norm -like "*$d*"){ $ok = $true; break } }
    }

    $status = if($ok){ 'OK' } else { 'Не ОК' }
    if($OnlyIssues -and $status -eq 'OK'){ continue }

    $note = if($ok){ '' } else { 'Значение отличается от рекомендуемого' }
    $results += New-Result -File $f.FullName -Rule $rule -Status $status -FoundValue $found -Note $note -DisplayName $displayName
  }
}

# -------------------- Вывод --------------------
if(-not $results){
  Write-Host "Проблем не обнаружено (по выбранным правилам/файлам)." -ForegroundColor Green
  return
}

$displayItems = Select-OutputItems -Source $results -IncludeNotFound:$IncludeNotFound -OnlyIssues:$OnlyIssues

switch($Format){
'Table' {
  if($Pretty){
    if($displayItems -and $displayItems.Count -gt 0){
      Show-PrettyConsole -Items $displayItems -IncludeNotFound:$IncludeNotFound
    } else {
      Write-Host "Нет записей после применения фильтров." -ForegroundColor Green
    }
  }
  else {
    if($displayItems -and $displayItems.Count -gt 0){
      $displayItems | Sort-Object Severity, Category, Title, File |
        Format-Table File,Category,Title,Desired,Found,Status,Severity -AutoSize
    } else {
      Write-Host "Нет данных для табличного вывода (проверьте фильтры)." -ForegroundColor Yellow
    }
  }
}
'Csv' {
  $csvItems = Select-OutputItems -Source $results -IncludeNotFound:$IncludeNotFound -OnlyIssues:$OnlyIssues
  if($csvItems -and $csvItems.Count -gt 0){
    $csvPath = Resolve-ReportPath -Base $Out -Extension 'csv'
    try {
      $csvItems | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvPath
      Write-Host ("CSV отчёт сохранён: {0}" -f $csvPath) -ForegroundColor Cyan
    }
    catch {
      Write-Error ("Не удалось сохранить CSV отчёт: {0}" -f $_.Exception.Message)
    }
  } else {
    Write-Host "Нет записей для экспорта в CSV (все фильтры отсеяли данные)." -ForegroundColor Yellow
  }
}
'Md' {
  $mdItems = Select-OutputItems -Source $results -IncludeNotFound:$IncludeNotFound -OnlyIssues:$OnlyIssues
  if(-not $mdItems -or $mdItems.Count -eq 0){
    Write-Host "Нет записей для Markdown отчёта (все фильтры отсеяли данные)." -ForegroundColor Yellow
    break
  }

  $mdPath = Resolve-ReportPath -Base $Out -Extension 'md'
  $sb = New-Object System.Text.StringBuilder
  $generatedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

  [void]$sb.AppendLine('# Отчёт по аудиту GPO')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine("Сгенерировано: $generatedAt")
  [void]$sb.AppendLine('')

  $issueItems = $mdItems | Where-Object { $_.Status -ne 'OK' }
  if($issueItems -and $issueItems.Count -gt 0){
    [void]$sb.AppendLine('## Предупреждения и рекомендации')
    foreach($item in ($issueItems | Sort-Object Severity, Category, Title, File)){
      $file = Escape-Markdown $item.File
      $title = Escape-Markdown $item.Title
      $rule = Escape-Markdown $item.RuleId
      [void]$sb.AppendLine( ("- **{0}** [{1}] `{2}` - {3}" -f $item.Status, $item.Severity, $rule, $title) )
      [void]$sb.AppendLine( ("  - Файл: {0}" -f $file) )
      if($item.Found){ [void]$sb.AppendLine( ("  - Найдено: {0}" -f (Escape-Markdown $item.Found)) ) }
      if($item.Desired){ [void]$sb.AppendLine( ("  - Ожидается: {0}" -f (Escape-Markdown $item.Desired)) ) }
      if($item.Recommendation){ [void]$sb.AppendLine( ("  - Рекомендация: {0}" -f (Escape-Markdown $item.Recommendation)) ) }
      if($item.Fix){ [void]$sb.AppendLine( ("  - Как исправить: {0}" -f (Escape-Markdown $item.Fix)) ) }
      if($item.Note){ [void]$sb.AppendLine( ("  - Примечание: {0}" -f (Escape-Markdown $item.Note)) ) }
    }
  }
  else {
    [void]$sb.AppendLine('## Предупреждения и рекомендации')
    [void]$sb.AppendLine('- Нет выявленных проблем.')
  }

  [void]$sb.AppendLine('')
  [void]$sb.AppendLine('## Детальный список')
  [void]$sb.AppendLine('| Файл | Категория | Правило | Заголовок | Статус | Срочность | Найдено | Ожидается | Рекомендация | Исправление |')
  [void]$sb.AppendLine('| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |')
  foreach($item in ($mdItems | Sort-Object Severity, Category, Title, File)){
    $rowValues = @(
      (Escape-Markdown $item.File),
      (Escape-Markdown $item.Category),
      (Escape-Markdown $item.RuleId),
      (Escape-Markdown $item.Title),
      (Escape-Markdown $item.Status),
      (Escape-Markdown $item.Severity),
      (Escape-Markdown $item.Found),
      (Escape-Markdown $item.Desired),
      (Escape-Markdown $item.Recommendation),
      (Escape-Markdown $item.Fix)
    )
    $row = "| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} | {8} | {9} |" -f $rowValues
    [void]$sb.AppendLine($row)
  }

  if($SummaryPerRule){
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Сводка по правилам')
    foreach($group in ($mdItems | Group-Object RuleId | Sort-Object Name)){
      $sample = $group.Group | Select-Object -First 1
      $statusStats = ($group.Group | Group-Object Status | ForEach-Object { "{0}: {1}" -f $_.Name,$_.Count }) -join ', '
      [void]$sb.AppendLine( ("- `{0}` - {1} ({2})" -f $group.Name, (Escape-Markdown $sample.Title), $statusStats) )
    }
  }

  try {
    $sb.ToString() | Set-Content -Path $mdPath -Encoding UTF8
    Write-Host ("Markdown отчёт сохранён: {0}" -f $mdPath) -ForegroundColor Cyan
  }
  catch {
    Write-Error ("Не удалось сохранить Markdown отчёт: {0}" -f $_.Exception.Message)
  }
}
}

$counts = $results | Group-Object Status | Select-Object Name,Count
Write-Host ("Итог: {0}" -f (($counts | ForEach-Object { "$($_.Name): $($_.Count)" }) -join '; ')) -ForegroundColor Cyan
