<#
.SYNOPSIS
  Сравнить пользователей с префиксами (adm-, s-, l-) и участников группы Protected Users.

.OUTPUTS
  Табличный вывод в консоль; опционально CSV (путь через -CsvPath).
#>

param(
    [string[]]$Prefixes = @('adm-','s-','l-'),
    [string]$GroupName = 'Protected Users',
    [string]$CsvPath = $null
)

function Ensure-ADModule {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error 'Модуль ActiveDirectory не найден. Установите RSAT / модуль ActiveDirectory и повторите.'
        return $false
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    return $true
}

function Get-ProtectedUsers {
    param([string]$Group)
    # вернёт SamAccountName списка участников группы (рекурсивно)
    try {
        $members = Get-ADGroupMember -Identity $Group -Recursive -ErrorAction Stop |
                   Where-Object { $_.objectClass -eq 'user' } |
                   ForEach-Object {
                       # если вернулось только SID/Недостаточно атрибутов — подгрузим пользователя
                       if ($_.SamAccountName) { $_.SamAccountName } else {
                           (Get-ADUser -Identity $_.distinguishedName -Properties SamAccountName).SamAccountName
                       }
                   }
        return $members | Sort-Object -Unique
    } catch {
        Write-Error "Не удалось получить участников группы '$Group': $_"
        return @()
    }
}

function Get-PrefixUsers {
    param([string[]]$Prefixes)
    # строим фильтр для Get-ADUser
    $orClauses = $Prefixes | ForEach-Object {
        $p = $_.Trim()
        # экранируем символы, если нужны (для простоты считаем обычные буквы/тире)
        "(SamAccountName -like '$p*')"
    }
    $filter = $orClauses -join ' -or '
    try {
        $users = Get-ADUser -Filter $filter -Properties SamAccountName |
                 Select-Object -ExpandProperty SamAccountName
        return $users | Sort-Object -Unique
    } catch {
        Write-Error "Ошибка получения пользователей по префиксам: $_"
        return @()
    }
}

function Compare-Users {
    param(
        [string[]]$PrefixUsers,
        [string[]]$ProtectedUsers,
        [string[]]$Prefixes
    )

    # множества
    $setPrefix = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $setProtected = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    $PrefixUsers | ForEach-Object { $setPrefix.Add($_) | Out-Null }
    $ProtectedUsers | ForEach-Object { $setProtected.Add($_) | Out-Null }

    # кто с префиксом, но НЕ в группе
    $missingInGroup = $setPrefix.Where({ -not $setProtected.Contains($_) }) | Sort-Object

    # кто в группе и соответствует префиксам
    $inGroupAndMatch = $setProtected.Where({
        $found = $false
        foreach ($p in $Prefixes) { if ($_.StartsWith($p, [System.StringComparison]::OrdinalIgnoreCase)) { $found = $true; break } }
        $found
    }) | Sort-Object

    # кто в группе, но НЕ соответствует префиксам (возможно лишние)
    $inGroupButNoPrefix = $setProtected.Where({
        $found = $false
        foreach ($p in $Prefixes) { if ($_.StartsWith($p, [System.StringComparison]::OrdinalIgnoreCase)) { $found = $true; break } }
        -not $found
    }) | Sort-Object

    # результат
    [PSCustomObject]@{
        Prefixes            = $Prefixes
        CountPrefixUsers    = ($setPrefix.Count)
        CountProtectedUsers = ($setProtected.Count)
        MissingInGroup      = $missingInGroup
        InGroupAndMatch     = $inGroupAndMatch
        InGroupButNoPrefix  = $inGroupButNoPrefix
    }
}

# === Run ===
if (-not (Ensure-ADModule)) { return }

$prefixUsers = Get-PrefixUsers -Prefixes $Prefixes
$protectedUsers = Get-ProtectedUsers -Group $GroupName

$result = Compare-Users -PrefixUsers $prefixUsers -ProtectedUsers $protectedUsers -Prefixes $Prefixes

# Вывод сводки
Write-Host "`n=== Сводка ==="
Write-Host "Префиксы поиска: $($result.Prefixes -join ', ')"
Write-Host "Найдено пользователей с префиксами: $($result.CountPrefixUsers)"
Write-Host "Участников группы '$GroupName': $($result.CountProtectedUsers)"
Write-Host ""

Write-Host "Пользователи с префиксами, которых НЕТ в группе ($($result.MissingInGroup.Count)):"
if ($result.MissingInGroup.Count -gt 0) { $result.MissingInGroup | ForEach-Object { "  - $_" } } else { Write-Host "  — отсутствуют" }

Write-Host ""
Write-Host "Пользователи в группе и соответствующие префиксам ($($result.InGroupAndMatch.Count)):"
if ($result.InGroupAndMatch.Count -gt 0) { $result.InGroupAndMatch | ForEach-Object { "  - $_" } } else { Write-Host "  — отсутствуют" }

Write-Host ""
Write-Host "Пользователи в группе без соответствия префиксам (возможные лишние) ($($result.InGroupButNoPrefix.Count)):"
if ($result.InGroupButNoPrefix.Count -gt 0) { $result.InGroupButNoPrefix | ForEach-Object { "  - $_" } } else { Write-Host "  — отсутствуют" }

# Опциональный экспорт
if ($CsvPath) {
    $export = [PSCustomObject]@{
        Prefixes = $result.Prefixes -join ','
        CountPrefixUsers = $result.CountPrefixUsers
        CountProtectedUsers = $result.CountProtectedUsers
        MissingInGroup = ($result.MissingInGroup -join ';')
        InGroupAndMatch = ($result.InGroupAndMatch -join ';')
        InGroupButNoPrefix = ($result.InGroupButNoPrefix -join ';')
    }
    $export | Export-Csv -Path $CsvPath -NoTypeInformation -Force
    Write-Host "`nРезультат экспортирован в: $CsvPath"
}
