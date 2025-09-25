# Метод 3: Демонстрация через чистый PowerShell и .NET
function Show-ProcessInjectionConcepts {
    Write-Host "=== КОНЦЕПЦИИ PROCESS INJECTION ===" -ForegroundColor Cyan
    
    # 1. Демонстрация работы с процессами
    Write-Host "`n1. РАБОТА С ПРОЦЕССАМИ:" -ForegroundColor Yellow
    $processes = Get-Process | Where-Object { $_.ProcessName -eq 'notepad' -or $_.ProcessName -eq 'calculator' }
    
    if ($processes) {
        foreach ($proc in $processes) {
            Write-Host "   Процесс: $($proc.ProcessName), PID: $($proc.Id), HandleCount: $($proc.HandleCount)" -ForegroundColor Gray
        }
    } else {
        Write-Host "   Запустите notepad или calc для демонстрации" -ForegroundColor Gray
    }
    
    # 2. Демонстрация того, что видит EDR
    Write-Host "`n2. КАК EDR ДЕТЕКТИРУЕТ INJECTION:" -ForegroundColor Red
    $triggers = @(
        "Sequence: OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread",
        "PowerShell accessing lsass.exe memory",
        "Unusual parent-child: msoffice → powershell → notepad",
        "Process hollowing (замена легитимного EXE в памяти)",
        "API hooking detection"
    )
    
    for ($i = 0; $i -lt $triggers.Count; $i++) {
        Write-Host "   $($i+1). $($triggers[$i])" -ForegroundColor Yellow
    }
    
    # 3. Пример безопасного кода, который НЕ триггерит EDR
    Write-Host "`n3. БЕЗОПАСНЫЕ ОПЕРАЦИИ:" -ForegroundColor Green
    try {
        # Безопасные вызовы
        $currentPid = $PID
        $processName = (Get-Process -Id $PID).ProcessName
        Write-Host "   Текущий PID: $currentPid, Имя: $processName" -ForegroundColor Gray
        
        # Работа с собственной памятью процесса - безопасно
        $memoryDemo = [System.Text.Encoding]::ASCII.GetBytes("Safe memory operation")
        Write-Host "   Работа с собственной памятью: OK" -ForegroundColor Gray
        
    } catch {
        Write-Host "   Ошибка: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Запускаем
Show-ProcessInjectionConcepts
