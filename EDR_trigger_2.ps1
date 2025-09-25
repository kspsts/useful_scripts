# Используем легитимные .NET методы для демонстрации
function Show-ReflectionDemo {
    try {
        Write-Host "=== ДЕМОНСТРАЦИЯ ЧЕРЕЗ .NET REFLECTION ===" -ForegroundColor Cyan
        
        # Безопасные операции с процессами
        $currentProcess = [System.Diagnostics.Process]::GetCurrentProcess()
        Write-Host "[+] Текущий процесс: $($currentProcess.ProcessName)" -ForegroundColor Green
        Write-Host "[+] PID: $($currentProcess.Id)" -ForegroundColor Green
        Write-Host "[+] Память: $([math]::Round($currentProcess.WorkingSet64/1MB, 2)) MB" -ForegroundColor Green
        
        # Демонстрация работы с assembly (безопасно)
        $assemblies = [System.AppDomain]::CurrentDomain.GetAssemblies() | 
                     Where-Object { $_.FullName -like "System*" } | 
                     Select-Object -First 3 FullName
                     
        Write-Host "`n[+] Загруженные System assemblies:" -ForegroundColor Yellow
        foreach ($asm in $assemblies) {
            Write-Host "    - $($asm.FullName)" -ForegroundColor Gray
        }
        
        Write-Host "`n[!] Это безопасные операции - Касперский не блокирует" -ForegroundColor Green
        
    } catch {
        Write-Host "[ОШИБКА] $($_.Exception.Message)" -ForegroundColor Red
    }
}

Show-ReflectionDemo
