while ($true) {
    $process1 = Get-CimInstance Win32_Process | Select-Object ProcessId, CommandLine
    Start-Sleep -Seconds 1
    $process2 = Get-CimInstance Win32_Process | Select-Object ProcessId, CommandLine

    $diff = Compare-Object -ReferenceObject $process1 -DifferenceObject $process2 -Property ProcessId, CommandLine
    
    if ($diff) {
        Write-Output "Process changes detected:"
        $diff | ForEach-Object {
            if ($_.SideIndicator -eq "<=") {
                Write-Output "[-] Process Stopped: PID=$($_.ProcessId) CMD=$($_.CommandLine)"
            } elseif ($_.SideIndicator -eq "=>") {
                Write-Output "[+] Process Started: PID=$($_.ProcessId) CMD=$($_.CommandLine)"
            }
        }
    }
}
