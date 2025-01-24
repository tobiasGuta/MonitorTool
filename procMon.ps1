$netConnections = Get-NetTCPConnection

$netConnections | ForEach-Object {
    $processId = $_.OwningProcess
    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
    
    # Handle missing process data gracefully with N/A
    $path = if ($process) { $process.Path } else { "N/A" }
    $user = if ($process) {
        $processOwner = (Get-WmiObject -Class Win32_Process -Filter "ProcessId = $processId").GetOwner()
        $processOwner.User
    } else { "N/A" }

    # Create a custom object with all the details
    [PSCustomObject]@{
        PID          = $processId
        ProcessName  = if ($process) { $process.ProcessName } else { "N/A" }
        UserName     = $user
        Path         = $path
        LocalAddress = $_.LocalAddress
        LocalPort    = $_.LocalPort
        State        = $_.State
    }
} | Format-Table -AutoSize
