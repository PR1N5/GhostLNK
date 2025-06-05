
function ShowAllInformation {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]$info
    )

    $info | Out-File "$(Get-Location)\recon_salida.txt"
    Start-Process notepad.exe "$(Get-Location)\recon_salida.txt"
    
}


# System information
function BasicReconInformation {
    # basic functionality for powershell
    
    
    $info = @()
    $info += "== BASIC SYSTEM INFORMATION =="
    $info += "System name: $env:COMPUTERNAME"
    $info += "Current user: $env:USERNAME"
    $info += "Domain: $env:USERDOMAIN"
    $info += "OS: $((Get-CimInstance Win32_OperatingSystem).Caption)"
    $info += "Local IP: $(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*"} | Select-Object -ExpandProperty IPAddress)"
    $info += ""

    return $info
}

function LocalUsers {
    [CmdletBinding()]
    param ()

    $info = @()
    $info += "== LOCAL USERS =="
    $usuarios = Get-LocalUser

    foreach ($usuario in $usuarios) {
        $info += "User: $($usuario.Name) | Active: $($usuario.Enabled)"
    }

    $info += ""

    return $info
    
}

function InstalledSoftware {
    [CmdletBinding()]
    param ()

    $info = @()
    $info += "== SOFTWARE INSTALLED (32 bits) =="
    $programs32 = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher)
    
    foreach($program in $programs32){
        if ($program.DisplayName) {
            $info += "Name: $($program.DisplayName) | Version: $($program.DisplayVersion) | Publisher: $($program.Publisher)"
        }
    }

    $info += ""
    $info += "== SOFTWARE INSTALLED (64 bits) =="
    $programs64 = (Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher)
    
    foreach($program in $programs64){
        if ($program.DisplayName) {
            $info += "Name: $($program.DisplayName) | Version: $($program.DisplayVersion) | Publisher: $($program.Publisher)"
        }
    }
    $info += ""

    return $info

}

function OpenPorts {
    [CmdletBinding()]
    param ()

    $info = @()

    $info += "== OPEN PORTS ==" 
    $ports += (Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess)
    
    foreach($p in $ports){
        $info += "LocalAddress: $($p.LocalAddress):$($p.LocalPort) | RemoteAddress: $($p.RemoteAddress):$($p.RemotePort) | Process: $(Get-Process -Id $p.OwningProcess)"
    }
    $info += ""

    return $info

}

function RunningProcess {
    [CmdletBinding()]
    param ()

    $info =@()
    $info += "== RUNNING PROCESSES =="

    $process = (Get-Process | Select-Object Name, Id, CPU)
    
    foreach($p in $process){
        $info += "Name: $($p.Name) | Id: $($p.Id) | CPU: $($p.CPU)"
    }

    $info += ""

    return $info
}

# call for storing the information from function
$info = @()
$info = BasicReconInformation
$info += LocalUsers
$info += InstalledSoftware
$info += OpenPorts
$info += RunningProcess

# this is for debug
ShowAllInformation -info $info