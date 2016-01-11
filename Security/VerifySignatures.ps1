function Verify-Signatures {
    If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
    {
        Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
        Break
    }

    $ErrorActionPreference = "SilentlyContinue"
    $disk = gwmi win32_logicaldisk -Filter "DriveType='3'"
    $drive = $disks.DeviceID +"\"
    
    foreach($e in $disk)
    {
        $file = gci $drive -Recurse -Include "*.exe"
        Get-AuthenticodeSignature $file | where {$_.Status -eq "NotSigned"}
    }
}
