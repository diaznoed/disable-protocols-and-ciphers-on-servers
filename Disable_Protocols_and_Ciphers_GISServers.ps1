<# PKCS disableStaticKeyCiphers OMITTED. Disabling this cipher causes problems on ArcGIS GIS Servers.
Added "#Requires -RunAsAdministrator" to halt script if it is not run from an Admin prompt.
#>

#Requires -RunAsAdministrator

$computers = @("fdqn")
$logFileName = ".\ProtoCipherLog-$computers.txt"

[timezoneinfo]::Local
# for pre PS v5 systems: $tzstr = [regex]::Replace([system.timezoneinfo]::Local.StandardName, '([A-Z}])\w+\s*', '$1')
$tzstr = (Get-TimeZone).id

function PSLog($tString)
## GeoState Log file writing function, automatically adds current date/time to each line
    {
    $logTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "$logTime - $tString" | out-file -Filepath $logFileName -append
    Write-Host "$logTime $tzstr - $tString"
    }


$root = "HKLM:"
$rootRegistryPath = "System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
$rootCipherPath = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"
$rootStaticPath = "System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms"

$sslv20 = "$rootRegistryPath\SSL 2.0\Server"
$sslv20Client = "$rootRegistryPath\SSL 2.0\Client"
$sslv30 = "$rootRegistryPath\SSL 3.0\Server"
$sslv30Client = "$rootRegistryPath\SSL 3.0\Client"
$tlsv10 = "$rootRegistryPath\TLS 1.0\Server"
$tlsv10Client = "$rootRegistryPath\TLS 1.0\Client"
$tlsv11 = "$rootRegistryPath\TLS 1.1\Server"
$tlsv11Client = "$rootRegistryPath\TLS 1.1\Client"
$tlsv12 = "$rootRegistryPath\TLS 1.2\Server"
$tlsv12Client = "$rootRegistryPath\TLS 1.2\Client"

$threeDes = "Triple DES 168"
$rc4128 = "RC4 128`/128"
$rc464 = "RC4 64`/128"
$rc456 = "RC4 56`/128"
$rc440 = "RC4 40`/128"
$nl = "Null"
$des56 = "DES 56`/56"
$rc240 = "RC2 40`/128"
$rc256 = "RC2 56`/128"
$rc2128 = "RC2 128`/128"
$aes128 = "AES 128`/128"
$aes256 = "AES 256`/256"

$staticAlgo = "PKCS"
$dh = "Diffie-Hellman"

$strongCrypto32 = "SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
$strongCrypto64 = "SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"

function DisableSecurityProtocol($keyPath, $computer) {

    $keyAdd = "$root\$keyPath"
    PSLog "DisableSecurityProtocolFunc: $keyAdd"
    $regkey=[microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$computer) 
    PSLog "DisableSecurityProtocolFunc: $regkey"
    $ref = $regKey.OpenSubKey($keyPath);
    PSLog "DisableSecurityProtocolFunc: $ref"
    
    if (!$ref) {
        PSLog "Creating registry key $keyAdd"
        Invoke-Command -ComputerName $computer -ScriptBlock {New-Item -Path $Args[0] -Force | Out-Null} -ArgumentList $keyAdd
    }
    else {
        PSLog "Keys already exist for $computer"
    }
  
    PSLog "Setting properties on $computer to disable $keyPath"
    Invoke-Command -ComputerName $computer -ScriptBlock {New-ItemProperty -Path $Args[0] -Name DisabledByDefault -Value 1 -PropertyType DWORD -Force | Out-Null} -ArgumentList $keyAdd
    Invoke-Command -ComputerName $computer -ScriptBlock {New-ItemProperty -Path $Args[0] -Name Enabled -Value 0 -PropertyType DWORD -Force | Out-Null} -ArgumentList $keyAdd
}

function disableStaticKeyCiphers($keyPath, $computer) {
	$keyAdd = "$root\$rootStaticPath\$keyPath"
    PSLog "DisableStaticKeyCipherFunc: $keyAdd"
    $regkey=[microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$computer) 
    PSLog "DisableStaticKeyCipherFunc: $regkey"
    $ref = $regKey.OpenSubKey($keyPath);
    PSLog "DisableStaticKeyCipherFunc: $reF"
        
    if (!$ref) {
        PSLog "Creating registry key $keyAdd"
        Invoke-Command -ComputerName $computer -ScriptBlock {(Get-Item $Args[0]).OpenSubKey($Args[1],$true).createSubKey($Args[2])} -ArgumentList $root,$rootStaticPath,$keyPath
        
    }
    else {
        PSLogt "Keys already exist for $computer"
    }
  
    PSLog "Setting properties on $computer to disable $keyPath"
    Invoke-Command -ComputerName $computer -ScriptBlock {New-ItemProperty -Path "$($Args[0])\$($Args[1])\$($Args[2])" -Name Enabled -Value 0 -PropertyType DWORD -Force | Out-Null} -ArgumentList $root,$rootStaticPath,$keyPath
  
}

function dhKeyLength($keyPath, $computer) {
    $keyAdd = "$root\$rootStaticPath\$keyPath"
    PSLog "dhKeyLengthFunc: $keyAdd"
    $regkey=[microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$computer) 
    PSLog "dhKeyLengthFunc: $regkey"
    $ref = $regKey.OpenSubKey($keyPath);
    PSLog "dhKeyLengthFunc: $ref"
    
    if (!$ref) {
        PSLog "Creating registry key $keyAdd"
        Invoke-Command -ComputerName $computer -ScriptBlock {(Get-Item $Args[0]).OpenSubKey($Args[1],$true).createSubKey($Args[2])} -ArgumentList $root,$rootStaticPath,$keyPath
        
    }
    else {
        PSLog "Keys already exist for $computer"
    }
  
    PSLog "Setting properties on $computer for $keyPath to fix key length to 2048"
    Invoke-Command -ComputerName $computer -ScriptBlock {New-ItemProperty -Path "$($Args[0])\$($Args[1])\$($Args[2])" -Name ServerMinKeyBitLength -Value 2048 -PropertyType DWORD -Force | Out-Null} -ArgumentList $root,$rootStaticPath,$keyPath
    Invoke-Command -ComputerName $computer -ScriptBlock {New-ItemProperty -Path "$($Args[0])\$($Args[1])\$($Args[2])" -Name ClientMinKeyBitLength -Value 2048 -PropertyType DWORD -Force | Out-Null} -ArgumentList $root,$rootStaticPath,$keyPath
}

function RemoveCiphers($computer) {
	PSLog "Cleaning up ciphers on $computer"
	Invoke-Command -ComputerName $computer -scriptBlock {Remove-Item -Path "$($Args[0])\$($Args[1])\*" -Recurse} -ArgumentList $root,$rootCipherPath
}

function DisableSecurityCipher($keyPath, $computer) {

    $keyAdd = "$root\$rootCipherPath\$keyPath"
    PSLog "DisableSecurityCipherFunc: $keyAdd"
    $regkey=[microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$computer) 
    PSLog "DisableSecurityCipherFunc: $regKey"
    $ref = $regKey.OpenSubKey($keyPath);
    PSLog "DisableSecurityCipherFunc: $ref"
    
    if (!$ref) {
        PSLog "Creating registry key $keyAdd"
        Invoke-Command -ComputerName $computer -ScriptBlock {(Get-Item $Args[0]).OpenSubKey($Args[1],$true).createSubKey($Args[2])} -ArgumentList $root,$rootCipherPath,$keyPath
        
    }
    else {
        PSLog "Keys already exist for $computer"
    }
  
    PSLog "Setting properties on $computer to disable $keyPath"
    Invoke-Command -ComputerName $computer -ScriptBlock {New-ItemProperty -Path "$($Args[0])\$($Args[1])\$($Args[2])" -Name Enabled -Value 0 -PropertyType DWORD -Force | Out-Null} -ArgumentList $root,$rootCipherPath,$keyPath
}

function TurnOnStrongCrypto($keyPath, $computer) {

    $keyAdd = "$root\$keyPath"
    PSLog "TurnOnStrongCryptoFunc: $keyAdd"
    $regkey=[microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$computer) 
    PSLog "TurnOnStrongCryptoFunc: $regKey"
    $ref = $regKey.OpenSubKey($keyPath);
    PSLog "TurnOnStrongCryptoFunc: $ref"
    
    if (!$ref) {
        PSLog "Creating registry key $keyAdd"
        Invoke-Command -ComputerName $computer -ScriptBlock {New-Item -Path $Args[0] -Force | Out-Null} -ArgumentList $keyAdd
    }
    else {
        PSLog "Keys already exist for $computer"
    }
  
    PSLog "Setting properties on $computer to enable $keyPath"
    Invoke-Command -ComputerName $computer -ScriptBlock {New-ItemProperty -Path $Args[0] -Name SchUseStrongCrypto -Value 1 -PropertyType DWORD -Force | Out-Null} -ArgumentList $keyAdd
}

function EnableSecurityProtocol($keyPath, $computer) {

    $keyAdd = "$root\$keyPath"
    PSLog "EnableSecurityProtocolFunc: $keyAdd"
    $regkey=[microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$computer) 
    PSLog "EnableSecurityProtocolFunc: $regKey"
    $ref = $regKey.OpenSubKey($keyPath);
    PSLog "EnableSecurityProtocolFunc: $ref"
    
    if (!$ref) {
        PSLog "Creating registry key $keyAdd"
        Invoke-Command -ComputerName $computer -ScriptBlock {New-Item -Path $Args[0] -Force | Out-Null} -ArgumentList $keyAdd
    }
    else {
        PSLog "Keys already exist for $computer"
    }
  
    PSLog "Setting properties on $computer to enable $keyPath"
    Invoke-Command -ComputerName $computer -ScriptBlock {New-ItemProperty -Path $Args[0] -Name DisabledByDefault -Value 0 -PropertyType DWORD -Force | Out-Null} -ArgumentList $keyAdd
    Invoke-Command -ComputerName $computer -ScriptBlock {New-ItemProperty -Path $Args[0] -Name Enabled -Value 1 -PropertyType DWORD -Force | Out-Null} -ArgumentList $keyAdd
}

##
## MAIN
##

foreach ($computer in $computers) {
	PSLog "Working on $computer"
    DisableSecurityProtocol $sslv20 $computer
	DisableSecurityProtocol $sslv20Client $computer
	DisableSecurityProtocol $sslv30 $computer
	DisableSecurityProtocol $sslv30Client $computer
	DisableSecurityProtocol $tlsv11 $computer
	DisableSecurityProtocol $tlsv11Client $computer
	DisableSecurityProtocol $tlsv10 $computer
	DisableSecurityProtocol $tlsv10Client $computer
		
	RemoveCiphers $computer
	
    # PKCS Needed on ArcGIS GIS Servers	
    # disableStaticKeyCiphers $staticAlgo $computer
    PSLog "PKCS disableStaticKeyCiphers SKIPPED. Disabling this cipher causes problems on ArcGIS GIS Servers."
	disableStaticKeyCiphers $dh $computer
    dhKeyLength $dh $computer
	
	DisableSecurityCipher $threeDes $computer
	DisableSecurityCipher $rc4128 $computer
	DisableSecurityCipher $rc464 $computer
	DisableSecurityCipher $rc456 $computer
	DisableSecurityCipher $rc440 $computer
	DisableSecurityCipher $nl $computer
	DisableSecurityCipher $des56 $computer
	DisableSecurityCipher $rc240 $computer
	DisableSecurityCipher $rc256 $computer
	DisableSecurityCipher $rc2128 $computer
	DisableSecurityCipher $aes128 $computer
	DisableSecurityCipher $aes256 $computer
	
	TurnOnStrongCrypto $strongCrypto32 $computer
	TurnOnStrongCrypto $strongCrypto64 $computer
	
    EnableSecurityProtocol $tlsv12 $computer
	EnableSecurityProtocol $tlsv12Client $computer
	
    PSLog "Work complete on $computer"
}