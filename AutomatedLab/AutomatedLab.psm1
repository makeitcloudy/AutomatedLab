function Install-Modules
{
    <#
    .PARAMETER modules
    $modules = @{
    'Module1' = '1.0'
    'Module2' = '2.3'
    'Module3' = '3.5'
    }

    #>
    
    # https://gist.githubusercontent.com/fabricesemti80/a776b85767df3453f253a5a773437214/raw/6b0dd9a340e3d1c5c898e6b5e04e90e427fd6498/New-ADDSC.psm1

    param (
        [Parameter(Mandatory)]
        $modules
    )
    if ( -not(Get-PSRepository -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*psgallery*' }) )
    {
        Write-Warning -fore Magenta '>> Fixing PsGallery, please wait... <<'
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Register-PSRepository -Default -Verbose
    }
    foreach ($moduleName in $modules.Keys)
    {
        $desiredVersion = $modules[$moduleName]
        $installedModule = Get-Module -Name $moduleName -ListAvailable -ErrorAction SilentlyContinue | Where-Object { $_.Version -eq $desiredVersion }
        if ($null -eq $installedModule)
        {
            Write-Warning "$moduleName version $desiredVersion is NOT yet installed on $($Env:COMPUTERNAME). Installing..."
            Install-Module -Name $moduleName -RequiredVersion $desiredVersion -Force -Confirm:$false
            Write-Information "$moduleName version $desiredVersion has been installed on $($Env:COMPUTERNAME)."
        }
        else
        {
            Write-Verbose "$moduleName version $desiredVersion is already installed on $($Env:COMPUTERNAME)." -ForegroundColor Green
        }
    }
}

function Create-SelfSignedCert
# https://gist.githubusercontent.com/fabricesemti80/a776b85767df3453f253a5a773437214/raw/6b0dd9a340e3d1c5c898e6b5e04e90e427fd6498/New-ADDSC.psm1
{
    param (
        $certFolder = 'C:\dsc\cert'
        ,
        $certStore = 'Cert:\LocalMachine\My'
        ,
        $validYears = 2
    )
    $pubCertPath = Join-Path -Path $certFolder -ChildPath DscPubKey.cer
    $expiryDate = (Get-Date).AddYears($validYears)
    # You may want to delete this file after completing
    $privateKeyPath = Join-Path -Path $ENV:TEMP -ChildPath DscPrivKey.pfx
    $privateKeyPass = Read-Host -AsSecureString -Prompt 'Private Key Password'
    if (!(Test-Path -Path $certFolder))
    {
        New-Item -Path $certFolder -Type Directory | Out-Null
    }
    $cert = New-SelfSignedCertificate -Type DocumentEncryptionCertLegacyCsp `
        -DnsName 'DscEncryption' `
        -HashAlgorithm SHA512 `
        -NotAfter $expiryDate `
        -KeyLength 4096 `
        -CertStoreLocation $certStore
    $cert | Export-PfxCertificate -FilePath $privateKeyPath `
        -Password $privateKeyPass `
        -Force
    $cert | Export-Certificate -FilePath $pubCertPath
    Import-Certificate -FilePath $pubCertPath `
        -CertStoreLocation $certStore
    Import-PfxCertificate -FilePath $privateKeyPath `
        -CertStoreLocation $certStore `
        -Password $privateKeyPass | Out-Null
}