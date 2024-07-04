function Get-GitModule 
{
    <#
    .SYNOPSIS
    .DESCRIPTION
    .PARAMETER One
    .PARAMETER Two
    .EXAMPLE
    .EXAMPLE
    .LINK
    #>
        
        [CmdletBinding()]
        Param
        (
            [Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true)]
            [ValidateNotNullOrEmpty()]
            $GithubUserName,

            [Parameter(Mandatory=$true,Position=1,ValueFromPipelineByPropertyName=$true)]
            [ValidateNotNullOrEmpty()]
            $ModuleName
        )
    
        BEGIN
        {
            $WarningPreference = "Continue"
            $VerbosePreference = "Continue"
            $InformationPreference = "Continue"
            Write-Verbose "$env:COMPUTERNAME - $($MyInvocation.MyCommand) - It downloads module from Github repository"
            $startDate = Get-Date

            #initialize variables
            #$ModuleName                    = "AutomatedLab"
            #$GitHubUserName                = 'makeitcloudy'
            $repoUrl                       = 'https://github.com',$GithubUserName,$ModuleName,'archive/refs/heads/main.zip' -join '/'

            $modulePath                    = "C:\Program Files\WindowsPowerShell\Modules\$ModuleName"

            $tempZipFileName               = $ModuleName,'.zip' -join ''
            $tempZipFullPath               = "$env:TEMP",$tempZipFileName -join '\'

            $extractedModuleTempFolderName = $ModuleName,'main' -join '-'
            $extractedModuleTempFullPath   = "$env:TEMP",$extractedModuleTempFolderName,$ModuleName -join '\'

        }
    
        PROCESS
        {
            try {
                # download the module from github
                Invoke-WebRequest -Uri $repoUrl -OutFile $tempZipFullPath
                # expand the archive to \AppData\Local\Temp
                Expand-Archive -Path $tempZipFullPath -DestinationPath $env:TEMP
                # copy the module folder from the repo directory to the C:\Program Files\WindowsPowerShell\Modules\[moduleName]
                Copy-Item -Path $extractedModuleTempFullPath -Destination $modulePath -Recurse -Force

                #cleanup
                # remove the downloaded repository zip file
                Remove-Item -Path $tempZipFullPath -Force
                # remove the extracted repository folder from the \AppData\Local\Temp
                Remove-Item -Path $(Join-Path -Path $env:TEMP -ChildPath $extractedModuleTempFolderName) -Recurse -Force
            }
            catch {
    
            }
        }
    
        END
        {
            $endDate = Get-Date
            Write-Verbose "$env:COMPUTERNAME - $($MyInvocation.MyCommand) - Time taken: $("{0:%d}d:{0:%h}h:{0:%m}m:{0:%s}s" -f ((New-TimeSpan -Start $startDate -End $endDate)))"
        }
    }

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
            Write-Warning "$moduleName version $desiredVersion is already installed on $($Env:COMPUTERNAME)."
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