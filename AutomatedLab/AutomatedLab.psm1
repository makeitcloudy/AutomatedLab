function Get-GitModule 
{
    <#
    .SYNOPSIS
    .DESCRIPTION
    .PARAMETER GithubUserName
    .PARAMETER ModuleName
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

function Get-OperatingSystemType {
    <#
    .SYNOPSIS

    It returns false if the OS is server based.
    It returns true if the OS is desktop type.
    .DESCRIPTION

    The SKU matches the values available in 2024.07

    .PARAMETER NodeName
    .EXAMPLE
    .EXAMPLE
    .LINK

    https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem#examples
    https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem
    #>

    param (
        [Parameter(Mandatory=$false,Position=0,ValueFromPipelineByPropertyName=$true)]    
        [String]$NodeName = $env:COMPUTERNAME
    )

    BEGIN
    {
        
    }

    PROCESS
    {
    # Get OS information using CIM
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $NodeName

    # Initialize the result
    $isDesktop = $false

    # Use switch statement to check the OperatingSystemSKU
    switch ($os.OperatingSystemSKU) {
        4 { $isDesktop = $true }   # Windows Home
        6 { $isDesktop = $true }   # Windows Business
        7 { $isDesktop = $true }   # Windows Server Standard
        12 { $isDesktop = $true }  # Windows Server Datacenter
        13 { $isDesktop = $true }  # Windows Server Enterprise
        18 { $isDesktop = $true }  # Windows Business N
        20 { $isDesktop = $true }  # Windows Home N
        27 { $isDesktop = $true }  # Windows Server Datacenter N
        28 { $isDesktop = $true }  # Windows Server Standard N
        33 { $isDesktop = $true }  # Windows Server Enterprise N
        36 { $isDesktop = $true }  # Windows Business
        37 { $isDesktop = $true }  # Windows Business N
        39 { $isDesktop = $true }  # Windows Server Essentials
        44 { $isDesktop = $true }  # Windows Server Essentials R2
        48 { $isDesktop = $true }  # Windows Professional
        49 { $isDesktop = $true }  # Windows Professional N
        51 { $isDesktop = $true }  # Windows Education
        98 { $isDesktop = $true }  # Windows Education N
        99 { $isDesktop = $true }  # Windows Enterprise
        100 { $isDesktop = $true } # Windows Enterprise N
        101 { $isDesktop = $true } # Windows Server Standard Core
        103 { $isDesktop = $true } # Windows Server Datacenter Core
        121 { $isDesktop = $true } # Windows Home Single Language
        125 { $isDesktop = $true } # Windows Home China
        129 { $isDesktop = $true } # Windows Professional with Media Center
        130 { $isDesktop = $true } # Windows Professional with Media Center N
        131 { $isDesktop = $true } # Windows IoT Core
        132 { $isDesktop = $true } # Windows IoT Core N
        133 { $isDesktop = $true } # Windows S
        148 { $isDesktop = $true } # Windows Home Single Language with Bing
        189 { $isDesktop = $true } # Windows Professional Education
        190 { $isDesktop = $true } # Windows Professional Education N
        191 { $isDesktop = $true } # Windows Server Semi-Annual Channel
        205 { $isDesktop = $true } # Windows Server Semi-Annual Channel Core
        219 { $isDesktop = $true } # Windows Server Essentials Semi-Annual Channel
        220 { $isDesktop = $true } # Windows Server Essentials Semi-Annual Channel Core
        221 { $isDesktop = $true } # Windows Professional for Workstations
        222 { $isDesktop = $true } # Windows Professional for Workstations N
        252 { $isDesktop = $true } # Windows Business
        251 { $isDesktop = $true } # Windows Business N
        default { $isDesktop = $false } # Default to false for other SKUs
    }

    return $isDesktop
    }

    END
    {

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

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $modules
    )
    
    BEGIN
    {

    }
    
    PROCESS
    {
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

    END
    {

    }
}

function Create-SelfSignedCert
# https://gist.githubusercontent.com/fabricesemti80/a776b85767df3453f253a5a773437214/raw/6b0dd9a340e3d1c5c898e6b5e04e90e427fd6498/New-ADDSC.psm1
{
    [CmdletBinding()]
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

function Set-InitialConfigDsc {
    <#
    .SYNOPSIS

    .DESCRIPTION

    .PARAMETER NewComputerName
    .PARAMETER Option
    .PARAMETER DomainName    
    .EXAMPLE
Set-InitialConfigDsc -NewComputerName $NewComputerName -Option Workgroup -Verbose

    .EXAMPLE
Set-InitialConfigDsc -NewComputerName $NewComputerName -Option Domain -Verbose

.EXAMPLE
Set-InitialConfigDsc -NewComputerName $NewComputerName -Option Domain -DomainName 'lab.local' -Verbose

    .EXAMPLE
Set-InitialConfiguration -NewComputerName $NewComputerName -Option WorkGroup -UpdatePowerShellHelp  -Verbose

    .LINK
    #>
        
        [CmdletBinding()]
        Param
        (
            [Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true)]
            [ValidateNotNullOrEmpty()]
            $NewComputerName,

            [Parameter(Mandatory=$true,Position=1,ValueFromPipelineByPropertyName=$true)]
            [ValidateNotNullOrEmpty()][ValidateSet('workgroup', 'domain')]
            $Option
        )
    
        BEGIN
        {
            $WarningPreference = "Continue"
            $VerbosePreference = "Continue"
            $InformationPreference = "Continue"
            Write-Verbose "$env:COMPUTERNAME - $($MyInvocation.MyCommand) - InitialConfigDsc"
            $startDate = Get-Date

            #region - initialize variables, downlad prereqs
            $dsc_CodeRepoUrl               = 'https://raw.githubusercontent.com/makeitcloudy/HomeLab/feature/007_DesiredStateConfiguration/000_targetNode'
            $dsc_InitialConfigFileName     = 'InitialConfigDsc.ps1'
            $dsc_initalConfig_demo_ps1_url = $dsc_CodeRepoUrl,$dsc_InitialConfigFileName -join '/'

            $outFile = Join-Path -Path $env:USERPROFILE\Documents -ChildPath $dsc_InitialConfigFileName
            #endregion
        }
    
        PROCESS
        {
            try {
                Invoke-WebRequest -Uri $dsc_initalConfig_demo_ps1_url -OutFile $outFile -Verbose
                . $outFile
                #psedit $outFile
            }
            catch {

            }

            try {
                #region - Initial Setup - WorkGroup
                # The -UpdatePowerShellHelp Parameter updates powershell help on the target node

                # Use PSBoundParameters to determine which parameters were passed
                Write-Information "Parameters passed into the function:"

                if ($PSBoundParameters.ContainsKey('NewComputerName')) {
                    Write-Information "NewComputerName: $NewComputerName"
                }

                if ($PSBoundParameters.ContainsKey('Option')) {
                    Write-Information "Option: $Option"
                }

                if ($PSBoundParameters.ContainsKey('DomainName')) {
                    Write-Information "DomainName: $DomainName"
                }

                # Perform actions based on the 'Option' parameter
                switch ($Option) {
                    'Workgroup' {
                        Write-Information "The computer will be configured to join a Workgroup."
                        Set-InitialConfigurationDsc -NewComputerName $NewComputerName -Option $Option -Verbose
                        if ($DomainName) {
                            Write-Warning "DomainName was provided, but it is ignored since Option is 'Workgroup'."
                        }
                    }
                    'Domain' {
                        Write-Information "The computer will be configured to join a Domain."
                        if ($DomainName) {
                            Write-Information "DomainName provided: $DomainName"
                            Set-InitialConfigurationDsc -NewComputerName $NewComputerName -Option $Option -DomainName $DomainName -Verbose
                        } else {
                            Write-Warning "No DomainName provided, pleaes make use of the -DomainName Parameter"
                        }
                    }
                }
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