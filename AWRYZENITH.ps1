function Check-Dependencies {
    # PowerShell Version
    $VersionMajor = $PSVersionTable.PSVersion.Major
    $VersionMinor = $PSVersionTable.PSVersion.Minor
    If ($VersionMajor -lt 5 -And $VersionMiner -lt 1) {
	Write-Host "Az requires at least PowerShell 5.1"
    }

    # .NET Framework Version
    # TODO: ensure .NET Framework 4.7.2+ is installed

    # PowerShellGet Version
    # TODO: ensure you have the latest version of PowerShellGet

    # Azure PowerShell is installed
    $SystemModules = Get-InstalledModule
    If($SystemModules.Name -NotContains "Az") {
        Write-Host "Azure PowerShell is not installed"
    }

    return $true
}

function Test-UserCredential {
    $Username = (Read-Host -Prompt "Enter the user's username: ").Trim()
    $Password = Read-Host -Prompt "Enter the user's password: "
    
    $SecurePassword = $Password | ConvertTo-SecureString -AsPlaintext -Force
    $Credential = [PSCredential]::New($Username, $SecurePassword)

    $AzureAccount = Connect-AzAccount -Credential $Credential

    If($AzureAccount -ne $null) {
	Write-Host "User Credentials are valid"
    } Else {
	# TODO: Display info about why credentials were invalid as returned by Connect-AzAccount
	Write-Host "Invalid User Credentials!"
    }
}

function Test-StorageAccountCredential {
    $AccountName = (Read-Host -Prompt "Enter the storage account-name: ").Trim()
    $AccountKey = Read-Host -Prompt "Enter the storage account-key: "

    $AzureStorageAccount = New-AzStorageContext -StorageAccountName $AccountName -StorageAccountKey $AccountKey

    If((Get-AzStorageContainer -Context $AzureStorageAccount) -ne $null) {
	Write-Host "Storage Account Credentials are valid"
    } ElseIf((Get-AzStorageShare -Context $AzureStorageAccount) -ne $null) {
	Write-Host "Storage Account Credentials are valid"
    } ElseIf((Get-AzStorageQueue -Context $AzureStorageAccount) -ne $null) {
	Write-Host "Storage Account Credentials are valid"
    } ElseIf((Get-AzStorageTable -Context $AzureStorageAccount) -ne $null) {
	Write-Host "Storage Account Credentials are valid"
    } Else {
        # TODO: Display info about why credentials were invalid as returned by Connect-AzAccount
        Write-Host "Invalid Storage Account Credentials!"
    }
}

function Test-ServicePrincipalCredential {
    $Username = (Read-Host -Prompt "Enter the service principal's username: ").Trim()
    $Password = Read-Host -Prompt "Enter the service principal's password: "
    $Tenant = (Read-Host -Prompt "Enter the service principal's tenant's id: ").Trim()

    $SecurePassword = $Password | ConvertTo-SecureString -AsPlaintext -Force
    $Credential = [PSCredential]::New($Username, $SecurePassword)

    $AzureAccount = Connect-AzAccount -ServicePrincipal -Credential $Credential -Tenant $Tenant

    If($AzureAccount -ne $null) {
	Write-Host "Service Principal Credentials are valid"
    } Else {
	# TODO: Display info about why credentials were invalid as returned by Connect-AzAccount
	Write-Host "Invalid Service Principal Credentials!"
    }
}

function AWRYZENITH {
<# 
.SYNOPSIS
  Script initialization routine
.PARAMETER 
#>
    $ErrorActionPreference = "SilentlyContinue"

    If(Check-Dependencies) {
        Write-Host "Welcome to AWRYZENITH" 
    }

    # Support other credential types such as SPs with Certificates 
    Write-Host @"

Credential Types:

User (user): 
    username: johndoe@organization.onmicrosoft.com
    password: Chiapet1
Storage Account (sa): 
    account-name: s8b1eaf96xefu45d (3-24 characters, lowercase+numeric, Azure-wide unique string)
    account-key: MRg579YKZCchVdvX8xfrlnTRJIjVoVQC7FPKu47a3jgSbKhRkavMuVzKtZVntwvJKSD+1tu6PjJSDm8qPD3nJx==
Service Principal (sp):
    Example 1: 
    username: 6e950d66-78d3-4bb5-a8c9-d085bda8a607
    password: b624aab7-4573-4b1c-ae64-8f888c6a2fe1
    tenant: 930fafc4-313b-40fb-9368-afda7c4f3561

    Example 2:
    username: SomeDisplayName
    password: SuperChiapet1
    tenant: 987bb494-bfd4-413a-bfb3-958c1342f3a3
    
    NOTE: Tenant is display as 'id' sometimes such as in the return value when creating an SP
    
"@

    $CredentialType = Read-Host -Prompt "Enter the type of credential you have (user, sa, or sp): "

    If($CredentialType -eq "user") {
        Test-UserCredential
    } ElseIf($CredentialType -eq "sa") {
	Test-StorageAccountCredential
    } ElseIf($CredentialType -eq "sp") {
	Test-ServicePrincipalCredential 
    } Else {
	Write-Host "Unsupported Credential Type, exiting"
	Exit
    }
}

AWRYZENITH
