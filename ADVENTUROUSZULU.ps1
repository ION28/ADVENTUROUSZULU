######################## Data Structures ########################

class AzureTenant {
    [AzureMgmtGroup] $RootGroup
    [Object] $AzureObject
}

class AzureMgmtGroup {
    [AzureTenant] $Tenant
    [AzureMgmtGroup] $ParentGroup
    [AzureMgmtGroup[]] $ChildGroups
    [AzureSubscription[]] $ChildSubscriptions
    [Object] $AzureObject
}

class AzureSubscription {
    [AzureTenant] $Tenant
    [AzureMgmtGroup] $ParentGroup
    [AzureResourceGroup[]] $ResourceGroups
    [Object] $AzureObject
}

class AzureResourceGroup {
    [AzureSubscription] $Subscription
    [AzureResource[]] $Resources
    [Object] $AzureObject
    [String] $Name
}

class AzureResource {
    [AzureResourceGroup] $ResourceGroup
    [Object] $AzureObject
}

######################## Perform AUTH ########################

function Confirm-UserCredential {
    $Username = (Read-Host -Prompt "Enter the user's username").Trim()
    $Password = Read-Host -Prompt "Enter the user's password"
    
    $SecurePassword = $Password | ConvertTo-SecureString -AsPlaintext -Force
    $Credential = [PSCredential]::New($Username, $SecurePassword)

    try {
        $AzureAccount = Connect-AzAccount -Credential $Credential -ErrorAction Stop
    } catch {
	If($_.Exception.message.Contains("multi-factor authentication")) {
	    Write-Host "User requires MFA to login - please use the pop-up to complete an interactive login"
	    $AzureAccount = Connect-AzAccount
	}
    }

    If($AzureAccount -ne $null) {
	Write-Host "User Credentials are valid"
    } Else {
	# TODO: Display info about why credentials were invalid as returned by Connect-AzAccount
	Write-Host "Invalid User Credentials!"
    }
}


function Confirm-StorageAccountCredential {
    $AccountName = (Read-Host -Prompt "Enter the storage account-name").Trim()
    $AccountKey = Read-Host -Prompt "Enter the storage account-key"

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

    return $AzureStorageAccount
}

function Confirm-ServicePrincipalCredential {
    $Username = (Read-Host -Prompt "Enter the service principal's username").Trim()
    $Password = Read-Host -Prompt "Enter the service principal's password"
    $Tenant = (Read-Host -Prompt "Enter the service principal's tenant's id").Trim()

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

######################## Utility Functions ########################

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


function Get-AccessibleResources {
    Write-Host ""
    Write-Host "Collecting accessible resources/resource groups/subscriptions/management groups/tenants with the provided credentials"
    $Context = Get-AzContext

    $AccessibleTenants = @()
    $AccessibleMgmtGroups = @()
    $AccessibleSubscriptions = @()
    $AccessibleResourceGroups = @()
    $AccessibleResources = @()

    $Tenants = Get-AzTenant -DefaultProfile $Context
    $Tenants | ForEach-Object {
	$Tenant = New-Object AzureTenant
	$Tenant.AzureObject = $_
	$AccessibleTenants += $Tenant
    }

    $ManagementGroups = Get-AzManagementGroup -DefaultProfile $Context
    $ManagementGroups | ForEach-Object {
	$MgmtGroup = New-Object AzureMgmtGroup
	$MgmtGroup.AzureObject = $_
	$MgmtGroup.Tenant = ($AccessibleTenants | Where-Object { $_.AzureObject.Id -eq $MgmtGroup.AzureObject.TenantId })

	If($MgmtGroup.AzureObject.DisplayName -eq "Tenant Root Group") {
	    $AssociatedTenant = ($AccessibleTenants | Where-Object { $_.AzureObject.TenantId -eq $MgmtGroup.AzureObject.TenantId })
	    $AssociatedTenant.RootGroup = $MgmtGroup
	}

	$AccessibleMgmtGroups += $MgmtGroup
    }

    # TODO: Ensure the following call to Get-AzSubscription will grab all subscriptions across multiple tenants
    $Subscriptions = Get-AzSubscription -DefaultProfile $Context
    ForEach($Subscription in $Subscriptions) {
	$Sub = New-Object AzureSubscription
	$Sub.AzureObject = $Subscription
	$Sub.Tenant = ($AccessibleTenants | Where-Object { $_.AzureObject.Id -eq $Sub.AzureObject.TenantId })
	$AccessibleSubscriptions += $Sub
        
        # Retrieve Resource Groups associated with Subscription
	$Context = Set-AzContext -SubscriptionId $Subscription.Id
        $ResourceGroups = Get-AzResourceGroup -DefaultProfile $Context

        if($ResourceGroups.Count -gt 0) {
	    ForEach($ResourceGroup in $ResourceGroups) {
		$RG = New-Object AzureResourceGroup
		$RG.AzureObject = $ResourceGroup
		$RG.Subscription = $Sub
		$RG.Name = $ResourceGroup.ResourceGroupName
		$AccessibleResourceGroups += $RG
		$Sub.ResourceGroups += $RG

                # Retrieve Resources associated with Resource Group
	        $Resources = Get-AzResource -DefaultProfile $Context -ResourceGroupName $ResourceGroup.ResourceGroupName

	        ForEach($Resource in $Resources) {
		    $Res = New-Object AzureResource
		    $Res.AzureObject = $Resource
		    $Res.ResourceGroup = $RG
		    $AccessibleResources += $Res
		    $RG.Resources += $Res
	        }
	    }
	} Else {
	    # No read access to any resource groups, enumerating resources
	    $IdentifiedResources = Get-AzResource -DefaultProfile $Context
	    $IdentifiedResourceGroups = $IdentifiedResources | Sort-Object -Property ResourceGroupName | Select-Object -Property ResourceGroupName

	    ForEach($ResourceGroup in $IdentifiedResourceGroups) {
		$RG = New-Object AzureResourceGroup
		$RG.AzureObject = $null
		$RG.Subscription = $Sub
		$RG.Name = $ResourceGroup.ResourceGroupName
		$AccessibleResourceGroups += $RG
		$Sub.ResourceGroups += $RG

		$Resources = $IdentifiedResources | Where-Object { $_.ResourceGroupName -eq $RG.Name }

	        ForEach($Resource in $Resources) {
		    $Res = New-Object AzureResource
		    $Res.AzureObject = $Resource
		    $Res.ResourceGroup = $RG
		    $AccessibleResources += $Res
		    $RG.Resources += $Res
		}
	    }	
	}
    }

    # Need to populate Parent and Children Info for ManagementGroups now that we've retrieved all other info
    ForEach($Group in $AccessibleMgmtGroups) {
	$FullInfo = Get-AzManagementGroup -DefaultProfile $Context -GroupName $Group.AzureObject.Name -Expand

	If($FullInfo.ParentId -eq $null) {
	    $Group.ParentGroup = $null
	} Else {
	    $Group.ParentGroup = ($AccessibleMgmtGroups | Where-Object { $_.AzureObject.Name -eq $FullInfo.ParentName })
        }

	ForEach($Child in $FullInfo.Children) {
	    If($Child.Type -eq "/providers/Microsoft.Management/managementGroups") {
		$Group.ChildGroups += ($AccessibleMgmtGroups | Where-Object { $_.AzureObject.Name -eq $Child.Name })
	    } Else {
		$ChildSub = ($AccessibleSubscriptions | Where-Object { $_.AzureObject.Id -eq $Child.Name })
		$Group.ChildSubscriptions += $ChildSub
		$ChildSub.ParentGroup = $Group
	    }
	}
    }

    return @{ Tenants = $AccessibleTenants; ManagementGroups = $AccessibleMgmtGroups; Subscriptions = $AccessibleSubscriptions; ResourceGroups = $AccessibleResourceGroups; Resources = $AccessibleResources }
}

function Write-RecursiveAzureItems ($Root, $Level) {
    If($Root.GetType().Name -eq "AzureTenant") {
        Write-Host (('    ' * $Level) + $Root.AzureObject.Name + " (Tenant)")
	Write-RecursiveAzureItems $Root.RootGroup ($Level + 1)
    } ElseIf($Root.GetType().Name -eq "AzureMgmtGroup") {
	Write-Host ""
        Write-Host (('    ' * $Level) + $Root.AzureObject.DisplayName + " (Management Group)")
	ForEach($ChildSub in $Root.ChildSubscriptions) {
	    Write-RecursiveAzureItems $ChildSub ($Level + 1)
	}
	ForEach($ChildGroup in $Root.ChildGroups) {
	    Write-RecursiveAzureItems $ChildGroup ($Level + 1)
	}
    } ElseIf($Root.GetType().Name -eq "AzureSubscription") {
	Write-Host ""
        Write-Host (('    ' * $Level) + $Root.AzureObject.Name + " (Subscription)")
	ForEach($RG in $Root.ResourceGroups) {
	    Write-RecursiveAzureItems $RG ($Level + 1)
	}
    } ElseIf($Root.GetType().Name -eq "AzureResourceGroup") {
	If($Root.AzureObject.ResourceGroupName -ne $null) {
            Write-Host (('    ' * $Level) + $Root.AzureObject.ResourceGroupName + " (Resource Group)")
	} Else {
            Write-Host (('    ' * $Level) + $Root.Name + " (Resource Group) (No Access)")
	}
	ForEach($Res in $Root.Resources) {
	    Write-RecursiveAzureItems $Res ($Level + 1)
	}
    } ElseIf($Root.GetType().Name -eq "AzureResource") {
        Write-Host (('    ' * $Level) + $Root.AzureObject.Name + " (Resource)")
    }
}

######################## Understand GENERAL ########################

function Write-AccessibleResourcesSummary ($AllResources) {
    Write-Host "Printing out a summary of all accessible resources/resource groups/subscriptions/management groups/tenants with the provided credentials"
    Write-Host ""
    Write-Host "Tenants:"
    ForEach($Tenant in $AllResources.Tenants) {
        Write-Host ('{0} ({1}) - {2}' -f $Tenant.AzureObject.Id, $Tenant.AzureObject.Name, ($Tenant.AzureObject.Domains -join ","))

	If($AllResources.ManagementGroups.Count -gt 0) {
	    Write-Host "  Management Groups/Subscriptions: "
	    If($Tenant.RootGroup -ne $null) {
	        Write-Host ("    {0}:" -f $Tenant.RootGroup.AzureObject.DisplayName)
		ForEach($ChildSub in $Tenant.RootGroup.ChildSubscriptions) {
		    Write-Host ("") 
		}
	    } Else {
	        # If we don't have read on the Root Management Group, just list the groups we have access to	
	    }
	} Else {
	    Write-Host "  Management Groups: "
	    Write-Host "    (No access)"
	}
    }
}


function Write-AccessibleResources ($AllResources) {
    Write-Host "Printing out all accessible resources/resource groups/subscriptions/management groups/tenants with the provided credentials"
    Write-Host ""
    # TODO: Recurse through and print resources
    ForEach($Tenant in $AllResources.Tenants) {
	If($Tenant.RootGroup -ne $null) {
            Write-RecursiveAzureItems $Tenant 0
	} Else {
            # No ManagementGroup Group Access
	    # TODO: Properly handle some Mgmt Group access where user doesn't have root mgmt group access
	    If($Tenant.AzureObject.Name -ne $null) {
	        Write-Host ($Tenant.AzureObject.Name + " (Tenant)")
	    } Else {
	        Write-Host ($Tenant.AzureObject.Id + " (Tenant)")
	    }
	    ForEach($Subs in $AllResources.Subscriptions) {
	        Write-RecursiveAzureItems $Subs 1
	    }
	}
    }
}

######################## Understand NETWORK ########################

# Prints Public IPs, etc
function Write-PublicAttackSurface ($AllResources) {
    Write-Host "Not yet implemented."
}

function Write-VirtualNetworksInfo ($AllResources) {
    Write-Host "Not yet implemented."
}

######################## Understand COMPUTE ########################

function Write-VirtualMachinesInfo ($AllResources) {
    Write-Host "Not yet implemented."
}

function Write-AppServicesInfo ($AllResources) {
    Write-Host "Not yet implemented."
}

######################## Understand STORAGE ########################

function Write-KeyVaultsInfo ($AllResources) {
    # KeyVaults store Certificates, Key/Values, Secrets, Managed StorageAccount Keys, and HSMs
    # TODO: Enumerate HSMs which are not held in KeyVaults, but associated with RG/Sub 
    $KeyVaults = $AllResources | Where-Object { $_.ResourceType -eq "Microsoft.KeyVault/vaults" }

    Write-Host ""
    Write-Host ("Enumerating accessible KeyVaults' contents...Found {0} accessible KeyVaults" -f ($KeyVaults | Measure-Object).Count)

    forEach($KeyVault in $KeyVaults) {
	Write-Host ("KeyVault {0}:" -f $KeyVault.Name)

	$Certificates = Get-AzKeyVaultCertificate -VaultName $KeyVault.Name
	$Keys = Get-AzKeyVaultKey -VaultName $KeyVault.Name
	$Secrets = Get-AzKeyVaultSecret -VaultName $KeyVault.Name
	$MSAs = Get-AzKeyVaultManagedStorageAccount -VaultName $KeyVault.Name

        Write-Host ""
        Write-Host "  Certificates: "
	ForEach($Certificate in $Certificates) {
	    Write-Host ('    * {0}' -f $Certificate.Name)
	}

        Write-Host ""
        Write-Host "  Keys: "
	ForEach($Key in $Keys) {
	    Write-Host ('    * {0}' -f $Key.Name)
	}

        Write-Host ""
        Write-Host "  Secrets: "
	ForEach($Secret in $Secrets) {
	    Write-Host ('    * {0}' -f $Secret.Name)
	}

        Write-Host ""
        Write-Host "  Managed Storage Account Keys: "
	ForEach($MSA in $MSAs) {
	    Write-Host ('    * {0}' -f $MSA.AccountName)
	}
    }	
}

function Write-StorageAccountsInfo {
    Param (
        [Parameter(Mandatory=$true, Position=0)][AllowNull()][Object[]] $AllResources,
	[Parameter(Mandatory=$true, Position=1)][AllowNull()][Object] $StorageAccountContext
    )

    # Storage Accounts store Containers (Blobs), Shares (Files), Queues (Queue), and Tables (Table)
    # TODO: Support auth with connection string and sas tokens
    Write-Host ""
    If($StorageAccountContext -eq $null) {
        $StorageAccounts = $AllResources | Where-Object { $_.ResourceType -eq "Microsoft.Storage/storageAccounts" }
	Write-Host ("Enumerating accessible StorageAccounts' contents...Found {0} accessible StorageAccounts" -f ($StorageAccounts | Measure-Object).Count)
    } Else {
        Write-Host "Enumerating 1 accessible StorageAccount"
	$StorageAccounts = @( @{ Name = $StorageAccountContext.StorageAccountName } ) 
    }
    
    forEach($StorageAccount in $StorageAccounts) {
	Write-Host ""
	Write-Host ("StorageAccount {0}:" -f $StorageAccount.Name)

	If($StorageAccountContext -eq $null) {
	    $AccountKeys = Get-AzStorageAccountKey -ResourceGroupName $StorageAccount.ResourceGroupName -Name $StorageAccount.Name
	    # May need to use Storage Account Keys that identity has access to
	    If($AccountKeys.Count -gt 0) {
		$StorageContext = New-AzStorageContext -StorageAccountName $StorageAccount.Name -StorageAccountKey $AccountKeys[0].Value
	    } Else {
	        $StorageContext = New-AzStorageContext -StorageAccountName $StorageAccount.Name
	    }
	} Else {
	    $StorageContext = $StorageAccountContext
	}

	$Containers = Get-AzStorageContainer -Context $StorageContext
	$Shares = Get-AzStorageShare -Context $StorageContext
	$Queues = Get-AzStorageQueue -Context $StorageContext
	$Tables = Get-AzStorageTable -Context $StorageContext

	Write-Host ""
        Write-Host "  Containers/Blobs: "
	ForEach($Container in $Containers) {
	    Write-Host ('    * {0}: ' -f $Container.Name)

	    try {
	        $Blobs = Get-AzStorageBlob -Context $StorageContext -Container $Container.Name -ErrorAction Stop
	    } catch {
	        If($_.Exception.message.Contains("AuthorizationPermissionMismatch")) {
		    Write-Host "      (No List access to container)"
		}
		$Blobs = @()
	    }
	    
	    ForEach($Blob in $Blobs) {
	        Write-Host ('      - {0}' -f $Blob.Name)
	    }
	}
        
	Write-Host ""
        Write-Host "  Shares/Files: "
	ForEach($Share in $Shares) {
	    Write-Host ('    * {0}: ' -f $Share.Name)

	    try {
	        $Files = Get-AzStorageFile -Context $StorageContext -ShareName $Share.Name -ErrorAction Stop
	    } catch {
	        If($_.Exception.message.Contains("AuthorizationPermissionMismatch")) {
		    Write-Host "      (No List access to share)"
		}
		$Files = @()
	    }
	    
	    ForEach($File in $Files) {
	        Write-Host ('      - {0}' -f $File.Name)
	    }
	}
        
	Write-Host ""
        Write-Host "  Queues: "
	ForEach($Queue in $Queues) {
	    Write-Host ('    * {0}: ' -f $Queue.Name)
	}
        
	Write-Host ""
        Write-Host "  Tables: "
	ForEach($Table in $Tables) {
	    Write-Host ('    * {0}: ' -f $Table.Name)
	}
    }
}



######################## Expand ACCESS ########################

function Run-SecretSearch ($AllResources) {
    Write-Host ""
    Write-Host "Searching for other accessible secrets and credentials"

    # Azure Container Registry Access Keys
    $ACRs = $AllResources | Where-Object { $_.ResourceType -eq "Microsoft.ContainerRegistry/registries" }
    Write-Host ("Found {0} accessible Azure Container Registries" -f ($ACRs | Measure-Object).Count)
    If($ACRs.Count -gt 0) {
	ForEach($ACR in $ACRs) {
	    $Creds = Get-AzContainerRegistryCredential -ResourceGroupName $ACR.ResourceGroupName -Name $ACR.Name
	    Write-Host ("ACR Name: " + $ACR.Name)
	    Write-Host "Username: " + $Creds.Username
	    Write-Host "Password: " + $Creds.Password
	    Write-Host "Password 2: " + $Creds.Password2
	}
    }
}

function Show-Menu {
    param (
      [string] $CredType
    )

    Write-Host ""
    Write-Host "Here are your options: "
    Write-Host ""
    
    If(($CredType -eq "user") -Or ($CredType -eq "sp")) {
        Write-Host "  [Discovery]"
        Write-Host "    General:"
        Write-Host "      1) Print out summary of accessible items"
        Write-Host "      2) Print out all accessible resources/resource groups/subscriptions/management groups"
        Write-Host "    Network:"
        Write-Host "      3) Print out Public Attack Surface (such as Public IPs, Anonymous List Buckets, etc)"
        Write-Host "      4) Print out Virtual Networks"
        Write-Host "    Compute:"
        Write-Host "      5) Print out Virtual Machines"
        Write-Host "      6) Print out App Services"
        Write-Host "      7) Print out Azure Functions"
        Write-Host "      8) Print out Azure SQL Servers & Cosmos DBs"
        Write-Host "      9) Print out Containers and K8Ss"
        Write-Host "    Storage:"
        Write-Host "      10) Print out accessible Key Vaults"
        Write-Host "      11) Print out accessible Storage Accounts"
        Write-Host "      12) Print out accessible Disks & Snapshots"
        Write-Host "  [Credential Access]"
        Write-Host "      13) Scan and dump accessible secrets (Key Vault Keys, App Services, SA Keys, etc)"
        Write-Host "  [Execution]"
        Write-Host "      14) What Compute 'creation' operations can you do (Create VMs, Create Functions, etc)"
        Write-Host "      15) What Compute 'control' operations can you do (Start/Stop VMs, Run Commands, Install Custom Extensions, etc)"
        Write-Host "  [Collection/Exfiltration]"
        Write-Host "      16) Download Storage Object Contents"
    } ElseIf($CredType -eq "sa") {
        Write-Host "  [Discovery]"
        Write-Host "    Storage:"
        Write-Host "      1) Print out the accessible Storage Account's Contents"
        Write-Host "  [Collection/Exfiltration]"
        Write-Host "      2) Download Storage Object Contents"
    }
    
    Write-Host ""
}

function ADVENTUROUSZULU {
<# 
.SYNOPSIS
   Main Script Function 
#>
    $ErrorActionPreference = "SilentlyContinue"

    If(Check-Dependencies) {
        Write-Host "Welcome to ADVENTUROUSZULU" 
    } Else {
        Write-Host "You do not meet the minimum dependencies to run ADVENTUROUSZULU"
        Exit
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
    
    NOTE: Tenant is displayed as 'id' sometimes such as in the return value when creating an SP
    
"@

    $CredentialType = Read-Host -Prompt "Enter the type of credential you have (user, sa, or sp)"

    # Obtain credentials/secrets from the operator
    If($CredentialType -eq "user") {
        Confirm-UserCredential
    } ElseIf($CredentialType -eq "sa") {
	$StorageAccountContext = Confirm-StorageAccountCredential
    } ElseIf($CredentialType -eq "sp") {
	Confirm-ServicePrincipalCredential 
    } Else {
	Write-Host "Unsupported Credential Type, exiting"
	Exit
    }

    # Now that we have some credentials/secrets, it's time to retrieve accessible info
    If(($CredentialType -eq "user") -Or ($CredentialType -eq "sp")) {
	$AllResources = Get-AccessibleResources
    }

    Do {
        Show-Menu $CredentialType
	$Selection = Read-Host "Please enter your selection (or q to quit)"
	Write-Host ""

        If(($CredentialType -eq "user") -Or ($CredentialType -eq "sp")) {
	    Switch($Selection) {
	        '1' {
		    Write-AccessibleResourcesSummary $AllResources
	        } '2' {
		    Write-AccessibleResources $AllResources
	        } '3' {
		    Write-PublicAttackSurface $AllResources
	        } '4' {
		    Write-VirtualNetworksInfo $AllResources
	        } '5' {
		    Write-VirtualMachinesInfo $AllResources
	        } '6' {
		    Write-AppServicesInfo $AllResources
	        } '7' {
	        } '8' {
	        } '9' {
	        } '10' {
		    Write-KeyVaultsInfo $AllResources
	        } '11' {
		    Write-StorageAccountsInfo $AllResources $null
	        } '12' {
	        } '13' {
	        } '14' {
		} 'q' {
		    Exit
	        } default {
		    Write-Host "Invalid option"
		}
            }
	} ElseIf($CredentialType -eq "sa") {
	    Switch($Selection) {
	        '1' {
		    Write-StorageAccountsInfo $null $StorageAccountContext
	        } '2' {
		} 'q' {
		    Exit
	        } default {
		    Write-Host "Invalid option"
		}
            }
	}
    } Until (($Selection -eq 'q') -Or ($Selection -eq 'quit') -Or ($Selection -eq 'exit'))
}

ADVENTUROUSZULU
