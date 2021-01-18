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
    [Object] $AzureContext
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

function Confirm-AccessTokenCredential {
    $AccessToken = (Read-Host -Prompt "Enter your Azure JWT Access Token").Trim()
    $KVAccessToken = (Read-Host -Prompt "Enter your Azure Key Vault JWT Access Token (if applicable) else just press enter").Trim()
    $JWT = Parse-JWTtoken $AccessToken
    If($KVAccessToken -ne "") {
        $KVJWT = Parse-JWTtoken $KVAccessToken
        $AzureAccount = Connect-AzAccount -AccessToken $AccessToken -KeyVaultAccessToken $KVJWT -AccountId $JWT.upn
    } Else {
        $AzureAccount = Connect-AzAccount -AccessToken $AccessToken -AccountId $JWT.upn
    }


    If($AzureAccount -ne $null) {
	Write-Host "JWT Credential is valid"
    } Else {
	# TODO: Display info about why credentials were invalid as returned by Connect-AzAccount
	Write-Host "Invalid JWT Credential!"
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
    # TODO: Require at least Az 5.3
    If($SystemModules.Name -NotContains "Az") {
        Write-Host "Azure PowerShell is not installed"
    }

    return $true
}

# Function from: https://www.michev.info/Blog/Post/2140/decode-jwt-access-and-id-tokens-via-powershell
function Parse-JWTtoken {
    param([Parameter(Mandatory=$true)][string]$token)
 
    If(!$token.Contains(".") -or !$token.StartsWith("eyJ")) {
        Write-Error "Invalid token" -ErrorAction Stop 
    }
 
    $tokenheader = $token.Split(".")[0].Replace('-', '+').Replace('_', '/')
    while ($tokenheader.Length % 4) { $tokenheader += "=" }
 
    $tokenPayload = $token.Split(".")[1].Replace('-', '+').Replace('_', '/')
    while ($tokenPayload.Length % 4) { $tokenPayload += "=" }
    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
    $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
    $tokobj = $tokenArray | ConvertFrom-Json
    
    return $tokobj
}

function Get-AccessibleResourcesFromAzure {
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
	$Context = Set-AzContext -SubscriptionId $Subscription.Id
	$Sub.AzureContext = $Context
	$AccessibleSubscriptions += $Sub
        
        # Retrieve Resource Groups associated with Subscription
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
	$FullInfo = Get-AzManagementGroup -DefaultProfile $Context -GroupId $Group.AzureObject.Name -Expand

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

function Get-RecursiveAzureItems ($Root, $Level) {
    If($Root.GetType().Name -eq "AzureTenant") {
        Write-Host (('    ' * $Level) + $Root.AzureObject.Name + " (Tenant)")
	Get-RecursiveAzureItems $Root.RootGroup ($Level + 1) 
    } ElseIf($Root.GetType().Name -eq "AzureMgmtGroup") {
	Write-Host ""
        Write-Host (('    ' * $Level) + $Root.AzureObject.DisplayName + " (Management Group)")
	ForEach($ChildSub in $Root.ChildSubscriptions) {
	    Get-RecursiveAzureItems $ChildSub ($Level + 1) 
	}
	ForEach($ChildGroup in $Root.ChildGroups) {
	    Get-RecursiveAzureItems $ChildGroup ($Level + 1)
	}
    } ElseIf($Root.GetType().Name -eq "AzureSubscription") {
	Write-Host ""
        Write-Host (('    ' * $Level) + $Root.AzureObject.Name + " (Subscription)")
	ForEach($RG in $Root.ResourceGroups) {
	    Get-RecursiveAzureItems $RG ($Level + 1) 
	}
    } ElseIf($Root.GetType().Name -eq "AzureResourceGroup") {
	If($Root.AzureObject.ResourceGroupName -ne $null) {
            Write-Host (('    ' * $Level) + $Root.AzureObject.ResourceGroupName + " (Resource Group)")
	} Else {
            Write-Host (('    ' * $Level) + $Root.Name + " (Resource Group) (No Access)")
	}
	ForEach($Res in $Root.Resources) {
	    Get-RecursiveAzureItems $Res ($Level + 1) 
	}
    } ElseIf($Root.GetType().Name -eq "AzureResource") {
        Write-Host (('    ' * $Level) + $Root.AzureObject.Name + " (" + $Root.AzureObject.ResourceType + ")")
    }
}

######################## Understand GENERAL ########################

function Get-AccessibleResourcesSummary ($AllResources) {
    Write-Host "Printing out a summary of all accessible resources/resource groups/subscriptions/management groups/tenants with the provided credentials"
    Write-Host ""
    Write-Host ("You have some level of access to {0} tenants" -f $AllResources.Tenants.Count) 
    Write-Host ("You have some level of access to {0} management groups" -f $AllResources.ManagementGroups.Count) 
    Write-Host ("You have some level of access to {0} subscriptions" -f $AllResources.Subscriptions.Count) 
    Write-Host ("You have some level of access to {0} resource groups" -f $AllResources.ResourceGroups.Count) 
    Write-Host ("You have some level of access to {0} resources" -f $AllResources.Resources.Count)
    Write-Host ""
    Write-Host "Of these resources, there are: "
    $ResourceTypes = @{}
    $AllResources.Resources | ForEach-Object {
	If($ResourceTypes.ContainsKey($_.AzureObject.ResourceType)) {
	    $ResourceTypes[$_.AzureObject.ResourceType] += 1
	} Else {
	    $ResourceTypes.Add($_.AzureObject.ResourceType, 1)
	}
    }

    ForEach($ResourceType in $ResourceTypes.GetEnumerator() | Sort Name) {
        Write-Host ("    {0} {1}" -f $ResourceTypes[$ResourceType.Name], $ResourceType.Name)
    }
}


function Get-AccessibleResources ($AllResources) {
    Write-Host "Printing out all accessible resources/resource groups/subscriptions/management groups/tenants with the provided credentials"
    Write-Host ""
    ForEach($Tenant in $AllResources.Tenants) {
	If($Tenant.RootGroup -ne $null) {
            Get-RecursiveAzureItems $Tenant 0
	} Else {
            # No ManagementGroup Group Access
	    # TODO: Properly handle some Mgmt Group access where user doesn't have root mgmt group access
	    If($Tenant.AzureObject.Name -ne $null) {
	        Write-Host ($Tenant.AzureObject.Name + " (Tenant)")
	    } Else {
	        Write-Host ($Tenant.AzureObject.Id + " (Tenant)")
	    }
	    ForEach($Subs in $AllResources.Subscriptions) {
	        Get-RecursiveAzureItems $Subs 1
	    }
	}
    }
}

######################## Understand NETWORK ########################

# Prints Public IPs, etc
function Get-PublicAttackSurface ($AllResources) {
    Write-Host "Not yet implemented."
}

function Get-VirtualNetworksInfo ($AllResources) {
    Write-Host "Not yet implemented."
}

######################## Understand COMPUTE ########################

function Get-VirtualMachinesInfo ($AllResources) {
    Write-Host "Not yet implemented."
}

function Get-AppServicesInfo ($AllResources) {
    Write-Host "Not yet implemented."
}

######################## Understand STORAGE ########################

function Get-KeyVaultsInfo ($AllResources, $DisplayValues) {
    # KeyVaults store Certificates, Key/Values, Secrets, Managed StorageAccount Keys, and HSMs
    # TODO: Enumerate HSMs which are not held in KeyVaults, but associated with RG/Sub 
    $KeyVaults = $AllResources.Resources | Where-Object { $_.AzureObject.ResourceType -eq "Microsoft.KeyVault/vaults" }
    Write-Host ""

    If($DisplayValues) {
        If($KeyVaults.Count -gt 0) {
            Write-Host ("You have access to the following {0} Key Vaults: " -f $KeyVaults.Count)
	    For($i = 0; $i -lt $KeyVaults.Count; $i++) {
	        Write-Host ("    {0}) {1}" -f $i, $KeyVaults[$i].AzureObject.Name)
	    }
	    Write-Host ""
	    $Selection = Read-Host "Please enter the number of the Key Vault you'd like to view secrets in or 'all' to target each one"
	    If($Selection -eq "all") {
	        # Enum all key vaults
	    } ElseIf(([int]$Selection -ge 0) -And ([int]$Selection -lt $KeyVaults.Count)) {
	        # Enum specific key vaults
	    } Else {
	        Write-Host "Invalid input, skipping Key Vaults."
		return
	    }
        } Else {
	    Write-Host "No Key Vaults to pillage!"
	}
    } Else {
        Write-Host ("Enumerating accessible KeyVaults' contents...Found {0} accessible KeyVaults" -f ($KeyVaults | Measure-Object).Count)
    }

    $i = -1
    ForEach($KeyVault in $KeyVaults) {
	$i += 1
	If($DisplayValues -And ($Selection -ne "all") -And ($Selection -ne $i)) {
	    continue
	}
	Write-Host ""
	$Context = $KeyVault.ResourceGroup.Subscription.AzureContext
	Write-Host ("KeyVault {0}:" -f $KeyVault.AzureObject.Name)

        Write-Host ""
        Write-Host "  Certificates: "
        try {
	    $Certificates = Get-AzKeyVaultCertificate -VaultName $KeyVault.AzureObject.Name -DefaultProfile $Context -ErrorAction Stop
	    ForEach($Certificate in $Certificates) {
	        Write-Host ('    * {0}' -f $Certificate.Name)
	    }
	} catch {
	    If($_.Exception.message.Contains("Forbidden") -Or $_.Exception.message.Contains("Unauthorized")) {
	        Write-Host "    (No List access to Certificates)"
	    }
	}
	
        Write-Host ""
        Write-Host "  Keys: "
	try {
	    $Keys = Get-AzKeyVaultKey -VaultName $KeyVault.AzureObject.Name -DefaultProfile $Context -ErrorAction Stop
	    ForEach($Key in $Keys) {
	        Write-Host ('    * {0}' -f $Key.Name)
	    }
	} catch {
	    If($_.Exception.message.Contains("Forbidden") -Or $_.Exception.message.Contains("Unauthorized")) {
	        Write-Host "    (No List access to Keys)"
	    }
	}

        Write-Host ""
        Write-Host "  Secrets: "
	try {
	    $Secrets = Get-AzKeyVaultSecret -VaultName $KeyVault.AzureObject.Name -DefaultProfile $Context -ErrorAction Stop
	    ForEach($Secret in $Secrets) {
		If($DisplayValues) {
	            try {
		        $Sec = Get-AzKeyVaultSecret -VaultName $KeyVault.AzureObject.Name -Name $Secret.Name -DefaultProfile $Context -ErrorAction Stop
		        $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Sec.SecretValue)
		        try {
		            $SecretValueText = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
		        } finally {
		            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
		        }
	                Write-Host ('    * {0} - {1}' -f $Sec.Name, $SecretValueText)
		    } catch {
	                Write-Host ('    * {0} - (No Read Access!)' -f $Sec.Name)
		    }
		} Else {
	            Write-Host ('    * {0}' -f $Secret.Name)
		}
	    }
	} catch {
	    If($_.Exception.message.Contains("Forbidden") -Or $_.Exception.message.Contains("Unauthorized")) {
	        Write-Host "    (No List access to Secrets)"
	    }
	}

        Write-Host ""
        Write-Host "  Managed Storage Account Keys: "
	try {
	    $MSAs = Get-AzKeyVaultManagedStorageAccount -VaultName $KeyVault.AzureObject.Name -DefaultProfile $Context
	    ForEach($MSA in $MSAs) {
	        Write-Host ('    * {0}' -f $MSA.AccountName)
	    }
	} catch {
	    If($_.Exception.message.Contains("Forbidden") -Or $_.Exception.message.Contains("Unauthorized")) {
	        Write-Host "    (No List access to MSAs)"
	    }
	}

    }	
}

function Get-StorageAccountsInfo {
    Param (
        [Parameter(Mandatory=$true, Position=0)][AllowNull()][Object[]] $AllResources,
	[Parameter(Mandatory=$true, Position=1)][AllowNull()][Object] $StorageAccountContext
    )

    # Storage Accounts store Containers (Blobs), Shares (Files), Queues (Queue), and Tables (Table)
    # TODO: Support auth with connection string and sas tokens
    Write-Host ""
    If($StorageAccountContext -eq $null) {
        $StorageAccounts = $AllResources.Resources | Where-Object { $_.AzureObject.ResourceType -eq "Microsoft.Storage/storageAccounts" }
	Write-Host ("Enumerating accessible StorageAccounts' contents...Found {0} accessible StorageAccounts" -f ($StorageAccounts | Measure-Object).Count)
    } Else {
        Write-Host "Enumerating 1 accessible StorageAccount"
	$StorageAccounts = @( @{ Name = $StorageAccountContext.StorageAccountName } ) 
    }
    
    ForEach($StorageAccount in $StorageAccounts) {
	Write-Host ""

	If($StorageAccountContext -eq $null) {
	    Write-Host ("StorageAccount {0}:" -f $StorageAccount.AzureObject.Name)
	    $Context = $StorageAccount.ResourceGroup.Subscription.AzureContext
	    $AccountKeys = Get-AzStorageAccountKey -ResourceGroupName $StorageAccount.AzureObject.ResourceGroupName -Name $StorageAccount.AzureObject.Name -DefaultProfile $Context
	    # May need to use Storage Account Keys that identity has access to
	    If($AccountKeys.Count -gt 0) {
		$StorageContext = New-AzStorageContext -StorageAccountName $StorageAccount.AzureObject.Name -StorageAccountKey $AccountKeys[0].Value
	    } Else {
	        $StorageContext = New-AzStorageContext -StorageAccountName $StorageAccount.AzureObject.Name
	    }
	} Else {
	    Write-Host ("StorageAccount {0}:" -f $StorageAccount.Name)
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
	    If($Share.IsSnapshot) {
		Write-Host ('    * {0} (Snapshot from {1}): ' -f $Share.Name, $Share.SnapshotTime)
	    } Else {
		Write-Host ('    * {0}: ' -f $Share.Name)
	    }

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



######################## Credential Access ########################

function Run-SecretSearch ($AllResources) {
    Write-Host ""
    Write-Host "Searching for other accessible secrets and credentials"
    Write-Host ""

    # Azure Container Registry Access Keys
    $ACRs = $AllResources.Resources | Where-Object { $_.AzureObject.ResourceType -eq "Microsoft.ContainerRegistry/registries" }
    Write-Host ("Found {0} accessible Azure Container Registries" -f ($ACRs | Measure-Object).Count)
    If($ACRs.Count -gt 0) {
	ForEach($ACR in $ACRs) {
	    $Creds = Get-AzContainerRegistryCredential -ResourceGroupName $ACR.AzureObject.ResourceGroupName -Name $ACR.AzureObject.Name
	    Write-Host ("ACR Name: " + $ACR.AzureObject.Name)
	    Write-Host ("Username: " + $Creds.Username)
	    Write-Host ("Password: " + $Creds.Password)
	    Write-Host ("Password 2: " + $Creds.Password2)
	}
    }
}

function Read-ResourceSecrets ($AllResources) {
    Write-Host ""
    Get-KeyVaultsInfo $AllResources $true
}

######################## Program Main ########################

function Show-Menu {
    param (
      [string] $CredType
    )

    Write-Host ""
    Write-Host "Here are your options: "
    Write-Host ""
    
    If(($CredType -eq "user") -Or ($CredType -eq "sp") -Or ($CredType -eq "jwt")) {
        Write-Host "  [Discovery]"
        Write-Host "    General:"
        Write-Host "      1) Print out a summary of accessible items"
        Write-Host "      2) Print out all of the accessible resources/resource groups/subscriptions/management groups"
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
        Write-Host "      13) Scan and dump secrets from all accessible services (Key Vault Keys, App Services, SA Keys, etc)"
        Write-Host "      14) Dump secrets from particular service/resource (such as accessible Key Vaults)"
        Write-Host "  [Execution]"
        Write-Host "      15) What Compute 'creation' operations can you do (Create VMs, Create Functions, etc)"
        Write-Host "      16) What Compute 'control' operations can you do (Start/Stop VMs, Run Commands, Install Custom Extensions, etc)"
        Write-Host "  [Collection/Exfiltration]"
        Write-Host "      17) Download Storage Object Contents"
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
JWT Credential (jwt):
    Example 1:
    Bearer Token (for management.core.windows.net): eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imk2bEdrM0ZaenhSY1ViMkMzbkVRN3N5SEpsWSJ9.eyJhdWQiOiI2ZTc0MTcyYi1iZTU2LTQ4NDMtOWZmNC1lNjZhMzliYjEyZTMiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3L3YyLjAiLCJpYXQiOjE1MzcyMzEwNDgsIm5iZiI6MTUzNzIzMTA0OCwiZXhwIjoxNTM3MjM0OTQ4LCJhaW8iOiJBWFFBaS84SUFBQUF0QWFaTG8zQ2hNaWY2S09udHRSQjdlQnE0L0RjY1F6amNKR3hQWXkvQzNqRGFOR3hYZDZ3TklJVkdSZ2hOUm53SjFsT2NBbk5aY2p2a295ckZ4Q3R0djMzMTQwUmlvT0ZKNGJDQ0dWdW9DYWcxdU9UVDIyMjIyZ0h3TFBZUS91Zjc5UVgrMEtJaWpkcm1wNjlSY3R6bVE9PSIsImF6cCI6IjZlNzQxNzJiLWJlNTYtNDg0My05ZmY0LWU2NmEzOWJiMTJlMyIsImF6cGFjciI6IjAiLCJuYW1lIjoiQWJlIExpbmNvbG4iLCJvaWQiOiI2OTAyMjJiZS1mZjFhLTRkNTYtYWJkMS03ZTRmN2QzOGU0NzQiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhYmVsaUBtaWNyb3NvZnQuY29tIiwicmgiOiJJIiwic2NwIjoiYWNjZXNzX2FzX3VzZXIiLCJzdWIiOiJIS1pwZmFIeVdhZGVPb3VZbGl0anJJLUtmZlRtMjIyWDVyclYzeERxZktRIiwidGlkIjoiNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3IiwidXRpIjoiZnFpQnFYTFBqMGVRYTgyUy1JWUZBQSIsInZlciI6IjIuMCJ9.pj4N-w_3Us9DrBLfpCt
    
    Example 2:
    Bearer Token (for management.core.windows.net): eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imk2bEdrM0ZaenhSY1ViMkMzbkVRN3N5SEpsWSJ9.eyJhdWQiOiI2ZTc0MTcyYi1iZTU2LTQ4NDMtOWZmNC1lNjZhMzliYjEyZTMiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3L3YyLjAiLCJpYXQiOjE1MzcyMzEwNDgsIm5iZiI6MTUzNzIzMTA0OCwiZXhwIjoxNTM3MjM0OTQ4LCJhaW8iOiJBWFFBaS84SUFBQUF0QWFaTG8zQ2hNaWY2S09udHRSQjdlQnE0L0RjY1F6amNKR3hQWXkvQzNqRGFOR3hYZDZ3TklJVkdSZ2hOUm53SjFsT2NBbk5aY2p2a295ckZ4Q3R0djMzMTQwUmlvT0ZKNGJDQ0dWdW9DYWcxdU9UVDIyMjIyZ0h3TFBZUS91Zjc5UVgrMEtJaWpkcm1wNjlSY3R6bVE9PSIsImF6cCI6IjZlNzQxNzJiLWJlNTYtNDg0My05ZmY0LWU2NmEzOWJiMTJlMyIsImF6cGFjciI6IjAiLCJuYW1lIjoiQWJlIExpbmNvbG4iLCJvaWQiOiI2OTAyMjJiZS1mZjFhLTRkNTYtYWJkMS03ZTRmN2QzOGU0NzQiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhYmVsaUBtaWNyb3NvZnQuY29tIiwicmgiOiJJIiwic2NwIjoiYWNjZXNzX2FzX3VzZXIiLCJzdWIiOiJIS1pwZmFIeVdhZGVPb3VZbGl0anJJLUtmZlRtMjIyWDVyclYzeERxZktRIiwidGlkIjoiNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3IiwidXRpIjoiZnFpQnFYTFBqMGVRYTgyUy1JWUZBQSIsInZlciI6IjIuMCJ9.pj4N-w_3Us9DrBLfpCt
    Key Vault Access Token (for vault.azure.net): eyJ0...

"@

    $CredentialType = Read-Host -Prompt "Enter the type of credential you have (user, sa, sp, or jwt)"

    # Obtain credentials/secrets from the operator
    If($CredentialType -eq "user") {
        Confirm-UserCredential
    } ElseIf($CredentialType -eq "sa") {
	$StorageAccountContext = Confirm-StorageAccountCredential
    } ElseIf($CredentialType -eq "sp") {
	Confirm-ServicePrincipalCredential 
    } ElseIf($CredentialType -eq "jwt") {
	Confirm-AccessTokenCredential 
    } Else {
	Write-Host "Unsupported Credential Type, exiting"
	Exit
    }

    # Now that we have some credentials/secrets, it's time to retrieve accessible info
    If(($CredentialType -eq "user") -Or ($CredentialType -eq "sp") -Or ($CredentialType -eq "jwt")) {
	$AllResources = Get-AccessibleResourcesFromAzure
    }

    Do {
        Show-Menu $CredentialType
	$Selection = Read-Host "Please enter your selection (or q to quit)"
	Write-Host ""

        If(($CredentialType -eq "user") -Or ($CredentialType -eq "sp") -Or ($CredentialType -eq "jwt")) {
	    Switch($Selection) {
	        '1' {
		    Get-AccessibleResourcesSummary $AllResources
	        } '2' {
		    Get-AccessibleResources $AllResources
	        } '3' {
		    Get-PublicAttackSurface $AllResources
	        } '4' {
		    Get-VirtualNetworksInfo $AllResources
	        } '5' {
		    Get-VirtualMachinesInfo $AllResources
	        } '6' {
		    Get-AppServicesInfo $AllResources
	        } '7' {
	        } '8' {
	        } '9' {
	        } '10' {
		    Get-KeyVaultsInfo $AllResources $false
	        } '11' {
		    Get-StorageAccountsInfo $AllResources $null
	        } '12' {
	        } '13' {
		    Run-SecretSearch $AllResources
	        } '14' {
		    Read-ResourceSecrets $AllResources
	        } '15' {
	        } '16' {
	        } '17' {
		} 'q' {
		    Exit
	        } default {
		    Write-Host "Invalid option"
		}
            }
	} ElseIf($CredentialType -eq "sa") {
	    Switch($Selection) {
	        '1' {
		    Get-StorageAccountsInfo $null $StorageAccountContext
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
