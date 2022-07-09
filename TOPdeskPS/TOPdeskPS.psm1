$script:ModuleRoot = $PSScriptRoot

# Declare directory separating character for X-Plat compatibility
$script:dc = [System.IO.Path]::DirectorySeparatorChar

$script:ModuleVersion = "0.1.6"

$script:__LoginToken = $null
function Import-ModuleFile {
    <#
		.SYNOPSIS
			Loads files into the module on module import.

		.DESCRIPTION
			This helper function is used during module initialization.
			It should always be dotsourced itself, in order to proper function.

			This provides a central location to react to files being imported, if later desired

		.PARAMETER Path
			The path to the file to load

		.EXAMPLE
			PS C:\> . Import-ModuleFile -File $function.FullName

			Imports the file stored in $function according to import policy
	#>
    [CmdletBinding()]
    Param (
        [string]
        $Path
    )

    if ($doDotSource) { . $Path }
    else { $ExecutionContext.InvokeCommand.InvokeScript($false, ([scriptblock]::Create([io.file]::ReadAllText($Path))), $null, $null) }
}

# Detect whether at some level dotsourcing was enforced
$script:doDotSource = Get-PSFConfigValue -FullName TOPdeskPS.Import.DoDotSource -Fallback $false
if ($TOPdeskPS_dotsourcemodule) { $script:doDotSource = $true }
if (($PSVersionTable.PSVersion.Major -lt 6) -or ($PSVersionTable.OS -like "*Windows*")) {
    if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsPowerShell\PSFramework\System" -Name "DoDotSource" -ErrorAction Ignore).DoDotSource) { $script:doDotSource = $true }
    if ((Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\WindowsPowerShell\PSFramework\System" -Name "DoDotSource" -ErrorAction Ignore).DoDotSource) { $script:doDotSource = $true }
}


<#
Note on Resolve-Path:
All paths are sent through Resolve-Path in order to convert them to the correct path separator.
This allows ignoring path separators throughout the import sequence, which could otherwise cause trouble depending on OS.
#>

# Detect whether at some level loading individual module files, rather than the compiled module was enforced
$importIndividualFiles = $true
if ($PSFramework_importIndividualFiles) { $importIndividualFiles = $true }
if (($PSVersionTable.PSVersion.Major -lt 6) -or ($PSVersionTable.OS -like "*Windows*")) {
    if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsPowerShell\PSFramework\System" -Name "ImportIndividualFiles" -ErrorAction Ignore).ImportIndividualFiles) { $script:doDotSource = $true }
    if ((Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\WindowsPowerShell\PSFramework\System" -Name "ImportIndividualFiles" -ErrorAction Ignore).ImportIndividualFiles) { $script:doDotSource = $true }
}
if (Test-Path (Join-Path (Resolve-Path -Path "$($script:ModuleRoot)\..") '.git')) { $importIndividualFiles = $true }
if ("<was compiled>" -eq '<was not compiled>') { $importIndividualFiles = $true }


function Import-ModuleFile {
    <#
		.SYNOPSIS
			Loads files into the module on module import.

		.DESCRIPTION
			This helper function is used during module initialization.
			It should always be dotsourced itself, in order to proper function.

			This provides a central location to react to files being imported, if later desired

		.PARAMETER Path
			The path to the file to load

		.EXAMPLE
			PS C:\> . Import-ModuleFile -File $function.FullName

			Imports the file stored in $function according to import policy
	#>
    [CmdletBinding()]
    Param (
        [string]
        $Path
    )

    try {
        if ($doDotSource) { . (Resolve-Path $Path) }
        else { $ExecutionContext.InvokeCommand.InvokeScript($false, ([scriptblock]::Create([io.file]::ReadAllText((Resolve-Path $Path).ProviderPath))), $null, $null) }
    }
    catch { throw (New-Object System.Exception("Failed to import $(Resolve-Path $Path) : $_", $_.Exception)) }
}

#region Load individual files
if ($importIndividualFiles) {
    # Execute Preimport actions
    . Import-ModuleFile -Path "$($script:ModuleRoot)\internal\scripts\preimport.ps1"

    # Import all internal functions
    foreach ($function in (Get-ChildItem "$($script:ModuleRoot)\internal\functions" -Filter "*.ps1" -Recurse -ErrorAction Ignore)) {
        . Import-ModuleFile -Path $function.FullName
    }

    # Import all public functions
    foreach ($function in (Get-ChildItem "$($script:ModuleRoot)\functions" -Filter "*.ps1" -Recurse -ErrorAction Ignore)) {
        . Import-ModuleFile -Path $function.FullName
    }

    # Execute Postimport actions
    . Import-ModuleFile -Path "$($script:ModuleRoot)\internal\scripts\postimport.ps1"

    # End it here, do not load compiled code below
    return
}
#endregion Load individual files

#region Load compiled code

function Convertto-Base64 {
    <#
	.SYNOPSIS
		Converts an object to base64

	.DESCRIPTION
		A detailed description of the Convertto-Base64 function.

	.PARAMETER InputObject
		A description of the InputObject parameter.

	.EXAMPLE
		PS C:\> Convertto-Base64 -InputObject 'string'
		Converts the string to Base64

#>

    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Convertto-Base64')]
    [OutputType([System.String])]
    param
    (
        $InputObject
    )


    process {
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($InputObject)
        [System.Convert]::ToBase64String($bytes)
    }
}


function Send-TdWebDAVFile {
    <#
	.SYNOPSIS
		Sends a file to your TOPdesk webdav share

	.DESCRIPTION
		adds a file to your TOPdesk/webdav/Import folder. This can be useful for you to upload files that are imported regularly in your environment.
		Common uses could be to regularly upload your users from a csv, or you could upload asset information that is imported.

	.PARAMETER File
		This is the path of the file that you want to upload to TOPdesk.

	.PARAMETER Credential
		Credential of the user with webdav permissions. This Credential is handled seperately from normal web requests as this doesn't interact with the normal API.

	.PARAMETER Folder
		Name of the TOPdesk webDAV folder that you want to upload a file into
		Valid Values:
		accesslogs
		csvexport
		database_backup
		import
		photos
		topsis
		upload
		web

	.PARAMETER Url
		This is the url to your TOPdesk instance. If you used Connect-TdService -Register then you don't need to specify one.

	.EXAMPLE
		PS C:\> Send-TdWebDAVFile -Credential (Get-Credential) -File 'C:\Users.csv' -Folder upload
		Uploads the C:\Users.csv file to TOPdesk using the credential specified in -Credential.

	.NOTES
		See Help About_TOPdesk_files for more
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/TOPdeskPS/Send-TdWebDAVFile')]
    param
    (
        [ValidateScript( {
                if (-Not ($_ | Test-Path)) {
                    throw "File or folder does not exist"
                }
                if (-Not ($_ | Test-Path -PathType Leaf)) {
                    throw "The Path argument must be a file. Folder paths are not allowed."
                }
                return $true
            })]
        [System.IO.FileInfo]
        $File,

        [Parameter(Mandatory = $true)]
        [PSCredential]
        $Credential,

        [Parameter(Mandatory = $true)]
        [ValidateSet('accesslogs', 'csvexport', 'database_backup', 'import', 'photos', 'photos/items', 'photos/locations', 'photos/objects', 'photos/operators', 'photos/others', 'photos/persons', 'photos/sites', 'topsis', 'upload', 'web')]
        [string]
        $Folder,

        [Alias('TOPdeskUrl')]
       	[PSFValidatePattern('http(s)?://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)?', ErrorMessage = '{0} is not a valid TOPdesk Url.')]
        [System.String]
        $Url = (Get-PSFConfigValue -FullName TOPdeskPS.Url -NotNull -ErrorAction Continue)
    )

    begin {
        Write-PSFMessage "Bound parameters: $($PSBoundParameters.Keys -join ", ")" -Tag 'debug', 'start', 'param' -Level InternalComment
    }

    process {
        Write-PSFMessage "Processing $File" -Level Verbose
        $FileName = Get-Item -Path $File | Select-Object -ExpandProperty Name
        $UploadUrl = "$Url/webdav/$Folder/$FileName"


        Write-PSFMessage "UploadUrl: $UploadUrl" -Level InternalComment
        try {
            Write-PSFMessage 'Uploading File...' -Level Verbose
            $Params = @{
                Uri = $UploadUrl
                Method = 'Put'
                InFile = $File
                Credential = $Credential
                ContentType = 'application/octet-stream'
            }
            Invoke-WebRequest @Params
        }
        catch {
            switch ($_.Exception.Response.StatusCode.Value__) {
                401 {
                    Write-PSFMessage "Invalid Credentials." -Level Warning -ErrorRecord $_ -OverrideExceptionMessage -EnableException $EnableException.tobool()
                }
                403 {
                    Write-PSFMessage "Unable to upload to TOPdesk. Make sure that you have write permissions on $UploadUrl directory." -Level Warning -ErrorRecord $_ -OverrideExceptionMessage -EnableException $EnableException.tobool()
                }
                409 {
                    Write-PSFMessage "Unknown directory on remote. Make sure that $UploadUrl directory exists." -Level Warning -ErrorRecord $_ -OverrideExceptionMessage -EnableException $EnableException.tobool()
                }
                500 {
                    Write-PSFMessage "Unknown server error." -Level Warning -ErrorRecord $_ -OverrideExceptionMessage -EnableException $EnableException.tobool()
                }
            }
        }
    }
}


function Add-TdAssetAssignment {
    <#
    .SYNOPSIS
    		Adds an assignment to an asset
    .DESCRIPTION
		Updates the given asset.It may be possible that one or more assets couldn’t be deleted because they have existing links from other components. In this case those assets’ ids will be listed in the ‘failed’ list of the response, but it doesn’t affect deletion of other assets.
    .PARAMETER AssetId
        ID of asset which is the subject of the assignment
    .PARAMETER LinkType
        Some of the other ID parameters must be also provided based on the current linkType. Available values: branch, location, person, personGroup, incident
        the incident linktype isn't currently documented, but it works!
    .PARAMETER LinkToId
        ID of the assigned entity. If it's a location, parent branch ID must be also provided.
    .PARAMETER BranchId
        Id of the branch you want to assign. If location is linked, this ID must be also provided as the parent branch ID of the location. Run Get-TdBranch for more
    .PARAMETER Body
        This is the body of the request. Use this to create your own bodies if the parameters aren't providing you with what you need.
	.PARAMETER Confirm
		If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
	.PARAMETER WhatIf
		If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
	.EXAMPLE
		PS C:\> Add-TdAssetAssignment -AssetId $AssetId
        Removes all assets with id's inside $assetId.
    #>

    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/TOPdeskPS/Add-TdAssetAssignment',
        SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Alias('Id')]
        [string]
        $AssetId,

        [Parameter(Mandatory)]
        [ValidateSet('branch', 'location', 'person', 'personGroup', 'incident')]
        [system.string]
        $LinkType,

        [system.string]
        $LinkToId,

        [system.string]
        $BranchId,

        [Parameter(ParameterSetName = 'Body')]
        [pscustomobject]$Body
    )

    process {
        Write-PSFMessage -Level InternalComment -Message "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-PSFMessage -Level InternalComment -Message "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        $uri = (Get-TdUrl) + "/tas/api/assetmgmt/assets/$AssetId/assignments"


        $body = [pscustomobject]@{}

        switch ($PSBoundParameters.Keys) {
            AssetId {

                # need to create an array with 1 string only. TOPdesk will change this in the future.
                $asset = @($assetId)
                $body | Add-Member -MemberType NoteProperty -Name 'assetIds' -Value $asset
            }

            LinkType {
                $body | Add-Member -MemberType NoteProperty -Name linkType -Value $LinkType
            }
            LinkToId {
                $body | Add-Member -MemberType NoteProperty -Name linkToId -Value $LinkToId
            }
            BranchId {
                $body | Add-Member -MemberType NoteProperty -Name branchId -Value $BranchId
            }
        }
        $params = @{
            'Uri' = $uri
            'Body' = $body | ConvertTo-Json
            'Method' = 'Put'
        }
        if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action "Sending Body $($body | convertto-json) ")) {
            return
        }
        Invoke-TdMethod @params
    }
}


function Get-TdAsset {
    <#
	.SYNOPSIS
		Returns TOPdesk assets
	.DESCRIPTION
        This API returns a list of assets. By default the following fields are included: id, name (text), etag and state (archived).
         You can use various parameters to filter this list or to retrieve other fields from the assets. In Asset Management, paging is missing deliberately.
         To return all assets for a given template please use the TemplateId parameter. You can also specify the fields that you would like returned when performing a template query.
    .PARAMETER NameFragment
        To filter assets by their name-fragment use this parameter. It’s case-insensitive.
    .PARAMETER Archived
        Whether to show archived assets. if performing a standard query it will return all, if performing a Tempalte query it will only return active assets.
    .PARAMETER TemplateName
        To filter assets by a specific template’s name (case sensitive).
    .PARAMETER ShowAssignments
        When it’s given it returns more meta information, including all person and location related assignments. See ‘/assignments’ endpoint documentation for more details about the response format.
    .PARAMETER TemplateId
        Id of the template specifying the type of assets to return. see Get-Tdtemplate to retrieve the id.
    .PARAMETER Field
        Which asset fields to include in the response. If not specified, only the id and name will be included. Fields should be referenced by their field id, not their display name. See Get-tdAssetField

	.EXAMPLE
		PS C:\> Get-TdAsset
		Get all topdesk assets
#>

    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdAsset', DefaultParameterSetName = 'List')]

    param
    (

        [Parameter(ParameterSetName = 'Standard Query')]
        [system.string]$NameFragment,

        [switch]$Archived,

        [Parameter(ParameterSetName = 'Standard Query')]
        [switch]$ShowAssignments,

        [Parameter(ParameterSetName = 'Standard Query')]
        [system.string]$TemplateName,

        # This is a different query so we need a seperate parameter set.
        [Parameter(Mandatory, ParameterSetName = 'Template Query')]
        $TemplateId,

        [system.string[]]
        $Field = 'name'
    )

    begin {
        Write-PSFMessage -Level InternalComment -Message "Bound parameters: $($PSBoundParameters.Keys -join ", ")" -Tag 'debug', 'start', 'param'
    }
    process {
        switch ($PsCmdlet.ParameterSetName) {
            'Standard Query' {
                $Uri = (Get-TdUrl) + '/tas/api/assetmgmt/assets/?'
                switch ($PSBoundParameters.keys) {
                    NameFragment {
                        $uri = "$uri&nameFragment=$NameFragment"
                    }
                    Archived {
                        $uri = "$uri&archived=$Archived"
                    }
                    ShowAssignments {
                        $uri = "$uri&showAssignments=$ShowAssignments"
                    }
                    TemplateName {
                        $uri = "$uri&templateName=$TemplateName"
                    }
                }
                Invoke-TdMethod -Uri $uri | Select-Object -ExpandProperty dataset  | Select-PSFObject -Typename 'TOPdeskPS.Asset' -KeepInputObject
            }

            'Template Query' {
                switch ($PSBoundParameters.Keys) {
                    TemplateId {
                        $uri = (get-tdurl) + "/tas/api/assetmgmt/assets/templateId/$TemplateId/?"
                    }
                    Archived {
                        $uri = $uri + "&includeArchived=$Archived/"
                    }
                }
                foreach ($f in $field) {
                    $uri = $uri + "&field=$F"
                }
                Invoke-TdMethod -Uri $uri | Select-Object -ExpandProperty results | Select-PSFObject -Typename 'TOPdeskPS.Asset' -KeepInputObject
            }

            List {
                $Uri = (Get-TdUrl) + '/tas/api/assetmgmt/import/assets/?'

                foreach ($f in $field) {
                    $uri = $uri + "&field=$F"
                }
                Invoke-TdMethod -Uri $uri  | Select-Object -ExpandProperty results
            }
        }
    }
    end {
    }
}


function Get-TdAssetAssignment {
    <#
    .SYNOPSIS
        Gets assignments for an asset
    .DESCRIPTION
        This API returns a list of assigned location, branches, persons and person groups of a specific asset.
    .PARAMETER AssetId
        Id of the asset to return asset links for.
    .EXAMPLE
        PS C:\> Get-TdAssetAssignment -AssetId $AssetId
        Returns assignments for $AssetId
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdAssetAssignment')]
    param (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Alias('id')]
        [system.string]
        $AssetId
    )
    process {
        Write-PSFMessage -Level InternalComment -Message "Bound parameters: $($PSBoundParameters.Keys -join ", ")" -Tag 'debug', 'start', 'param'
        $uri = (Get-TdUrl) + "/tas/api/assetmgmt/assets/$AssetId/assignments"
        $res = Invoke-TdMethod -Uri $uri
        $res | Add-Member -MemberType NoteProperty -Name AssetId -Value $AssetId
        $res
    }
}


function Get-TdAssetCapability {
    <#
    .SYNOPSIS
        Returns list of capabilities.
    .DESCRIPTION
        Assets can be linked together with capabilities. This command returns all of them.
    .EXAMPLE
        PS C:\> Get-TdAssetCapability
        Returns capabilities
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdAssetCapability')]
    param ()
    $uri = (Get-TdUrl) + "/tas/api/assetmgmt/capabilities"
    Invoke-TdMethod -Uri $uri | Select-Object -ExpandProperty dataset
}


function Get-TdAssetCapabilityDetail {
    <#
    .SYNOPSIS
        Returns details about asset capabilities
    .DESCRIPTION
        Assets can be linked together with capabilities. This command returns all of them.
    .PARAMETER CapabilityId
        Id of the capability. Use Get-TdAssetCapability
    .EXAMPLE
        PS C:\> Get-TdAssetCapability | Get-TdAssetCapabilityDetail
        Returns additional detail about asset capabilities
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdAssetCapabilityDetail')]
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('id')]
        [system.string]
        $CapabilityId
    )
    process {
        $uri = (Get-TdUrl) + "/tas/api/assetmgmt/capabilities/$CapabilityId"
        Invoke-TdMethod -Uri $uri
    }
}


function Get-TdAssetDetail {
    <#
    .SYNOPSIS
        Returns additional information about assets
    .DESCRIPTION
        Get more information about Assets retrieved with Get-TdAsset
    .PARAMETER AssetId
        Id of the asset that you want more details about
    .EXAMPLE
        PS C:\> Get-TdAsset | Get-TdAssetDetail
        Returns details for assets returned with Get-TdAsset
    .NOTES
        See https://developers.topdesk.com/explorer/?page=assets#/Assets/getAssets for more information.
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdAssetDetail')]
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('id')]
        [system.string]
        $AssetId
    )
    process {
        $uri = (Get-TdUrl) + "/tas/api/assetmgmt/assets/$AssetId"
        Invoke-TdMethod -Uri $uri
    }
}


function Get-TdAssetField {
    <#
    .SYNOPSIS
        Lists asset fields
    .DESCRIPTION
        Returns all asset fields contained inside TOPdesk.
    .EXAMPLE
        PS C:\> Get-TdAssetField
        Returns all asset fields
        #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdAssetField')]
    param(
    )
    $uri = (Get-TdUrl) + "/tas/api/assetmgmt/fields"
    Invoke-TdMethod -Uri $uri | Select-Object -ExpandProperty DataSet
}


function Get-TdAssetFieldValue {
    <#
    .SYNOPSIS
        Returns Asset field values
    .DESCRIPTION
        Lists asset fields
    .PARAMETER FieldId
        Id of the field that you want the value for. See Get-TdAssetField
    .EXAMPLE
        PS C:\> Get-TdAssetField | Get-TdAssetFieldValue
        Returns asset fieldvalues for all Asset fields.
        #>
    [cmdletbinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdAssetFieldValue')]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('id')]
        [system.string]$FieldId
    )

    process {
        $uri = (Get-TdUrl) + "/tas/api/assetmgmt/fields/$FieldId"
        Invoke-TdMethod -Uri $uri
    }
}


function Get-TdAssetFile {
    <#
    .SYNOPSIS
        Lists files from an asset
    .DESCRIPTION
        Lists files from an asset
     .PARAMETER AssetId
        Id of the asset that you want files for
    .EXAMPLE
        PS C:\> Get-TdAssetFile -AssetId $AssetId
        Returns files from asset $AssetId
        #>
    [cmdletbinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdAssetFile')]
    param(
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Alias('Id')]
        [system.string]
        $AssetId
    )
    $uri = (Get-TdUrl) + "/tas/api/assetmgmt/uploads/?assetId=$AssetId"
    Invoke-TdMethod -Uri $uri | Select-Object -ExpandProperty DataSet
}


function Get-TdAssetLink {
    <#
	.SYNOPSIS
		Returns linked assets
	.DESCRIPTION
        This API returns a list of assets that are linked to a specificed asset provided as a parameter (sourceId).
        The list will include the following information about the linked assets: the name, id, type and properties of the icon of the asset; the type and id of the link; id and name of the used capability.
    .PARAMETER AssetId
        Id of the asset to return asset links for.
    .EXAMPLE
        PS C:\> Get-TdAssetLink -AssetId $assetId
        Returns all linked assets for the $assetId.
#>

    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdAssetlink')]
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Alias('Id', 'SourceId')]
        [system.string]
        $AssetId
    )

    process {
        $uri = (Get-TdUrl) + "/tas/api/assetmgmt/assetLinks/?&sourceId=$AssetId"
        Invoke-TdMethod -Uri $uri
    }
}


function Get-TdAssetLinkPossibleRelation {
    <#
	.SYNOPSIS
		Returns possible relations between source and target asset.
	.DESCRIPTION
   This API returns the available relationship types (child, parent and available capability ids) for two assets (sourceId, targetId).
    If the specified two assets are already linked in every possible way, then the result will be empty.
    This endpoint is the most beneficial if you use it before creating a new link between two assets.
      .PARAMETER AssetId
        The ID of the source Asset
    .PARAMETER TargetAssetId
        The ID of the target Asset
    .EXAMPLE
        PS C:\> Get-TdAssetLinkPossibleRelations -AssetId $assetId -TargetAssetId $targetId
        Returns all possible relationships between the two assets.
#>

    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdAssetlinkPossibleRelation')]
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Alias('Id', 'sourceId')]
        [system.string]
        $AssetId,

        [Parameter(Mandatory = $true)]
        [Alias('targetId')]
        [system.string]
        $TargetAssetId
    )

    process {
        $uri = (Get-TdUrl) + "/tas/api/assetmgmt/assetLinks/possibleRelations/?sourceId=$AssetId&targetId=$TargetAssetId"
        Invoke-TdMethod -Uri $uri
    }
}


function Get-TdAssetTemplate {
    <#
    .SYNOPSIS
        Gets Asset Templates
    .DESCRIPTION
        This API returns the list of available templates/asset types with their IDs.
        You will need the ID when creating a new asset for that type or when filtering the list of assets on asset type.
    .PARAMETER Archived
        Whether to retrieve archived asset templates.  Leave out for all, or specify true/false for only archived, or only active templates, respectively.
    .PARAMETER Name
        Name of the AssetTemplate that you want returned. Wildcards are supported. Default value is '*'
    .EXAMPLE
        PS C:\> Get-TdAssetTemplate -Name 'Work*'
        Returns all templates with a name matching 'work*'. In this instance it would return a 'Workstation' template.
    #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdAssetTemplate')]
    param (
        [Parameter(Position = 0)]
        [System.String]
        $Name = '*',

        [switch]
        $Archived
    )
    Write-PSFMessage -Level InternalComment -Message "Bound parameters: $($PSBoundParameters.Keys -join ", ")" -Tag 'debug', 'start', 'param'
    $uri = (Get-TdUrl) + '/tas/api/assetmgmt/templates'
    Write-PSFMessage -Level InternalComment -Message "AssetTemplate url: $uri"

    if ($Archived) {
        Write-PSFMessage -Level InternalComment -Message "Archive = $Archive"
        $uri = "$uri/?archived=$Archived"
    }

    $Params = @{
        'uri' = $uri
    }
    $res = Invoke-TdMethod @Params | Select-Object -ExpandProperty dataset
    $res | Where-Object text -like $Name
}


function Get-TdAssetTemplateBlank {
    <#
	.SYNOPSIS
		Returns blank asset cards
	.DESCRIPTION
    This API returns a blank asset card based on a specific template. You can add the id or name of the specific template as a parameter to the endpoint (templateid / templateName). The result will show all the fields on the card, and their properties.
    You can use this endpoint to see the mandatory fields of the asset, and with that, create new assets of that type.    .PARAMETER NameFragment
    To filter assets by their name-fragment use this parameter. It’s case-insensitive.
    .PARAMETER TemplateName
        Name of the templateid
	.EXAMPLE
        PS C:\> Get-TdAssetTemplateBlank -TemplateName 'Network Device'
		Returns all fields on the card for the template specified.
#>

    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdAssetTemplateBlank')]
    param
    (
        [Parameter(Mandatory = $true)]
        [system.string]$TemplateName
    )

    process {
        $uri = "$(get-tdurl)/tas/api/assetmgmt/assets/blank/?templateName=$TemplateName"
        Invoke-TdMethod $uri
    }

}


function New-TdAsset {
    <#
    .SYNOPSIS
        Create a new asset
    .DESCRIPTION
        This API creates a new asset. To create a new asset, you will need the type of the asset you want to create (type_id), and to fill in the values of the mandatory fields of that specific asset type/template. You can get the ID of the available types of assets/templates using the /assetmgmt/templates endpoint. use Get-TdAssetTemplateBlank
    .PARAMETER TemplateId
        The ID of the template.
    .PARAMETER Name
        The Name, or assetId of the asset that you want to create. Example: TestComputer
    .PARAMETER Body
        This object contains key-value pairs, where the key is the field’s id, and the value is the value of this field.
        This model must contain every mandatory field with a value. Note: do not add a name or type_id key as they are handled seperately in the parameters name and TemplateId, respectively.

        Example:
        $body = @{
            serialnumber = '123'
            type_id = 'Id Of the template that you want to use'
            name = 'Server01'
        }

        	.PARAMETER Confirm
		If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

	.PARAMETER WhatIf
		If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

    .EXAMPLE
        PS C:\> New-TdAsset -TemplateId $templateId -Name 'TestComputer' -body @{Type = 'Computer'}
        Creates a new asset named TestComputer. It also sets the asset type to 'Computer'

    #>
    [CmdletBinding( SupportsShouldProcess = $true,
        HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/New-TdAsset')]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [system.string]$TemplateId,

        [pscustomobject]$Body,

        #TODO determine if I should make this mandatory. I believe it can be, but I need to spend more time in Assetmgmt to decide further
        [System.string]$Name
    )

    begin {
        $uri = (get-tdurl) + '/tas/api/assetmgmt/assets'
    }

    process {

        # create a body if one wasn't provided.
        if (-not $body) {
            $body = [PSCustomObject]@{}
        }

        # Go through parameters and add them to our body
        switch ($PSBoundParameters.Keys) {
            TemplateId {
                $body | Add-Member -MemberType NoteProperty -Name 'type_id' -Value $TemplateId
            }
            Name {
                $body | Add-Member -MemberType NoteProperty -Name 'name' -Value $Name
            }
        }


        $params = @{
            'Uri'    = $uri
            'Body'   = $Body | ConvertTo-Json
            'Method' = 'Post'
        }
        if ($PSCmdlet.ShouldProcess("Send body --- $($body | convertto-json)" , "to $uri")) {
            Invoke-TdMethod @params
        }
    }
}





function New-TdAssetCapability {
    <#
    .SYNOPSIS
        Create a new Asset Capability
    .DESCRIPTION
        Create a new Asset Capability
    .PARAMETER Name
        Name of the capability that you would like to create.
    .PARAMETER Confirm
		If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
	.PARAMETER WhatIf
		If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
    .EXAMPLE
        PS C:\> New-TdAssetCapability -Name 'testCapability'
        Creates a new capability named 'testCapability'
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/New-TdAssetCapability',
        SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('id')]
        [system.string]
        $Name
    )
    process {
        $uri = (Get-TdUrl) + "/tas/api/assetmgmt/capabilities"
        $body = [PSCustomObject]@{
            name = $name
        }
        if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action 'Creating asset capability.')) {
            return
        }
        Invoke-TdMethod -Uri $uri -Body ($body | ConvertTo-Json) -Method POST
    }
}


function Remove-TdAsset {
    <#
	.SYNOPSIS
		Deletes the given asset

	.DESCRIPTION
		Deletes the given assets.It may be possible that one or more assets couldn’t be deleted because they have existing links from other components. In this case those assets’ ids will be listed in the ‘failed’ list of the response, but it doesn’t affect deletion of other assets.
 .PARAMETER AssetId
        Id of the asset to remove
	.PARAMETER Confirm
		If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

	.PARAMETER WhatIf
		If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

	.EXAMPLE
		PS C:\> Remove-TdAsset -AssetId $AssetId
		Removes all assets with id's inside $assetId.
#>

    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/TOPdeskPS/Remove-TdAsset',
        SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Alias('Id')]
        [string[]]
        $AssetId
    )
    process {
        Write-PSFMessage -Level InternalComment -Message "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-PSFMessage -Level InternalComment -Message "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        $uri = (Get-TdUrl) + "/tas/api/assetmgmt/assets/delete"

        if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $AssetId.ToString() -Action 'Removing asset.')) {
            return
        }
        $body = [PSCustomObject]@{
            unids = $AssetId
        }
        $params = @{
            'Uri' = $uri
            'Body' = $body | ConvertTo-Json
            'Method' = 'Post'
        }
        Write-PSFMessage -Message "Body - $body" -Level InternalComment
        Invoke-TdMethod @params
    }

}


function Remove-TdAssetAssignment {
    <#
	.SYNOPSIS
		Remove an assignment from an asset.
	.DESCRIPTION
        This API removes an assigned branch, location, person or person group from an asset.
        To unassign something, you need to provide the linkId, which you can retrieve with Get-TdAssetAssignment.
    .PARAMETER LinkId
        The Id of the relation. You can get this by using Get-TdAssetLink
    .PARAMETER AssetId
        Id of the asset to update
	.PARAMETER Confirm
		If this switch is enabled, you will be prompted for confirmation before executing any operations that change state
	.PARAMETER WhatIf
		If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
    .EXAMPLE
        PS C:\> Remove-TdAssetAssignment -AssetId $assetId -LinkId $linkId
            Removes the asset assignemt link $linkId for $assetId

#>

    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/TOPdeskPS/Remove-TdAssetAssignment',
        SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        # locations alias to accept the parent property of the linkid
        [Alias('locations')]
        $LinkId,

        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [system.string]
        $AssetId
    )
    process {
        Write-PSFMessage -Level InternalComment -Message "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-PSFMessage -Level InternalComment -Message "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"
        $uri = (Get-TdUrl) + "/tas/api/assetmgmt/assets/$AssetId/assignments/$($LinkId.linkId)"
        if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $AssetId -Action "Removing asset assignment $($LinkId.linkId).")) {
            return
        }
        Invoke-TdMethod -Method 'Delete' -Uri $uri
    }
}


function Remove-TdAssetFile {
    <#
    .SYNOPSIS
        Removes file from an asset
    .DESCRIPTION
        Removes file from an asset
    .PARAMETER UploadId
        Id of the blob that you want to remove. Use Get-TdAssetFile toreceive the id
   	.PARAMETER Confirm
		If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

	.PARAMETER WhatIf
		If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

    .EXAMPLE
        PS C:\> Get-TdAssetFile -AssetId $AssetId | Remove-TdAssetFile
        Gets all asset files from $AssetId and then removes them.
        #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/TOPdeskPS/Remove-TdAssetFile',
        SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Alias('Id')]
        [system.string]
        $UploadId
    )
    process {
        $uri = (Get-TdUrl) + "/tas/api/assetmgmt/uploads/$UploadId"
        if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $UploadId -Action 'Removing asset file.')) {
            return
        }
        Invoke-TdMethod -Uri $uri -Method Delete
    }
}


function Remove-TdAssetLink {
    <#
	.SYNOPSIS
		Remove link between 2 assets.
	.DESCRIPTION
		Remove link between 2 assets.
    .PARAMETER LinkId
        The Id of the relation. You can get this by using Get-TdAssetLink
	.PARAMETER Confirm
		If this switch is enabled, you will be prompted for confirmation before executing any operations that change state
	.PARAMETER WhatIf
		If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
    .EXAMPLE
        PS C:\> Get-TdAssetLink -AssetId $assetId | Remove-TdAssetLink
            Removes the asset links for $assetId

#>

    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/TOPdeskPS/Remove-TdAssetLink',
        SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Alias('relationId')]
        [system.string]
        $LinkId
    )
    process {
        Write-PSFMessage -Level InternalComment -Message "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-PSFMessage -Level InternalComment -Message "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        $uri = (Get-TdUrl) + "/tas/api/assetmgmt/assetLinks/$LinkId"
        if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $LinkId -Action 'Removing asset Link.')) {
            return
        }
        Invoke-TdMethod -Method 'Delete' -Uri $uri
    }
}


function Send-TdAssetFile {
    <#
    .SYNOPSIS
        Upload a file to an asset
    .DESCRIPTION
        Upload a file to an asset
    .PARAMETER Number
        The number of the incident that you want to upload a file to.
    .PARAMETER File
        Path and name to the file that you want to upload to the incident.
    .PARAMETER AssetID
        Id of the asset that you want to send a file to. See Get-TdAsset

    .PARAMETER ContentType
        You can manually specify the type of content that it is. This should only be used if you experience issues. This contenttype is passed to Invoke-RestMethod
    .EXAMPLE
        PS C:\> Get-TdAsset -NameFragment 'test-computer' | Send-TdAssetFile -File "C:\log.txt"
        Sends a File to the asset named test-computer.
    #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Send-TdAssetFile')]
    param (

        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Alias('Id')]
        [system.string]
        $AssetId,

        [Alias('InFile')]
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path)) {
                    throw "File or folder does not exist"
                }
                if (-Not ($_ | Test-Path -PathType Leaf)) {
                    throw "The Path argument must be a file. Folder paths are not allowed."
                }
                if (-Not (Get-Item $_)) {
                    throw "Cannot find path $($_)"
                }
                return $true
            })]
        [System.IO.FileInfo]
        $File,

        [string]
        $ContentType
    )
    begin {
    }
    process {
        Write-PSFMessage -Level InternalComment -Message "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-PSFMessage -Level InternalComment -Message "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        $uri = (Get-TdUrl) + "/tas/api/assetmgmt/uploads/?assetId=$AssetId"
        $File = Get-Item $file

        $params = @{
            Uri = $Uri
            Method = 'Post'
            File = $File
        }

        if ($ContentType) {
            $params.ContentType = $ContentType
        }
        Invoke-TdMethod @params
    }

}


function Send-TdAssetImportFile {
    <#
    .SYNOPSIS
        Sends a file to containing assets to be uploaded to asset management.
    .DESCRIPTION
        In order to upload assets using this endpoint you need to first configure an import inside TOPdesk.

        As an operator, go to Settings -> Import Settings -> Asset MGMT Imports -> New Import

        Configure the import using the csv containing your asset information. Set the Scheduling of the import to be Automated

        When you upload a csv with the same name as specified in your import, TOPdesk will automatically trigger an import of the csv when you upload it using this command.

    .PARAMETER File
        The csv containing your assets
    .PARAMETER Confirm
        If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
    .PARAMETER WhatIf
        If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
    .EXAMPLE
        PS C:\> Send-TdAssetImportFile -File 'C:\AssetsToImport.csv'
        Sends C:\AssetstoImport.csv to TOPdesk asset import. This will cause an import to occur

    #>
    [cmdletbinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Send-TdAssetImportFile',
        SupportsShouldProcess = $true)]
    param(
        [Alias('InFile')]
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path)) {
                    throw "File or folder does not exist"
                }
                if (-Not ($_ | Test-Path -PathType Leaf)) {
                    throw "The Path argument must be a file. Folder paths are not allowed."
                }
                if (-Not (Get-Item $_)) {
                    throw "Cannot find path $($_)"
                }
                return $true
            })]
        [System.IO.FileInfo]
        $File
    )

    begin {
        if (-not $Script:__LoginToken) {
            throw 'no connection to topdesk, try running Connect-TdService'
        }
        else {
            $Headers = @{
                'Authorization' = $Script:__LoginToken
                'Content-Type' = 'application/octet-stream'
            }
        }
    }
    process {
        Write-PSFMessage -Level InternalComment -Message "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-PSFMessage -Level InternalComment -Message "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        $file = Get-Item $file
        $uri = "$(Get-TdUrl)/services/import-to-api-v1/api/sourceFiles?filename=$($File.name)"


        $params = @{
            Infile = $file
            uri = $uri
            Method = 'PUT'
            Headers = $Headers
            #            ContentType = 'application/octet-stream'
        }

        # Going to use Invoke-RestMethod as this is one of the only endpoints that doesn't require us to build a file.
        if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action "Sending to Invoke-RestMethod -- $($params | out-string)")) {
            return
        }
        Invoke-RestMethod @params
    }
}


function Set-TdAsset {
    <#
	.SYNOPSIS
		Updates an asset
	.DESCRIPTION
		Updates the given asset.It may be possible that one or more assets couldn’t be deleted because they have existing links from other components. In this case those assets’ ids will be listed in the ‘failed’ list of the response, but it doesn’t affect deletion of other assets.
    .PARAMETER AssetId
        Id of the asset to update
    .PARAMETER Body
        This object contains key-value pairs, where the key is the modified field’s id, and the value is the new value.
        If a mandatory field is not given in this model, then it’s value remains the same.
        Example:
        {
          "numberField": "string",
         "textField": "string",
        "dropdownField": "string",
          "@status": "OPERATIONAL",
        "@statusLocked": true,
        "@etag": "string"
        }
        Further explanation.
        numberField	string
        An example value could be: 15.440

        textField	string
        An example value could be: Sample text

        dropdownField	string
        An example dropdown value is an id: AF404E17-F1E3-4AB7-BB77-F9FC5189CF6E

        @status	string
        Status shows if this asset is operational right now or not. Main field to set for triggering Impact Analysis features
        Enum:
        [ OPERATIONAL, IMPACTED ]

        @statusLocked	boolean
        Enterprise users can enable automatic propagation by setting @statusLocked to false, or stop automatic propagation and enable manual status switching by setting @statusLocked to true.

        @etag	string
        ETag for the given entity. It is used for concurrent modification checking with optimistic locking.
	.PARAMETER Confirm
		If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
	.PARAMETER WhatIf
		If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
	.EXAMPLE
		PS C:\> Set-TdAsset -AssetId $AssetId
        Removes all assets with id's inside $assetId.
#>

    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/TOPdeskPS/Set-TdAsset',
        SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Alias('Id')]
        [system.string]
        $AssetId,

        [Parameter(Mandatory)]
        [pscustomobject]$Body

        #TODO add parameters for status, statuslocked, and etag as shortcuts to quickly spin up a body for the request.
    )

    process {
        Write-PSFMessage -Level InternalComment -Message "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        $uri = (Get-TdUrl) + "/tas/api/assetmgmt/assets/$AssetId"

        Write-PSFMessage "$($Body | ConvertTo-Json | Out-String)" -Level debug
        $params = @{
            'Uri' = $uri
            'Body' = $Body | ConvertTo-Json
            'Method' = 'Post'
        }
        if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action 'Updating asset.')) {
            return
        }
        Invoke-TdMethod @params
    }

}


function Set-TdAssetCapability {
    <#
    .SYNOPSIS
        Returns list of capabilities.
    .DESCRIPTION
        Assets can be linked together with capabilities. This command returns all of them.
    .PARAMETER CapabilityId
        The Id of the capability that you want to update.
    .PARAMETER Name
        The new name that you want to give the asset.
    .PARAMETER Confirm
		If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
	.PARAMETER WhatIf
		If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
    .EXAMPLE
        PS C:\> Get-TdAssetCapability | where name -like 'test' | Set-TdAssetCapability -name 'newtest'
        Updates the name of capability 'test' to 'newtest'
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Set-TdAssetCapability',
        SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('id')]
        [System.String]
        $CapabilityId,

        [Parameter(Mandatory)]
        [System.String]
        $Name
    )
    process {
        $uri = (Get-TdUrl) + "/tas/api/assetmgmt/capabilities/$CapabilityId"
        [pscustomobject]$body = @{
            name = $Name
        }
        $params = @{
            uri = $uri
            body = $body | ConvertTo-Json
            method = 'POST'
        }
        if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action 'setting asset capability.')) {
            return
        }
        Invoke-TdMethod @params
    }
}


function Set-TdAssetLink {
    <#
	.SYNOPSIS
		Links asset to target asset
	.DESCRIPTION
        This API creates a link between two assets. These links are often referred to as 'relationships’.
        When creating a link, you need to specify the two assets you want to link (AssetId, TargetAssetId), and the desired relationship between them.
        To get the available types of relationship between the two assets, use Get-TdAssetLinkPossibleRelation
    .PARAMETER AssetId
        The id of the asset to be the source of the link. For a child relation, this will be the parent, for a parent relation, this will be the child. For capabilities, this asset will provide the capability.
    .PARAMETER TargetAssetId
        The id of the asset to be the target of the link. For a child relation, this will be the child, for a parent relation, this will be the parent. For capabilities, this asset will use the capability.
    .PARAMETER Type
        Defines the direction of the relation. ‘child’ means the ‘target’ is the child of the 'source’. ‘child’ is the default value. Ignored if a CapabilityId is present.
    .PARAMETER CapabilityId
        The id of the capability that is offered through the link. Don’t specify it for parent-child relation
	.PARAMETER Confirm
		If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
	.PARAMETER WhatIf
		If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
	.EXAMPLE
        PS C:\> Set-TdAssetLink -AssetId $AssetId -TargetAssetId $TargetId
        Links $assetId to $targetId using
#>

    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/TOPdeskPS/Set-TdAssetLink',
        SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true)]
        [Alias('id', 'SourceId')]
        [string]
        $AssetId,

        [Parameter(Mandatory = $true)]
        [Alias('targetId')]
        [string]
        $TargetAssetId,

        [ValidateSet('parent', 'child')]
        [string]
        $Type = 'child',

        [string]
        $CapabilityId
    )

    begin {}
    process {
        Write-PSFMessage -Level InternalComment -Message "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-PSFMessage -Level InternalComment -Message "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"
        $uri = (Get-TdUrl) + "/tas/api/assetmgmt/assetLinks"

        $body = [PSCustomObject]@{}
        switch ($PSBoundParameters.Keys) {
            AssetId {
                $body | Add-Member -MemberType NoteProperty -Name 'sourceId' -Value $AssetId
            }
            TargetAssetId {
                $body | Add-Member -MemberType NoteProperty -Name 'targetId' -Value $TargetAssetId
            }
            type {
                $body | Add-Member -MemberType NoteProperty -Name 'type' -Value $Type
            }
            CapabilityId {
                $body | Add-Member -MemberType NoteProperty -Name 'capabilityId' -Value $CapabilityId
            }
        }
        Write-PSFMessage "$($Body | ConvertTo-Json | Out-String)" -Level debug

        $params = @{
            'Uri' = $uri
            'Body' = $Body | ConvertTo-Json
            'Method' = 'Post'
        }
        if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $AssetId -Action "Sending Body $($body | convertto-json)")) {
            return
        }
        Invoke-TdMethod @params
    }
}


function Get-TdChange {
    <#
.SYNOPSIS
    Returns changes

.DESCRIPTION
    Returns changes.

.PARAMETER Id
    The internal ID(s) of the change(s) to return.

.PARAMETER ClosedDate
    If specified, only changes that were closed on or after the given date are returned.

.PARAMETER OperatorGroupId
    If specified, only changes assigned to the given operator group(s) will be returned.

.PARAMETER OperatorId
    If specified, only changes assigned to the given operator(s) will be returned.

.PARAMETER ChangeType
    If specified, only changes of the supplied type(s) will be returned.

.PARAMETER Phase
    If specified, only changes in the supplied phase(s) will be returned.

.PARAMETER Status
    If specified, only changes in the supplied status(es) will be returned.

.PARAMETER Open
    If specified, only changes that are open will be returned. Specify -Open:$false to return only closed changes.

.PARAMETER Archived
    If specified, only changes that are archived will be returned. Specify -Archived:$false to return only active changes.

.EXAMPLE
    PS C:\> Get-TdChange
    Returns all changes
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdChange')]

    param
    (
        [Parameter(Position = 0)]
        [string[]]
        $Id,

        [datetime]
        $ClosedDate,

        [string[]]
        $OperatorGroupId,

        [string[]]
        $OperatorId,

        [string[]]
        [ValidateSet('simple', 'extensive')]
        $ChangeType,

        [string[]]
        [ValidateSet('prfc', 'rfc', 'simple', 'progress', 'evaluation', 'closed', 'rejected', 'canceled')]
        $Phase,

        [string[]]
        $Status,

        [switch]
        $Open,

        [switch]
        $Archived
    )

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level InternalComment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level InternalComment

        $methodParams = @{
            Uri = "$(Get-TdUrl)/tas/api/operatorChanges?"
        }

        if ($PSBoundParameters.Keys -contains 'ClosedDate') {
            $methodParams['Uri'] = "$($methodParams.uri)&closedDate.start=$(get-date $ClosedDate -UFormat '+%Y-%m-%dT%H:%M:%SZ')"
        }

        if ($PSBoundParameters.Keys -contains 'OperatorGroupId') {
            foreach ($g in $OperatorGroupId) {
                $methodParams['Uri'] = "$($methodParams.uri)&simple.assignee.groupid=$g"
            }
        }

        if ($PSBoundParameters.Keys -contains 'OperatorId') {
            foreach ($g in $OperatorId) {
                $methodParams['Uri'] = "$($methodParams.uri)&simple.assignee.id=$g"
            }
        }

        if ($PSBoundParameters.Keys -contains 'ChangeType') {
            foreach ($g in $ChangeType) {
                $methodParams['Uri'] = "$($methodParams.uri)&changeType=$g"
            }
        }

        if ($PSBoundParameters.Keys -contains 'Phase') {
            foreach ($g in $Phase) {
                $methodParams['Uri'] = "$($methodParams.uri)&phase=$g"
            }
        }

        if ($PSBoundParameters.Keys -contains 'Status') {
            foreach ($g in $Status) {
                $methodParams['Uri'] = "$($methodParams.uri)&status=$g"
            }
        }

        if ($PSBoundParameters.Keys -contains 'Id') {
            foreach ($g in $Id) {
                $methodParams['Uri'] = "$($methodParams.uri)&id=$g"
            }
        }

        if ($PSBoundParameters.Keys -contains 'Open') {
            $methodParams['Uri'] = "$($methodParams.uri)&open=$($Open.ToString().ToLower())"
        }

        if ($PSBoundParameters.Keys -contains 'Archived') {
            $methodParams['Uri'] = "$($methodParams.uri)&archived=$($Archived.ToString().ToLower())"
        }

        (Invoke-TdMethod @methodParams).results
    }
}


function Get-TdChangeActivity {
    <#
	.SYNOPSIS
		Gets change activities
	.DESCRIPTION
        This command returns change activitites. This returns changes available to the account used with Connect-TdService.
    .PARAMETER Change
        Id or number of the parent change
        This is a repeatable filter parameter
    .PARAMETER Archived
		Whether to only retrieve archived changes or not.
	.EXAMPLE
		PS C:\> Get-TdChangeActivity -Change 'C1801-123'
		Grabs change activitites for C1801-123
#>

    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdChangeActivity')]
    param
    (
        [Parameter(ParameterSetName = 'query')]
        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('id')]
        [system.string[]]$Change,

        [Parameter(ParameterSetName = 'query')]
        [switch]
        $Archived
    )

    process {
        Write-PSFMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level Debug
        Write-PSFMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -Level Debug

        if ($PSCmdlet.ParameterSetName -match 'Query') {
            $methodParams = @{
                uri = ("$(Get-TdUrl)/tas/api/operatorChangeActivities?")
            }
            foreach ($chan in $change) {
                $methodParams['uri'] = "$($methodParams.uri)&change=$chan"
            }
            if ($PSBoundParameters.keys -contains 'Archive') {
                $methodParams['uri'] = "$($methodParams.uri)&archive=$($Archive.tostring().tolower())"
            }
        }
        else {
            $methodParams = @{
                uri = ("$(Get-TdUrl)/tas/api/operatorChangeActivities")
            }
        }
        $res = Invoke-TdMethod @methodParams
        $res.results
    }

}


function Get-TdChangeCalendar {
    <#
.SYNOPSIS
    returns list of changes and activities in specified date range
.DESCRIPTION
    returns list of changes and activities in specified date range. For activities to appear in this endpoint the option “Display in Calendar” under “Planning” on the activity card has to be set. Start and end date are mandatory.
.PARAMETER Start
    start of range to return changes. Default value = 90 days
.PARAMETER End
    end of range to return changes. Default value = 90 days
.PARAMETER CardType
    Type of card to filter results by. Accepted options 'change_simple', 'change_extensive', 'undefined', 'activity_authorization', 'activity_normal'
.PARAMETER Branch
    Branch to filter results by
.PARAMETER Category
    Category of cards to obtain
.PARAMETER Status
    Status of cards to obtain
.PARAMETER Type
    Type of cards to obtain
.PARAMETER CurrentState
    CurrentState that cards to be obtained are in
.EXAMPLE
    PS C:\> Get-TdChangeCalendar
    Returns results with default date values (90 days back and 90 days forward)
.EXAMPLE
    PS C:\> Get-TdChangeCalendar -Branch 'Side Branch'
    Returns all results for 'Side Branch' branch
.EXAMPLE
    PS C:\> Get-TdChangeCalendar -CurrentState 'done'
    Returns all 'done' change cards
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdChangeCalendar')]

    param
    (

        [datetime]
        $Start = ((get-date).AddDays(-90)),

        [datetime]
        $End = ((get-date).AddDays('90')),

        [ValidateSet('change_simple', 'change_extensive', 'undefined', 'activity_authorization', 'activity_normal')]
        [string[]]
        $CardType,

        [string[]]
        $Branch,

        [string[]]
        $Category,

        [string[]]
        $Status,

        [string[]]
        $Type,

        [ValidateSet('planned', 'in_progress', 'done')]
        [string[]]
        $CurrentState


    )
    begin {
        Write-PsfMessage "Function started" -level verbose
    }

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level InternalComment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level InternalComment

        $methodParams = @{
            Uri = "$(Get-TdUrl)/tas/api/changeCalendar?start=$(get-date $start -UFormat '+%Y-%m-%dT%H:%M:%SZ')&end=$(get-date $end -UFormat '+%Y-%m-%dT%H:%M:%SZ')"
        }

        if ($PSBoundParameters.Keys -contains 'CardType') {
            foreach ($g in $cardType) {
                $methodParams['Uri'] = "$($methodParams.uri)&cardType=$g"
            }
        }

        if ($PSBoundParameters.Keys -contains 'branch') {
            foreach ($g in $branch) {
                $methodParams['Uri'] = "$($methodParams.uri)&branch=$g"
            }
        }

        if ($PSBoundParameters.Keys -contains 'category') {
            foreach ($g in $category) {
                $methodParams['Uri'] = "$($methodParams.uri)&category=$g"
            }
        }

        if ($PSBoundParameters.Keys -contains 'subcategory') {
            foreach ($g in $subcategory) {
                $methodParams['Uri'] = "$($methodParams.uri)&subcategory=$g"
            }
        }

        if ($PSBoundParameters.Keys -contains 'status') {
            foreach ($g in $status) {
                $methodParams['Uri'] = "$($methodParams.uri)&status=$g"
            }
        }

        if ($PSBoundParameters.Keys -contains 'type') {
            foreach ($g in $type) {
                $methodParams['Uri'] = "$($methodParams.uri)&type=$g"
            }
        }

        if ($PSBoundParameters.Keys -contains 'currentState') {
            foreach ($g in $currentState) {
                $methodParams['Uri'] = "$($methodParams.uri)&currentState=$g"
            }
        }

        $res = Invoke-TdMethod @methodParams
        ($res).results
    }
    end {
        Write-PSFMessage "Function Complete" -level Verbose
    }
}



function Get-TdChangeCalendarDetail {
    <#
.SYNOPSIS
    returns detailed information about the change
.DESCRIPTION
    returns detailed infromation about the change
.Parameter CalendarId
    Id of the calendar event
.EXAMPLE
    PS C:\> Get-TdChangeCalendarDetail -ChangeId $changeId
    returns detailed information about the change
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdChangeCalendarDetail')]

    param
    (
        [Parameter(
            mandatory = $true,
            ValueFromPipelineByPropertyName
        )]
        [Alias('Id')]
        $CalendarId
    )

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level InternalComment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level InternalComment

        $uri = "$(Get-TdUrl)/tas/api/changeCalendar/$CalendarId"
        $res = Invoke-TdMethod -Uri $uri
        $res
    }

}



function Get-TdChangeCalendarProgress {
    <#
.SYNOPSIS
    returns the progress trail of the specified calendar id
.DESCRIPTION
    returns the progress trail of the specified calendar id
.PARAMETER CalendarId
    ID of the Calendar Event. See Get-TdChangeCalendar
.EXAMPLE
    PS C:\> Get-TdChangeCalendar | Get-TdChangeCalendarProgress
    returns the progress trail of all calendar events
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdChangeCalendarProgress')]

    param
    (
        [Parameter(
            mandatory = $true,
            ValueFromPipelineByPropertyName
        )]
        [Alias('Id')]
        $calendarId
    )

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level InternalComment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level InternalComment

        $uri = "$(Get-TdUrl)/tas/api/changeCalendar/$calendarId/progresstrail"
        $res = Invoke-TdMethod -Uri $uri
        $res
    }
}



function Get-TdChangeCalendarRequest {
    <#
.SYNOPSIS
    Lists the requests for specified calendar event
.DESCRIPTION
    lists the requests for specified calendar event
.EXAMPLE
    PS C:\> Get-TdChangeCalendar | Get-TdChangeCalendarRequest
    lists all change requests
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdChangeCalendarRequest')]

    param
    (

    )


    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level InternalComment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level InternalComment

        $uri = "$(Get-TdUrl)/tas/api/changeCalendar/$calendarId/requests"
        $res = Invoke-TdMethod -Uri $uri
        $res
    }

}



function Get-TdChangeDetail {
    <#
.SYNOPSIS
    returns details of a specified change
.DESCRIPTION
    returns details of a specified change
.PARAMETER ChangeNumber
    Change Number in format CYYMM-XXXX
.EXAMPLE
    PS C:\> Get-TdChange | Get-TdChangeDetail
    returns details of all changes
#>
    #TODO add support for change ID
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdChangeDetail')]

    param
    (
        [Parameter(
            mandatory = $true,
            ValueFromPipelineByPropertyName
        )]
        [Alias('number')]
        $ChangeNumber
    )

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level InternalComment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level InternalComment

        $uri = "$(Get-TdUrl)/tas/api/operatorChanges/$ChangeNumber"
        $res = Invoke-TdMethod -Uri $uri
        $res
    }
}



function Get-TdChangeProgress {
    <#
.SYNOPSIS
    Returns progress trail of specified change
.DESCRIPTION
    returns progress trail of specified change
.PARAMETER ChangeId
    ID of the Change See Get-TdChange
.PARAMETER InlineImages
    if enabled InlineImages will be in the output
.PARAMETER BrowserFriendlyUrls
    if enabled Browser Friendly Urls will be in output
.EXAMPLE
    PS C:\> Get-TdChangeProgress -ChangeId (Get-TdChange -Name 'example).id
    returns progress trail of specified change
.EXAMPLE
    PS C:\> Get-TdChange -Name 'My Sample Change' | Get-TdChangeProgress
    Returns progress trail of 'My Sample Change'

#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdChangeProgress')]

    param
    (
        [Parameter(
            mandatory = $true,
            ValueFromPipelineByPropertyName
        )]
        [Alias('Id')]
        $ChangeId,

        [switch]
        $InlineImages = $false,

        [switch]
        $BrowserFriendlyUrls = $false
    )

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level InternalComment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level InternalComment

        $uri = "$(Get-TdUrl)/tas/api/operatorChanges/$ChangeId/progresstrail"

        #TODO fix this logic these are both 'query' and not 'path' for the param type
        if ($InlineImages) {
            $uri = "$uri&inlineimages=true"
        }
        if ($BrowserFriendlyUrls) {
            $uri = "$uri&browserFriendlyUrls=true"
        }
        $res = Invoke-TdMethod -Uri $uri
        $res.results
    }

}



function Get-TdChangeRequest {
    <#
.SYNOPSIS
    returns list of change requests
.DESCRIPTION
    returns list of change requests
.PARAMETER ChangeId
    ID of the Change. See Get-TdChange
.PARAMETER InlineImages
    if enabled InlineImages will be in the output
.PARAMETER BrowserFriendlyUrls
    if enabled Browser Friendly Urls will be in output
.EXAMPLE
    PS C:\> Get-TdChangeRequest -ChangeId $ChangeId
    returns list of change requests associated with specified change
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdChangeRequest')]

    param
    (
        [Parameter(
            mandatory = $true,
            ValueFromPipelineByPropertyName
        )]
        [Alias('Id')]
        $ChangeId,

        [switch]
        $InlineImages,

        [switch]
        $BrowserFriendlyUrls
    )

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level InternalComment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level InternalComment

        $uri = "$(Get-TdUrl)/tas/api/operatorChanges/$Changeid/requests"

        #TODO fix this logic these are both 'query' and not 'path' for the param type
        if ($InlineImages) {
            $uri = "$uri&inlineimages=true"
        }
        if ($BrowserFriendlyUrls) {
            $uri = "$uri&browserFriendlyUrls=true"
        }
        $res = Invoke-TdMethod -Uri $uri
        $res
    }
}



function Get-TdChangeTemplate {
    <#
.SYNOPSIS
    returns list of all templates used to create new requests for changes
.DESCRIPTION
    returns list of all templates used to create new requests for changes
.PARAMETER Name
    Basic Name/BriefDescription filter. This will filter the results. Wildcards accepted. Default value = '*'
.EXAMPLE
    PS C:\> Get-TdChangeTemplate
    returns list of all templates used to create new requests for change
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdChangeTemplate')]

    param
    (
        [string]
        $Name = '*'
    )
    begin {
        Write-PsfMessage "[$($MyInvocation.MyCommand.Name)] Function started" -level verbose
    }

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level InternalComment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level InternalComment

        $uri = "$(Get-TdUrl)/tas/api/applicableChangeTemplates"
        $res = Invoke-TdMethod -Uri $uri
        $res.results | Where-Object BriefDescription -Like $Name
    }
    end {
        Write-PSFMessage "Function Complete" -level Verbose
    }
}


function New-TdChange {
    <#
    .SYNOPSIS
        Create a new Request for Change
    .DESCRIPTION
        Create new change request. Can also use a change template to help fill out the change.
        Also triggers Events and Actions. Note! Actions that require user interaction like “Confirm before sending” or “Editable before sending” will not be executed.
    .PARAMETER RequesterId
        Id of the requester of the change. This is a person id. See Get-TdPerson
    .PARAMETER BriefDescription
        Brief description of a created change. example: Smartphone broken
    .PARAMETER ChangeType
        Specify the type of change. Options: Simple, Extensive
    .PARAMETER Request
        The request of the change
        example: Dean reported that his smartphone is broken. We need to order new ones.
    .PARAMETER Action
        The action of the change. example: I ordered 5 new smartphones.
    .PARAMETER TemplateId
        Id of the template that you want. if both TemplateId and TemplateNumber are set, then only the id weill be taken into account.
    .PARAMETER ExternalNumber
        External number of the change. example: 12345
    .PARAMETER Category
    UUID or name of the category. example: Software
    .PARAMETER SubCategory
        UUID or name of the subcategory. It must match with the provided category or the category of the template
    .PARAMETER Benefit
        UUID or name of the benefit. example: Cost Savings
    .PARAMETER Impact
        UUID or name of the impact. example: Branch
    .PARAMETER Priority
        UUID or name of the priority. example: Low
    .PARAMETER Confirm
		If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
	.PARAMETER WhatIf
		If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
    .EXAMPLE
        PS C:\> New-TdChange -RequesterId (Get-TdPerson -name 'Jane User').id -BriefDescription 'an example change' -ChangeType 'extensive'
        creates new extensive change with description 'an example change' with requester Jane User
    #>
    [CmdletBinding( SupportsShouldProcess = $true,
        HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/New-TdChange')]
    param (
        [Parameter(Mandatory)]
        [system.string]
        $RequesterId,

        [Parameter(Mandatory)]
        [system.string]
        $BriefDescription,

        [ValidateSet('Simple', 'Extensive')]
        [system.string]
        $ChangeType,

        [system.string]
        $Request,

        [system.string]
        $Action,

        [system.string]
        $TemplateId,

        [system.string]
        $ExternalNumber ,

        [system.string]
        $Category,

        [system.string]
        $SubCategory,

        [system.string]
        $Benefit,

        [system.string]
        $Impact,

        [system.string]
        $Priority
        #TODO add optional activities
        #TODO add template
        #TODO add phases

    )

    begin {
        $uri = (get-tdurl) + '/tas/api/operatorChanges'
    }

    process {

        $body = [PSCustomObject]@{}
        switch ($PSBoundParameters.Keys) {
            BriefDescription {
                Write-PSFMessage -Level InternalComment -Message "Adding briefDescription to Body"
                $body | Add-Member -MemberType NoteProperty -Name 'briefDescription' -Value $BriefDescription
            }

            ChangeType {
                Write-PSFMessage -Level InternalComment -Message "Adding ChangeType to Body"
                $body | Add-Member -MemberType NoteProperty -Name 'changeType' -Value $ChangeType.ToLower()
            }
            RequesterId {
                $requesterIdObject = @{
                    id = $RequesterId
                }
                Write-PSFMessage -Level InternalComment -Message "Adding requesterId to Body"
                $body | Add-Member -MemberType NoteProperty -Name 'requester' -Value $requesterIdObject
            }
            Request {
                Write-PSFMessage -Level InternalComment -Message "Adding request to Body"
                $body | Add-Member -MemberType NoteProperty -Name 'request' -Value $Request
            }

            action {
                Write-PSFMessage -Level InternalComment -Message "Adding action to Body"
                $body | Add-Member -MemberType NoteProperty -Name 'action' -Value $action
            }
            TemplateId {
                $templateIdObject = @{
                    id = $TemplateId
                }
                Write-PSFMessage -Level InternalComment -Message "Adding templateId to Body"
                $body | Add-Member -MemberType NoteProperty -Name 'template' -Value $templateIdObject
            }
            externalNumber {
                Write-PSFMessage -Level InternalComment -Message "Adding externalNumber to Body"
                $body | Add-Member -MemberType NoteProperty -Name 'externalNumber' -Value $externalNumber
            }
            category {
                Write-PSFMessage -Level InternalComment -Message "Adding category to Body"
                $body | Add-Member -MemberType NoteProperty -Name 'category' -Value $category
            }
            subcategory {
                Write-PSFMessage -Level InternalComment -Message "Adding subcategory to Body"
                $body | Add-Member -MemberType NoteProperty -Name 'subcategory' -Value $subcategory
            }
            benfit {
                Write-PSFMessage -Level InternalComment -Message "Adding benfit to Body"
                $body | Add-Member -MemberType NoteProperty -Name 'benfit' -Value $benfit
            }
            impact {
                Write-PSFMessage -Level InternalComment -Message "Adding impact to Body"
                $body | Add-Member -MemberType NoteProperty -Name 'impact' -Value $impact
            }
            priority {
                Write-PSFMessage -Level InternalComment -Message "Adding priority to Body"
                $body | Add-Member -MemberType NoteProperty -Name 'priority' -Value $priority
            }
        }
        Write-PSFMessage "$($body | ConvertTo-Json | Out-String)" -Level debug
        $params = @{
            'Uri' = $uri
            'Body' = $body | ConvertTo-Json
            'Method' = 'Post'
        }
        if ($PSCmdlet.ShouldProcess("Request" , "Sending change request $BriefDescription")) {
            Invoke-TdMethod @params
        }

    }

    end {
    }
}


function New-TdChangeAction {
    <#
    .SYNOPSIS
        Creates a new action for a change
    .DESCRIPTION
        Create a simple change action for a change. Rich text is not supported.
    .PARAMETER ChangeId
        The UNID of the change.
    .PARAMETER MemoText
    The text of this progress trail entry, if it is of type 'memo’. May not contain only whitespace characters (Spaces, New Lines, Tabs) and may not be empty. Rich text is not supported when using this object to create a new progress trail entry.
    	.PARAMETER Confirm
		If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

	.PARAMETER WhatIf
		If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

    .EXAMPLE
        PS C:\> <example usage>
        Explanation of what the example does
    #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/TOPdeskPS/New-TdChangeAction',
        SupportsShouldProcess = $true)]
    param (
        [system.string]
        $ChangeId,
        [system.string]
        $MemoText
    )

    begin {
        Write-PSFMessage -Level InternalComment -Message "Bound parameters: $($PSBoundParameters.Keys -join ", ")" -Tag 'debug', 'start', 'param'
        $url = (Get-TdUrl) + "/tas/api/operatorChanges/$ChangeId/progresstrail"

    }

    process {
        Write-PSFMessage -Level InternalComment -Message "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"

        #TODO look into this more

        $Body = [PSCustomObject]@{
            memoText = $MemoText
            # API currently only supports memos so this is hardcoded.
            type = 'memo'
        }
        Write-PSFMessage "Body: `n $($body | ConvertTo-Json)" -level Verbose

        $Params = @{
            'Uri' = $url
            'Body' = ($Body | ConvertTo-Json)
            'Method' = 'Post'
        }
        Invoke-TdMethod @Params
    }

}


function New-TdChangeProgress {
    <#
.SYNOPSIS
    creates a new action for specified change
.DESCRIPTION
    creates a new action for specified change
.PARAMETER ChangeId
    ID of the Change
.PARAMETER MemoText
    text to be added to memo field
.PARAMETER Type
    The type of this progress trail entry.
.PARAMETER Confirm
    If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
.PARAMETER WhatIf
    If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
.EXAMPLE
    PS C:\> New-TdChangeProgress -ChangeId $ChangeId -MemoText 'this is a memo'
    addes a new memo to the specified change
#>
    #TODO this is a duplicate of New-TdChangeAction ... neither of these work

    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/New-TdChangeProgress',
        SupportsShouldProcess = $true)]
    param
    (
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName
        )]
        [Alias('Id')]
        $ChangeId,

        [Parameter(Mandatory = $true)]
        [string]
        $MemoText,

        [ValidateSet('memo', 'attachment', 'link')]
        [string]
        $Type = 'memo'

    )

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -Level InternalComment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -Level InternalComment

        $uri = "$(Get-TdUrl)/tas/api/operatorChanges/$ChangeId/progresstrail"
        $body = [PSCustomObject]@{}
        $body | Add-Member -MemberType NoteProperty -Name 'memoText' -Value $MemoText
        $body | Add-Member -MemberType NoteProperty -Name 'type' -Value $Type

        Write-PSFMessage "Body: `n$($body | ConvertTo-Json)" -level Verbose


        if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action 'Sending Request')) {
            return
        }

        $methodParams = @{
            'Uri' = $uri
            'Body' = ($body | ConvertTo-Json)
            'Method' = 'Post'
        }
        $res = Invoke-TdMethod @methodParams
        $res
    }
}



function Send-TdChangeActivityFile {
    <#
    .SYNOPSIS
        Upload a file to a change activity.
    .DESCRIPTION
        Upload a file to a change activity.
    .PARAMETER ChangeId
        Id of the change activity that you want to work with.
    .PARAMETER File
        File that you want to upload.

    .EXAMPLE
        PS> Get-TdChangeActivity 'C1811-123' | Send-TdChangeActivityFile -File 'C:\TestFile.txt'
        Uploads a file to a change activity

    .EXAMPLE
        PS> Get-TdChangeDetail 'C1211-123' | Send-TdChangeActivityFile -file 'C:\log.txt'
        uploads a file to C1211-123
    #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Send-TdChangeActivityFile')]
    param (

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('id')]
        [string]
        $ChangeId,

        [Parameter(Mandatory, ValueFromPipeline, ValuefromPipelineByPropertyName)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path)) {
                    throw "File or folder does not exist"
                }
                if (-Not ($_ | Test-Path -PathType Leaf)) {
                    throw "The Path argument must be a file. Folder paths are not allowed."
                }
                return $true
            })]
        [System.IO.FileInfo[]]
        $File
    )

    process {
        $Body = [PSCustomObject]@{}
        foreach ($f in $File) {

            $uri = "$(Get-TdUrl)/tas/api/operatorChangeActivities/$ChangeId/attachments"


            $params = @{
                Body = $Body
                Uri = $Uri
                File = "$($f.fullname)"
                Method = 'Post'
            }
            Invoke-TdMethod @params
        }
    }
}


function Send-TdChangeFile {
    <#
    .SYNOPSIS
        Upload a file to a change.
    .DESCRIPTION
        Upload a file to an Change. You can make the file invisible to the caller and you can also add a description.
    .PARAMETER ChangeId
        Id of the change that you want to work with.
    .PARAMETER File
        File that you want to upload.

    .EXAMPLE
        PS> Get-TdChangeDetail 'C1811-123' | Send-TdChangeFile -File 'C:\TestFile.txt'
        Uploads a file to a change

    .EXAMPLE
        PS> Get-TdChangeDetail 'C1211-123' | Send-TdChangeFile -file 'C:\log.txt'
        uploads a file to C1211-123
    #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Send-TdChangeFile')]
    param (

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('id')]
        [string]
        $ChangeId,

        [Parameter(Mandatory, ValueFromPipeline, ValuefromPipelineByPropertyName)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path)) {
                    throw "File or folder does not exist"
                }
                if (-Not ($_ | Test-Path -PathType Leaf)) {
                    throw "The file argument must be a file. Folder paths are not allowed."
                }
                return $true
            })]
        [System.IO.FileInfo[]]
        $File
    )

    process {
        foreach ($f in $File) {

            $uri = "$(Get-TdUrl)/tas/api/operatorChanges/$ChangeId/attachments"

            $params = @{
                Uri = $Uri
                File = "$($f.fullname)"
                Method = 'Post'
            }
            Invoke-TdMethod @params
        }
    }
}


function Set-TdChange {
    <#
.SYNOPSIS
    Sort of sets a change, this is poorly supported by TOPdesk :/
.DESCRIPTION
    does most of the change setting, poorly supported by TOPdesk, read the .LINK
.PARAMETER ChangeId
    Id of the Change Request to be altered
.PARAMETER BodyInput
    formatted input to match the example value linked to in the .LINK
.PARAMETER Confirm
    If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
.PARAMETER WhatIf
    If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
.EXAMPLE
    PS C:\> Set-TdChange -ChangeId 'C1807-627' -BodyInput 'body text'
    sets the body of specified change. this api is poorly supported by TOPdesk
.LINK
    https://developers.topdesk.com/explorer/?page=change#/Working%20as%20an%20operator/patch_operatorChanges__identifier_
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Set-TdChange',
        SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory)]
        [system.string]
        $ChangeId,
        [Parameter(Mandatory)]
        $BodyInput
    )
    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -Level InternalComment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -Level InternalComment

        $uri = "$(Get-TdUrl)/tas/api/operatorChanges/$ChangeId"
        $body = $BodyInput

        if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action 'Sending Request')) {
            return
        }
        $methodParams = @{
            Uri = $uri
            Body = (ConvertTo-Json $body)
            Method = 'Patch'
            ContentType = 'application/json-patch+json'
        }
        $res = Invoke-TdMethod @methodParams
        $res
    }
}


function Set-TdChangeActivity {
    <#
.SYNOPSIS
    creates a new change activity
.DESCRIPTION
    creates a new change activity
.PARAMETER  ActivityTemplate
    ID or AT-XXXX number for activity template
.PARAMETER ChangeId
    Id of the change see Get-TdChange
.PARAMETER BriefDescription
    a brief description
.PARAMETER ChangePhase
    accepted values 'rfc' 'progress' 'evaluation'
.PARAMETER ActivityType
    accepted values 'normal' 'authorization'
.PARAMETER PlannedStartDate
    Format: 2018-04-23T10:09:00+0000
.PARAMETER PlannedFinalDate
    Format: 2018-04-23T10:09:00+0000
.PARAMETER AssigneeId
    ID of the operator to be assigned to the change
.PARAMETER AssigneeGroupId
    ID of the group to be assigned to the change
.PARAMETER AssigneeType
    accepted values 'manager' 'operator'
.PARAMETER Status
    user defined status of activity. accepts name or id
.PARAMETER Category
    user defined category of activity. accepts name or id
.PARAMETER Subcategory
    user defined subcategory of activity. accepts name or id
.PARAMETER Request
    description of activity
.PARAMETER Action
    action to be added to the activity
.PARAMETER OptionalFields1
    optional see .NOTES
.PARAMETER OptionalFields2
    optional see .NOTES
.PARAMETER Confirm
    If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
.PARAMETER WhatIf
    If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
.NOTES
https://developers.topdesk.com/explorer/?page=change&version=1.2.0#/Working%20as%20an%20operator/post_operatorChangeActivities
.EXAMPLE
    PS C:\> Set-TdChangeActivity -changeId $changeId -briefDescription 'My Description' -changePhase 'progress' -status 'planned'
    creates a new change with specified fields
#>
    #TODO add activity template support
    #TODO Help params
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Set-TdChangeActivity',
        SupportsShouldProcess = $true)]
    param
    (
        [parameter(ParameterSetName = 'template')]
        $ActivityTemplate,

        [Parameter(
            mandatory = $true,
            ValueFromPipelineByPropertyName
        )]
        [Alias('Id')]
        $ChangeId,

        [string]
        $BriefDescription,

        [string]
        [ValidateSet('rfc', 'progress', 'evaluation')]
        $ChangePhase,

        [string]
        [ValidateSet('normal', 'authorization')]
        $ActivityType,

        [string]
        $PlannedStartDate,

        [string]
        $PlannedFinalDate,

        [string]
        $AssigneeId,

        [parameter(ValueFromPipelineByPropertyName)]
        $AssigneeGroupId,

        [string]
        [ValidateSet('manager', 'operator')]
        $AssigneeType,

        [string]
        $Status,

        [string]
        $Category,

        [string]
        $Subcategory,

        [string]
        $Request,

        [string]
        $Action,

        [hashtable]
        $OptionalFields1,

        [hashtable]
        $OptionalFields2
    )

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -Level InternalComment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -Level InternalComment

        $uri = "$(Get-TdUrl)/tas/api/operatorChangeActivities"
        $body = [PSCustomObject]@{
            changeId = $changeId
        }
        if ($PsCmdlet.ParameterSetName -like 'template') {
            $body | Add-Member -MemberType NoteProperty -Name activityTemplate -Value $ActivityTemplate
        }

        switch ($PSBoundParameters.Keys) {
            BriefDescription {
                $body | Add-Member -MemberType NoteProperty -Name briefDescription -Value $BriefDescription
            }
            ChangePhase {
                $body | Add-Member -MemberType NoteProperty -Name changePhase -Value $changePhase
            }
            ActivityType {
                $body | Add-Member -MemberType NoteProperty -Name activityType -Value $activityType
            }
            PlannedStartDate {
                $body | Add-Member -MemberType NoteProperty -Name plannedStartDate -Value $plannedStartDate
            }
            plannedFinalDate {
                $body | Add-Member -MemberType NoteProperty -Name plannedFinalDate -Value $plannedFinalDate
            }
            #       AssigneeGroupId {
            #          $assignee | Add-Member -MemberType NoteProperty -Name groupId -Value $AssigneeGroupId
            #     }
            #    AssigneeType {
            #       $assignee | Add-Member -MemberType NoteProperty -Name type -Value $assigneeType
            #  }
            assigneeId {
                $assignee = @{
                    id = $AssigneeId # parameters are CaPiTaLiZeD 0_0
                }
                if ($AssigneeGroupId) {
                    $assignee['groupId'] = $AssigneeGroupId
                }
                if ($AssigneeType) {
                    $assignee['type'] = $AssigneeType
                }
                $body | Add-Member -MemberType NoteProperty -Name assignee -Value $assignee #TODO look at how this is being passed. NOTE
            }
            status {
                $body | Add-Member -MemberType NoteProperty -Name status -Value $status
            }
            category {
                $body | Add-Member -MemberType NoteProperty -Name category -Value $category
            }
            subcategory {
                $body | Add-Member -MemberType NoteProperty -Name subcategory -Value $subcategory
            }
            request {
                $body | Add-Member -MemberType NoteProperty -Name request -Value $request
            }
            action {
                $body | Add-Member -MemberType NoteProperty -Name action -Value $activityaction
            }
            optionalFields1 {
                $body | Add-Member -MemberType NoteProperty -Name optionalFields1 -Value $OptionalFields1
            }
            optionalFields2 {
                $body | Add-Member -MemberType NoteProperty -Name optionalFields2 -Value $OptionalFields2
            }
        }

        Write-PSFMessage "Body: `n $($body | ConvertTo-Json)" -level verbose

        if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action 'Sending Request')) {
            return
        }
        $methodParams = @{
            Uri = $uri
            Body = ($body | ConvertTo-Json)
            Method = 'Post'
        }
        $res = Invoke-TdMethod @methodParams
        $res
    }
}



function Set-TdChangeProcessingStatus {
    <#
.SYNOPSIS
    process a change through a phase
.DESCRIPTION
    process a change through a phase
.PARAMETER ChangeId
ID of the Change. See Get-TdChange
.PARAMETER From
    original status of change
.PARAMETER Action
    Action to implement on the change
.PARAMETER Reason
    reason for the change
.PARAMETER Comment
    additional comment
.PARAMETER Confirm
    If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
.PARAMETER WhatIf
    If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
.EXAMPLE
    PS C:\> Get-TdChangeDetail -ChangeNumber 'C1810-005' | Get-TdChangeProcessingStatus -action 'no_go'
    changes the status of specified change to specfied action
    #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Set-TdChangeProcessingStatus',
        SupportsShouldProcess = $true)]
    param
    (
        [Parameter(
            mandatory = $true,
            ValueFromPipelineByPropertyName
        )]
        [Alias('Id')]
        $ChangeId,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet(
            'prfc', 'rfc', 'simple_notStarted', 'simple_InProgress', 'simple_done', 'extensive_done', 'extensive_evaluated'
        )]
        [Alias('processingStatus')]
        $From,


        [Parameter(Mandatory)]
        [ValidateSet('submit', 'approve', 'reject', 'no_go', 'start', 'implement', 'close')]
        $Action,

        [string]
        $Reason,

        [string]
        $Comment


    )


    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -Level InternalComment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -Level InternalComment

        $uri = "$(Get-TdUrl)/tas/api/operatorChanges/$changeId/processingStatusTransitions"
        $body = [PSCustomObject]@{
            from = $From
            action = $action
        }
        switch ($PSBoundParameters.Keys) {
            reason {
                $body | Add-Member -MemberType NoteProperty -Name reason -Value $Reason
            }
            comment {
                $body | Add-Member -MemberType NoteProperty -Name comment -Value $Comment
            }
        }

        $methodParams = @{
            Uri = $uri
            Body = ($body | ConvertTo-Json)
            Method = 'Post'
        }
        if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $methodparams.uri -Action 'Sending Request')) {
            return
        }

        $res = Invoke-TdMethod @methodParams
        $res
    }

}



function Connect-TdService {
    <#
	.SYNOPSIS
		Prepares your session for TOPdeskPS

	.DESCRIPTION
		This command either generates a login token if you provide TOPdesk credentials or this will generate the headers if you are using an application password (use -ApplicationPassword)

	.PARAMETER Credential
		Credentials used to access TOPdesk.

	.PARAMETER UserType
		Specify whether you want to login as a person or an operator. Default value: operator

	.PARAMETER PassThru
		Passes the login token through to the console. Can be useful for troubleshooting or if you want to generate a login token to be consumed by a different application.

	.PARAMETER Url
		This is the Url of your TOPdesk instance. You can specify a custom port. Example: 'https://Company.TOPdesk.net' , 'http://10.1.2.3:90'

	.PARAMETER Register
		Saves your TOPdesk url so you don't need to manually specify it each time. For more information see about_TOPdeskPS_Registration

	.PARAMETER EnableException
        Specify whether you want this command to throw an exception if it encounters an error.

    .PARAMETER ApplicationPassword
        Specify whether you are supplying an application password credential rather than a TOPdesk credential. The credential still needs to be provided to the Credential parameter.

	.EXAMPLE
		PS C:\> Connect-TdService -Url 'https://company.topdesk.net' -Credential (Get-Credential)
		Prompts you for your TOPdesk credentials and then connects to TOPdesk.

	.EXAMPLE
		PS C:\> Connect-TdService -Credential $Cred -Url 'https://company.topdesk.net:90' -Register -ApplicationPassword
        Generates a header that is specific to Application Passwords. The Url will be registered so you don't need to enter it the next time you run connect-tdservice. We will be using port 90.
#>

    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/TOPdeskPS/Connect-TdService')]
    [OutputType([System.String])]
    param
    (

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSCredential]
        $Credential,

        [ValidateSet('person', 'operator')]
        $UserType = 'operator',

        [switch]
        $PassThru,

        #[PSFValidatePattern('http(s)?://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)?', ErrorMessage = '{0} is not a valid TOPdesk Url.')]
        [System.String]
        $Url = (
           Get-TdUrl),

        [switch]
        $Register,

        [Switch]
        $ApplicationPassword,

        [switch]
        $EnableException
    )
    Write-PSFMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level Debug
    Write-PSFMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -Level Debug
    $resourceUri = "$url/tas/api/login/$UserType"

    if ($ApplicationPassword) {
        Write-PSFMessage -Level Verbose -Message "Generating Basic header using applicationpassword."
        $Script:__LoginToken = "Basic $(ConvertTo-Base64 "$($Credential.username):$($Credential.GetNetworkCredential().password)")"
    }

    elseif (-not $ApplicationPassword) {
        Write-PSFMessage "Sending login request to TOPdesk to generate token." -Level Verbose
        $headers = @{
            'Authorization' = "Basic $(ConvertTo-Base64 "$($Credential.username):$($Credential.GetNetworkCredential().password)")"
        }
        $params = @{
            URI = $resourceURi
            Method = "GET"
            Headers = $headers
        }
        $result = Invoke-RestMethod @params -ErrorAction Stop
        if ($result.item.name -like 'item') {
            Stop-PSFFunction -Message 'invalid url given.' -EnableException $EnableException -Cmdlet $PSCmdlet
            return
        }
        else {
            Write-PSFMessage -Level Verbose -Message 'LoginToken received and set.'
            $Script:__LoginToken = "TOKEN id=`"$result`""
        }
    }
    if ($PassThru) {
        $Script:__LoginToken
    }


    Set-PSFConfig -FullName TOPdeskPS.Url -Value $Url
    if ($Register) {
        Register-PSFConfig -FullName TOPdeskPS.Url
    }

    if (Test-PSFFunctionInterrupt) {
        return
    }
}


function Disconnect-TdService {
    <#
	.SYNOPSIS
		Disconnects you from the TOPdesk service and invalidates your login token.

	.DESCRIPTION
		Disconnects you from the TOPdesk service and invalidates your login token.

	.EXAMPLE
		PS C:\> Disconnect-TdService
		Disconnects from TOPdesk and invalidates your token.
#>

    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/TOPdeskPS/Disconnect-TdService')]
    param ()

    begin {
        Write-PSFMessage -Level InternalComment -Message "Bound parameters: $($PSBoundParameters.Keys -join ", ")" -Tag 'debug', 'start', 'param'
        Write-PSFMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level InternalComment
    }
    process {
        $ResourceUri = (get-TdUrl) + '/tas/api/logout'
        Write-PSFMessage -Level InternalComment -Message "ResourceUri: $ResourceUri"
        $headers = @{
            'Authorization' = $Script:__LoginToken
        }

        $parameter = @{
            URI     = $resourceURi
            Method  = 'GET'
            Headers = $headers
        }

        #TODO: test more.
        $result = Invoke-RestMethod @parameter -ErrorAction Stop
        $result
        $Script:__LoginToken = $null
    }
    end {
        Write-PSFMessage -Level InternalComment 'Function complete.'
    }
}

function Get-TdApiVersion {
    <#
    .SYNOPSIS
        Gets version of the TOPdesk API
    .DESCRIPTION
        Gets version of the TOPdesk API
    .EXAMPLE
        PS C:\> Get-TdApiVersion
        Gets version of the TOPdesk API

    #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdApiVersion')]
    param ()
    Write-PSFMessage -Level InternalComment -Message "Bound parameters: $($PSBoundParameters.Keys -join ", ")" -Tag 'debug', 'start', 'param'
    $uri = (Get-TdUrl) + '/tas/api/version'
    Write-PSFMessage -Level InternalComment -Message "version url: $uri"
    $Params = @{
        'uri' = $uri
    }
    $res = Invoke-TdMethod @Params
    $res
}


function Get-TdArchiveReason {
    <#
    .SYNOPSIS
        Gets archive reasons
    .DESCRIPTION
        Can get all archive reasons, or specify which one you want by a Name lookup.
    .PARAMETER Name
        Name of the branch that you want returned. Wildcards are supported.
    .EXAMPLE
        PS C:\> Get-TDArchiveReason -Name 'No longer employed'
        Gets the archive reason with the name 'no longer employed'
    .EXAMPLE
        PS> Get-TdArchiveReason -name 'Phased*'
        Returns all archive reasons that begin with "phased"
    #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdArchiveReason')]
    param (
        [parameter(position = 0)]
        [string]
        $Name = '*'
    )
    $uri = "$(Get-TdUrl)/tas/api/archiving-reasons"
    $res = Invoke-TdMethod -Uri $uri
    $res | Where-Object name -like $Name | Select-PSFObject -Typename 'TOPdeskPS.ArchiveReason' -KeepInputObject
}


function Get-TdCallType {
    <#
    .SYNOPSIS
        Gets call types
    .DESCRIPTION
        Gets call types
    .PARAMETER Name
        Name of the call type that you want returned. Wildcards are supported. Default value is '*'
    .EXAMPLE
        PS C:\> Get-TdCallType
        Gets list of call types

    .EXAMPLE
        PS> Get-TdCalltype Alert
        Returns the alert call type

    #>
    [CmdletBinding(Helpuri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdCallType')]
    param (
        [Parameter(position = 0)]
        [string]
        $Name = '*'
    )
    $uri = (Get-TdUrl) + '/tas/api/incidents/call_types'
    $res = Invoke-TdMethod $uri
    $res | Where-Object name -like $Name | Select-PSFObject -Typename 'TOPdeskPS.BasicObj' -KeepInputObject
}


function Get-TdCategory {
    <#
	.SYNOPSIS
		Get categories from TOPdesk

	.DESCRIPTION
		Gets either one category or a list of categories from TOPdesk.

	.PARAMETER Name
		This is the name of the category that you want. Wildcards are supported.

	.EXAMPLE
		PS C:\> Get-TdCategory
		Gets a list of all categories

	.EXAMPLE
		PS C:\> Get-TdCategory -Name 'End User Support'
		Gets the category with the name 'End User Support'
#>

    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/TOPdeskPS/Get-TdCategory')]
    param
    (
        [String]
        $Name = '*'
    )

    process {
        $CategoryURL = (Get-TdUrl) + '/tas/api/incidents/categories'

        $Params = @{
            'uri' = $CategoryUrl
        }
        $Categories = Invoke-TdMethod @Params
        $categories | Where-Object name -like $name | Select-PSFObject -Typename 'TOPdeskPS.BasicObj' -KeepInputObject
    }

}


function Get-TdClosureCode {
    <#
    .SYNOPSIS
        Gets closure codes
    .DESCRIPTION
        Gets closurec codes
    .PARAMETER Name
        Name of the closure code that you want returned. Wildcards are supported. Default value is '*'

    .EXAMPLE
        PS C:\> Get-TdClosureCode
        Gets list of all closurecodes

    .EXAMPLE
        PS> Get-TdClosureCode -Name 'hardware failure'
        Returns the hardware failure closure code
    #>
    [CmdletBinding( HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdClosureCode')]
    param (
        [Parameter(position = 0)]
        [string]
        $Name = '*'
    )
    $uri = (Get-TdUrl) + '/tas/api/incidents/closure_codes'
    $res = Invoke-TdMethod $uri
    $res | Where-Object name -like $Name | Select-PSFObject -Typename 'TOPdeskPS.BasicObj' -KeepInputObject
}


function Get-TdDeescalationReason {
    <#
    .SYNOPSIS
        Gets deescalation reasons
    .DESCRIPTION
        Gets deescalation reasons
    .PARAMETER Name
        Name of the deescalation reason that you want returned. Wildcards are supported. Default value is '*'

    .EXAMPLE
        PS C:\> Get-TdDeescalationReason
        Gets list of all deescalation reasons

    #>
    [CmdletBinding( HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdDeescalationReason')]
    param (
        [Parameter(position = 0)]
        [string]
        $Name = '*'
    )
    $uri = (Get-TdUrl) + '/tas/api/incidents/deescalation-reasons'
    $res = Invoke-TdMethod $uri
    $res | Where-Object name -like $Name | Select-PSFObject -Typename 'TOPdeskPS.BasicObj' -KeepInputObject
}


function Get-TdDuration {
    <#
    .SYNOPSIS
        Gets durations
    .DESCRIPTION
        Gets list of durations
    .PARAMETER Name
        Name of the duration that you want returned. Wildcards are supported. Default value is '*'

    .EXAMPLE
        PS C:\> Get-Tdduration
        Gets list of all durations

    #>
    [CmdletBinding(Helpuri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdDuration')]
    param (
        [string]$Name = '*'
    )
    $uri = (Get-TdUrl) + '/tas/api/incidents/durations'
    $Params = @{
        'uri' = $uri
    }
    $res = Invoke-TdMethod @Params
    $res | Where-object Name -like $Name
}


function Get-TdEntryType {
    <#
    .SYNOPSIS
        Gets entry types
    .DESCRIPTION
        Gets entry types
    .PARAMETER Name
        Name of the entry type that you want returned. Wildcards are supported.

    .EXAMPLE
        PS C:\> Get-Tdentrytype
        Gets list of all entry types

    #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdEntryType')]
    param (
        [string]$Name = '*'
    )
    $uri = (Get-TdUrl) + '/tas/api/incidents/entry_types'
    $Params = @{
        'uri' = $uri
    }
    $res = Invoke-TdMethod @Params
    $res | Where-Object name -like $Name | Select-PSFObject -Typename 'TOPdeskPS.BasicObj' -KeepInputObject
}


function Get-TdEscalationReason {
    <#
    .SYNOPSIS
        Gets all EscalationReasons
    .DESCRIPTION
            Gets all EscalationReasons
    .PARAMETER Name
        Name of the escalation reason that you want returned. Wildcards are supported. Default value is '*'

    .EXAMPLE
        PS C:\> Get-TdEscalationReason
        Gets list of all EscalationReasons

    #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdEscalationReason')]
    param (
        [Parameter(position = 0)]
        [string]
        $Name = '*'
    )
    $uri = (Get-TdUrl) + '/tas/api/incidents/escalation-reasons'

    $res = Invoke-TdMethod $uri
    $res | Where-Object name -like $Name | Select-PSFObject -Typename 'TOPdeskPS.BasicObj' -KeepInputObject
}


function Get-TdImpact {
    <#
    .SYNOPSIS
        Gets list of impacts
    .DESCRIPTION
        Gets list of impacts
    .PARAMETER Name
        Name of the impact that you want returned. Wildcards are supported. Default value is '*'

    .EXAMPLE
        PS C:\> Get-TdImpact
        Gets list of impacts

        .EXAMPLE
        PS> Get-TdImpact -name person
        Returns the 'person' impact
    #>
    [CmdletBinding( HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdImpact')]
    param (
        $Name = '*'
    )
    $uri = (Get-TdUrl) + '/tas/api/incidents/impacts'
    $Params = @{
        'uri' = $uri
    }
    $res = Invoke-TdMethod @Params
    $res | Where-Object name -like $Name | Select-PSFObject -Typename 'TOPdeskPS.BasicObj' -KeepInputObject
}


function Get-TdIncident {
    <#
	.SYNOPSIS
		Gets incidents

	.DESCRIPTION
		This command returns incidents from TOPdesk. The most you can grab per request is 100.

	.PARAMETER ResultSize
        The amount of incidents to be returned. Due to API limitations we're only able to return 1000 incidents per api call.

        If you would like to grab more than 10000 incidents at once you can use a very high value for resultsize and it will loop through until it reaches the resultsize or it runs out of events to return.

	.PARAMETER Start
		This is the offset at which you want to start listing incidents. Using Resultsize

	.PARAMETER Completed
		Retrieve only incidents that are completed / not completed. Set this parameter to $false to only retrieve not completed incidents, and set it to $true to only receive completed incidents.

	.PARAMETER Closed
		Retrieve only incidents that are closed /not closed.

	.PARAMETER Resolved
		Retrieve only incidents that are resolved depending on the setting "Call is resolved when" (Module Settings -> Call Management -> General)

	.PARAMETER Archived
		Whether to retrieve archived incidents.

	.PARAMETER Number
        This is the incident number of the incident that you would like to retrieve.

    .PARAMETER OrderBy
        Order the retrieved incidents by these criteria:
call_date
creation_date
modification_date
target_date
closed_date
with the order ASC (ascending) or DESC (descending) appended with a plus-sign. Possible combinations of orders are comma-separated
Example: order_by=creation_date+DESC,target_date+ASC
Default is sorted by creation date, descending (newest first).
Default value: creation_date+DESC

.PARAMETER MajorCall
Retrieve only incidents that are major calls / not major calls.
Can only be set by operators.

.PARAMETER TargetDateStart
Retrieve only incidents with target date greater or equal to this day 00:00:00, using time zone of the logged in user or operator

Accepts DateTime Objects

.PARAMETER TargetDateEnd
Retrieve only incidents with target date smaller or equal to this day 23:59:59, using time zone of the logged in user or operator

Accepts Datetime objects

.PARAMETER CallDateStart
Retrieve only incidents with call date greater or equal to this day 00:00:00, using time zone of the logged in user or operator

Accepts DateTime Objects

.PARAMETER CallDateEnd
Retrieve only incidents with call date smaller or equal to this day 23:59:59, using time zone of the logged in user or operator

Accepts Datetime objects
.PARAMETER CreationDateStart
Retrieve only incidents with creation date greater or equal to this day 00:00:00, using time zone of the logged in user or operator

Accepts DateTime Objects

.PARAMETER CreationDateEnd
Retrieve only incidents with creation date smaller or equal to this day 23:59:59, using time zone of the logged in user or operator

Accepts Datetime objects
.PARAMETER ModificationDateStart
Retrieve only incidents with modification date greater or equal to this day 00:00:00, using time zone of the logged in user or operator

Accepts DateTime Objects

.PARAMETER ModificationDateEnd
Retrieve only incidents with modification date smaller or equal to this day 23:59:59, using time zone of the logged in user or operator

Accepts Datetime objects
.PARAMETER ClosedDateStart
Retrieve only incidents with closed date greater or equal to this day 00:00:00, using time zone of the logged in user or operator

Accepts DateTime Objects
.PARAMETER ClosedDateEnd
Retrieve only incidents with closed date smaller or equal to this day 23:59:59, using time zone of the logged in user or operator

Accepts Datetime objects



.PARAMETER CallerId
Retrieve only incidents reported by one of these caller ids

.PARAMETER OperatorGroupId
Retrieve only incidents assigned to one of these operator group ids or "unassigned" for unassigned incidents

.PARAMETER OperatorId
Retrieve only incidents assigned to one of these operator ids or "unassigned" for unassigned incidents

.PARAMETER ProcessingStatusId
Retrieve only incidents with one of these processing status ids

.PARAMETER MainIncidentId
Retrieve only incidents that have one of these main incident ids. Overrides any status filter as only partials have main incidents.

.PARAMETER Status
    Retrieve only firstLine/secondLine/partial incidents (permission required)

.PARAMETER CallerBranchId
Retrieve only incidents reported by callers from one of these branch ids

.PARAMETER ObjectId
Retrieve only incidents that have one of the specified objects set (by id)

.PARAMETER ObjectName
Retrieve only incidents that have one of the specified objects set (by object name)

.PARAMETER LinkedObjectId
Retrieve only incidents that are linked to one of the specified objects (by id)

.PARAMETER LinkedObjectName

Retrieve only incidents that are linked to one of the specified objects (by object name)

.PARAMETER ExternalLinkId
Retrieve only incidents with external link id equal to one of these values. Should be used in combination with ExternalLinkType

.PARAMETER ExternalLinkType
Retrieve only incidents with external link type equal to one of these values. Should be used in combination with external_link_id.

.PARAMETER ExternalNumber
Retrieve one or more incidents with the given external numbers.

.PARAMETER Id
Retrieve one or more incidents with the given ids, make sure "page_size" is set accordingly to get all results.


	.EXAMPLE
		PS C:\> Get-TdIncident
        returns incidents

    .EXAMPLE
        PC> Get-Tdincident | Format-List *
        return incidents and all of their properties

    .EXAMPLE
        PS C:\> Get-TdIncident -Closed
        Returns incidents and includes closed incidents.
    .EXAMPLE
        PS C:\> Get-TdIncident -ResultSize 2000
        Returns 2000 incidents.
    .Example
        PS > Get-TdIncident -ResultSize Unlimited -ModificationDateStart (Get-date).adddays(-7)
        Returns all Incidents Modified in the last 7 days
#>

    [CmdletBinding(DefaultParameterSetName = 'List',
        HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/TOPdeskPS/Get-TdIncident')]
    param
    (
        [Parameter(ParameterSetName = 'Number',
            ValueFromPipeline = $true,
            position = 0)]
        [Alias('IncidentNumber')]
        [string[]]
        $Number,

        [ValidateRange(1, 999999)]
        [int]
        $ResultSize = 10,

        [int]
        $Start = 0,


        # Filters only one value used for each
        [switch]
        $Completed,

        [switch]
        $Closed,

        [switch]
        $Resolved,

        [switch]
        $Archived,

        #TODO
        [switch]
        $MajorCall,

        [datetime]
        $TargetDateStart,

        [datetime]
        $TargetDateEnd,

        [datetime]
        $CallDateStart,

        [datetime]
        $CallDateEnd,

        [datetime]
        $CreationDateStart,

        [datetime]
        $CreationDateEnd,

        [datetime]
        $ModificationDateStart,

        [datetime]
        $ModificationDateEnd,

        [datetime]
        $ClosedDateStart,

        [datetime]
        $ClosedDateEnd,

        # Filters accepting multiple values

        [string[]]
        $CallerId,

        [string[]]
        $OperatorGroupId,

        [string[]]
        $OperatorId,

        [string[]]
        $ProcessingStatusId,

        [string[]]
        $MainIncidentId,


        [ValidateSet('firstLine', 'secondLine', 'partial')]
        [string[]]
        $Status,

        [string[]]
        $CallerBranchId,

        [string[]]
        $ObjectId,

        [string[]]
        $ObjectName,

        [string[]]
        $LinkedObjectId,

        [string[]]
        $LinkedObjectName,

        [string[]]
        $ExternalLinkId,

        [string[]]
        $ExternalLinkType,

        [string[]]
        $ExternalNumber,

        [string[]]
        $Id,
        # Sorting
        [string]
        $OrderBy

    )


    process {
        Write-PSFMessage -Level InternalComment -Message "Bound parameters: $($PSBoundParameters.Keys -join ", ")" -Tag 'debug', 'start', 'param'
        Write-PSFMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level Debug


        $uri = "$(Get-TdUrl)/tas/api/incidents"

        switch ($PSCmdlet.ParameterSetName) {

            List {
                $uri = "$uri/?"

                switch ($PSBoundParameters.keys) {

                    #Region Filter parameters (used once)
                    Completed {
                        $uri = "$uri&completed=$Completed"
                    }

                    Closed {
                        $uri = "$uri&closed=$Closed"
                    }

                    Resolved {
                        $uri = "$uri&resolved=$Resolved"
                    }

                    Archived {
                        $uri = "$uri&archived=$($Archived.tostring().tolower())"
                    }


                    MajorCall {
                        $uri = "$uri&major_call=$($MajorCall.tostring().tolower())"
                    }

                    TargetDateStart {
                        $uri = "$uri&target_date_start=$(Get-Date $TargetDateStart -Format 'yyyy-MM-dd')"
                    }

                    TargetDateEnd {
                        $uri = "$uri&target_date_end=$(Get-Date $TargetDateEnd -Format 'yyyy-MM-dd')"
                    }

                    CallDateStart {
                        $uri = "$uri&call_date_start=$(Get-Date $CallDateStart -Format 'yyyy-MM-dd')"
                    }
                    CallDateEnd {
                        $uri = "$uri&call_date_end=$(Get-Date $CallDateEnd -Format 'yyyy-MM-dd')"
                    }

                    CreationDateStart {
                        $uri = "$uri&creation_date_start=$(Get-Date $CreationDateStart -Format 'yyyy-MM-dd')"
                    }

                    CreationDateEnd {
                        $uri = "$uri&creation_date_end=$(Get-Date $CreationDateEnd -Format 'yyyy-MM-dd')"
                    }

                    ModificationDateStart {
                        $uri = "$uri&modification_date_start=$(Get-Date $ModificationDateStart -Format 'yyyy-MM-dd')"
                    }

                    ModificationDateEnd {
                        $uri = "$uri&modification_date_end=$(Get-Date $ModificationDateEnd -Format 'yyyy-MM-dd')"
                    }

                    ClosedDateStart {
                        $uri = "$uri&closed_date_start=$(Get-Date $ClosedDateStart -Format 'yyyy-MM-dd')"
                    }

                    ClosedDateEnd {
                        $uri = "$uri&closed_date_end=$(Get-Date $ClosedDateEnd -Format 'yyyy-MM-dd')"
                    }

                    #endregion Filter parameters (used once)

                    #region Filter Parameters (multiple values)


                    CallerId {
                        foreach ($g in $CallerId) {
                            $uri = "$uri&caller=$g"
                        }
                    }

                    OperatorGroupId {
                        foreach ($g in $OperatorGroupId) {
                            $uri = "$uri&operator_group=$g"
                        }
                    }

                    OperatorId {
                        foreach ($g in $operatorId) {
                            $uri = "$uri&operator=$g"
                        }
                    }

                    ProcessingStatusId {
                        foreach ($g in $ProcessingStatusId) {
                            $uri = "$uri&processing_status=$g"
                        }
                    }

                    MainIncidentId {
                        foreach ($g in $MainIncidentId) {
                            $uri = "$uri&main_incident_id=$g"
                        }
                    }

                    Status {
                        foreach ($g in $status) {
                            $uri = "$uri&status=$g"
                        }
                    }

                    CallerBranchId {
                        foreach ($g in $CallerBranchId) {
                            $uri = "$uri&caller_branch=$g"
                        }
                    }

                    ObjectId {
                        foreach ($g in $ObjectId) {
                            $uri = "$uri&object_id=$g"
                        }
                    }


                    ObjectName {
                        foreach ($g in $ObjectName) {
                            $uri = "$uri&object_name=$g"
                        }
                    }

                    LinkedObjectId {
                        foreach ($g in $LinkedObjectId) {
                            $uri = "$uri&linked_object_id=$g"
                        }
                    }

                    LinkedObjectName {
                        foreach ($g in $LinkedObjectName) {
                            $uri = "$uri&linked_object_name=$g"
                        }
                    }

                    ExternalLinkId {
                        foreach ($g in $ExternalLinkeId) {
                            $uri = "$uri&external_link_id=$g"
                        }
                    }

                    ExternalLinkType {
                        foreach ($g in $ExternalLinkType) {
                            $uri = "$uri&external_link_type=$g"
                        }
                    }

                    Id {
                        foreach ($g in $Id) {
                            $uri = "$uri&id=$g"
                        }
                    }

                    ExternalNumber {
                        foreach ($g in $ExternalNumber) {
                            $uri = "$uri&external_number=$g"
                        }
                    }
                }

                #endregion Filter Parameters (multiple values)



                if ($ResultSize -gt 10000) {
                    $pageSize = 10000
                }
                else {
                    $pageSize = $ResultSize
                }

                $uri = $uri.Replace('?&', '?')
                $count = 0
                do {
                    # Add a number to 'unlimited'
                    if ($ResultSize -like 'unlimited') { $ResultSize = 99999999 }
                    $remaining = $ResultSize - $count

                    # 10000 is the most we can get per api call. if -LE 10k is needed then we don't need to loop any more.
                    if ($remaining -le 10000) {
                        $pageSize = $remaining
                        $loopingStatus = 'finished'
                    }

                    # Set the uri each time we loop because we need to increase the start
                    $loopingUri = "$uri&start=$Start&page_size=$pageSize"
                    $Params = @{
                        'uri' = $loopingUri
                    }

                    # grab the incidents
                    $incidents = Invoke-TdMethod @Params

                    if (($Incidents.count) -eq 1) {
                        $LoopingStatus = 'finished'
                    }

                    foreach ($incident in $incidents) {
                        if ($incident.Number -notlike '') {
                            $Incident | Select-PSFObject -Typename 'TOPdeskPS.Incident' -KeepInputObject
                        }
                    }
                    $count += $incidents.count
                    $start += $PageSize
                }
                until ($loopingStatus -like 'finished')
            }

            Number {
                foreach ($num in $Number) {
                    $uri = "$uri/number/$($num.ToLower())"
                    $Params = @{
                        'uri' = $uri
                    }

                    Invoke-TdMethod @Params |
                    Foreach-Object {
                        # add the type to the result
                        $_ | Select-PSFObject -Typename 'TOPdeskPS.Incident' -KeepInputObject
                    }
                }
            }
        }
    }
}



function Get-TdIncidentAction {
    <#
    .SYNOPSIS
       Gets actions from an incident
    .DESCRIPTION
        Returns all actions for an incident.
    .PARAMETER Number
        This is the incident number.
	.PARAMETER PageSize
		The amount of actions to be returned per request. The default value is 10 and the maximum value is 100.

	.PARAMETER Start
		This is the offset at which you want to start listing actions. This is useful if you want to grab more than 100.
		The default value is 0.

    .EXAMPLE
        PS C:\> Get-TdIncidentAction -Number 'i123-1234'
        Grabs all actions from incident with number 'i123-1234

    #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdIncidentAction')]
    param (
        [Parameter(
            Mandatory, ValueFromPipelineByPropertyName
        )]
        [string]
        $Number,

        [ValidateRange(1, 100)]
        [int]
        $PageSize = 100,

        [int]
        $Start = 0
    )
    process {
        Write-PSFMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -Level Debug
        foreach ($num in $Number) {
            $incidentActionURL = (Get-TdUrl) + "/tas/api/incidents/number/$num/actions"
            Write-PSFMessage -Level debug -Message "IncidentActionUrl: $incidentActionUrl"
            $uri = "$incidentActionUrl/?start=$Start&page_size=$PageSize"
            $Params = @{
                'uri' = $uri
            }
            $actions = Invoke-TdMethod @Params
            $actions
        }
    }

}


function Get-TdIncidentTimeSpent {
    <#
.SYNOPSIS
    Retrieves time spent on an incident
.DESCRIPTION
    Retrieves time spent on an incident

.PARAMETER Number
    The number of the incident that you want to retrieve time spent for.

.EXAMPLE
    PS > Get-TdIncident | Get-TdIncidentTimeSpent
    Returns time spent for the provided incidents

.EXAMPLE
    PS > Get-TdIncidentTimeSpent i1811-123
    returns time spent for i1811-123
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdIncidentTimeSpent')]

    param
    (
        [Parameter(
            ValueFromPipelinebypropertyname = $true,
            position = 0)]
        [Alias('IncidentNumber')]
        [string[]]
        $Number
    )

    process {
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level InternalComment

        foreach ($num in $number) {
            $uri = "$(Get-TdUrl)/tas/api/incidents/number/$($num.tolower())/timespent"
            $res = Invoke-TdMethod -Uri $uri
            $res
        }
    }

}



function Get-TdPriority {
    <#
    .SYNOPSIS
        Gets priorities
    .DESCRIPTION
        Gets priorities
     .PARAMETER Name
        Name of the priority that you want returned. Wildcards are supported. Default value is '*'
    .EXAMPLE
        PS C:\> Get-TdPriority
        Gets list of all priorities

    #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdPriority')]
    param (
        [string]$Name = '*'
    )
    $uri = (Get-TdUrl) + '/tas/api/incidents/priorities'
    $Params = @{
        'uri' = $uri
    }
    $res = Invoke-TdMethod @Params
    $res | Where-Object name -like $Name
}


function Get-TdProcessingStatus {
    <#
    .SYNOPSIS
        Gets processing statuses
    .DESCRIPTION
        Gets processing statuses
    .PARAMETER Name
        Name of the processing status that you want returned. Wildcards are supported. Default value is '*'
    .EXAMPLE
        PS C:\> Get-TdProcessingStatus
        Gets list of all processing statuses

    #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdProcessingStatus')]
    param (
        [string]$Name = '*'
    )
    $uri = (Get-TdUrl) + '/tas/api/incidents/processing_status'
    $Params = @{
        'uri' = $uri
    }
    $res = Invoke-TdMethod @Params
    $res | Where-Object name -like $Name
}


function Get-TdServiceWindow {
    <#
    .SYNOPSIS
        Gets all service windows
    .DESCRIPTION
            Gets all service windows
        .PARAMETER Name
        Name of the service window that you want returned. Wildcards are supported. Default value is '*'

    .EXAMPLE
        PS C:\> Get-TdServiceWindow
        Gets list of all service windows
    .EXAMPLE
        PS> Get-TdServiceWindow Window1
        Returns the window1 service windows

    #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdServiceWindow')]
    param (
        [system.string]$Name = '*'
    )
    $uri = (Get-TdUrl) + '/tas/api/serviceWindow/lookup/'
    $res = Invoke-TdMethod $uri
    $res | Where-Object name -like $Name
}


function Get-TdSubcategory {
    <#
	.SYNOPSIS
		Get subcategories from TOPdesk

	.DESCRIPTION
		Gets either one subcategory or a list of subcategories from TOPdesk.

    .PARAMETER Name
        Name of the subcategory that you want returned. Wildcards are supported. Default value is '*'

	.EXAMPLE
		PS C:\> Get-TdSubcategory
		Gets a list of all subcategories

	.EXAMPLE
		PS C:\> Get-TdSubcategory -Name 'Applications'
		Gets the Subcategory with the name 'Applications'

#>

    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/TOPdeskPS/Get-TdSubcategory')]
    param
    (
        [String]
        $Name = '*'
    )
    $SubcategoryURL = (Get-TdUrl) + '/tas/api/incidents/subcategories'
    $Subcategories = Invoke-TdMethod $SubcategoryURL
    $Subcategories | Where-Object name -like $name
}


function Get-TdTimeSpentReason {
    <#
    .SYNOPSIS
        Gets all time spent reasons
    .DESCRIPTION
            Gets all time spent reasons
    .PARAMETER Name
        Name of the time spent reason that you want returned. Wildcards are supported. Default value is '*'

    .EXAMPLE
        PS C:\> Get-TdTimeSpent
        Gets all time spent reasons

    #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdTimeSpentReason')]
    param (
        [string]$Name = '*'
    )

    $uri = (Get-TdUrl) + '/tas/api/timespent-reasons'
    $res = Invoke-TdMethod $uri
    $res | where-object name -like $name
}


function Get-TdUrgency {
    <#
    .SYNOPSIS
        Gets list of all urgencies
    .DESCRIPTION
        Gets list of all urgencies
    .PARAMETER Name
        Name of the urgency that you want returned. Wildcards are supported. Default value is '*'

    .EXAMPLE
        PS C:\> Get-TdUrgency
        Gets list of all urgencies

    .EXAMPLE
        PS> Get-TdUrgency -name 'Able to work'
        Returns the requested urgency

    #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdUrgency')]
    param (
        [parameter (position = 0)]
        [string]
        $Name = '*'
    )
    $uri = (Get-TdUrl) + '/tas/api/incidents/urgencies'
    $res = Invoke-TdMethod $uri
    $res | Where-Object name -like $Name | Select-PSFObject -Typename 'TOPdeskPS.BasicObj' -KeepInputObject
}


function Get-TdUrl {
    <#
	.SYNOPSIS
		Grabs the TOPdesk url from the config system using Get-PSFConfigValue

	.DESCRIPTION
		Grabs the TOPdesk url from the config system using Get-PSFConfigValue

	.EXAMPLE
		PS C:\> Get-TdUrl
		Grabs the TOPdesk url from the config system using Get-PSFConfigValue -Fullname TOPdeskPS.Url

#>

    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdUrl')]
    param ()

    begin {
        Write-PSFMessage -Level InternalComment -Message "Bound parameters: $($PSBoundParameters.Keys -join ", ")" -Tag 'debug', 'start', 'param'
    }
    process {
        try {
            Get-PSFConfigValue -FullName TOPdeskPS.Url -NotNull
        }
        catch {
            throw 'Unable to find your TOPdesk url. Try running Connect-TdService -Url "https://yourtopdeskurl".'
        }
    }
    end {
    }
}


function Invoke-TdMethod {
    <#
	.SYNOPSIS
		Wrapper for Invoke-RestMethod. This command is exposed in case you encounter api calls that aren't part of this module. All api commands call this command to perform the web request.

	.DESCRIPTION
		A detailed description of the Invoke-TdMethod function.

	.PARAMETER ContentType
		default for contenttype is application/json . You may need to use a different contenttype for uploading files.

	.PARAMETER Uri
		the uri that you are targeting

	.PARAMETER Body
		The body of the request to be sent to TOPdesk. Accepts a PSCustomObject. If you also specify a file we will convert the body into a multipart/form request.

	.PARAMETER Method
		The method that you want to pass

	.PARAMETER Token
        Custom Api token if you want to avoid using Connect-TdService ex:'TOKEN id="Token id="Base64encodedToken

    .PARAMETER File
    path to the file that you want to upload. If you specify a body then we will construct a multipart/form request.
    In Windows PowerShell this functionality isn't built in.
    If no body is specified then we will just use the -infile parameter of Invoke-RestMethod

	.EXAMPLE
		PS C:\> Invoke-TdMethod -Token $Token -Body $Body
		Sends a Get request to your TOPdesk instance.

#>

    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/TOPdeskPS/Invoke-TdMethod')]
    param
    (

        [Parameter(Mandatory, Position = 0)]
        [uri]
        $Uri,

        [string]
        $ContentType = 'application/json' ,

        [pscustomobject]
        $Body,

        [ValidateSet('Get', 'Set', 'Put', 'Patch', 'Delete', 'Post', 'Head', 'Merge', 'Options')]
        [string]
        $Method = 'Get',

        [string]
        $Token,

        [Parameter(ParameterSetName = 'File')]
        [Alias('InFile')]
        [ValidateScript( {
                if (-Not ($_ | Test-Path)) {
                    throw "File or folder does not exist"
                }
                if (-Not ($_ | Test-Path -PathType Leaf)) {
                    throw "The Path argument must be a file. Folder paths are not allowed."
                }
                if (-Not (Get-Item $_)) {
                    throw "Cannot find path $($_)"
                }
                return $true
            })]
        [system.io.fileinfo]
        $File
    )

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level InternalComment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level InternalComment

        if ($Token) {
            $Headers = @{
                'Authorization' = $Token
            }
        }
        else {
            if (-not $Script:__LoginToken) {
                throw 'no connection to topdesk, try running Connect-TdService'
            }
            else {
                $Headers = @{
                    'Authorization' = $Script:__LoginToken
                }
            }
        }

        Switch ($PSCmdlet.ParameterSetName) {
            '__AllParameterSets' {
                $Params = @{
                    'Body' = $Body
                    'Method' = $Method
                    'Uri' = $Uri
                    'Headers' = $Headers
                }
                if ($ContentType) {
                    $params.contenttype = $contenttype
                }
                Write-PSFMessage -Level InternalComment -Message "Params to be bassed to IRM: $($params.Keys -join ",")"
                Invoke-RestMethod @Params

            }


            'File' {

                switch ($PSVersionTable.PSVersion.Major) {
                    5 {
                        #TOPdesk always want a multipart request for files from what I've seen.

                        # Use fiddler to troubleshoot this.
                        # We are going to generate webrequest

                        Add-Type -AssemblyName System.web

                        $boundary = [System.Guid]::NewGuid().ToString()

                        # determine content type
                        $mimeType = [System.Web.MimeMapping]::GetMimeMapping($File)

                        if ($mimeType) {
                            $ContentType = $mimeType
                        }
                        else {
                            $ContentType = "application/octet-stream"
                        }



                        $fileBin = [System.IO.File]::ReadAllBytes($File)
                        $enc = [System.Text.Encoding]::GetEncoding("iso-8859-1")
                        $fileEnc = $enc.GetString($fileBin)

                        $LF = "`r`n"
                        $fileName = Split-Path $File -leaf

                        # composed contains all lines of our web request
                        $composedBody = @()

                        # Loop through all members of the body and add their values to the request.
                        $bodyMembers = $body.psobject.Members | where-object membertype -like 'noteproperty'
                        foreach ($b in $bodyMembers ) {
                            $composedBody += "--$boundary"
                            $composedBody += "Content-Type: text/plain; charset=utf-8"
                            $composedBody += "Content-Disposition: form-data; name=$($b.name)$LF"
                            $composedBody += "$($b.value)"
                        }


                        # now we add the actual content of the of file
                        $composedBody += (
                            "--$boundary",
                            "Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`"",
                            "Content-Type: $ContentType$LF",
                            $fileEnc,
                            "--$boundary--$LF"
                        ) -join $LF


                        $composedBody = $composedBody -join $LF
                        $params = @{
                            uri = $Uri
                            Method = $Method
                            ContentType = "multipart/form-data; boundary=`"$boundary`""
                            Body = $composedBody
                            Headers = $Headers
                        }
                        Invoke-RestMethod @params

                    }


                    6 {

                        $form = @{
                            file = Get-Item $file
                        }

                        $bodyMembers = $body.psobject.Members | where-object membertype -like 'noteproperty'
                        foreach ($b in $bodyMembers) {
                            $form.add( "$($b.name)", "$($b.Value)")
                        }
                        $params = @{
                            Uri = $uri
                            Method = $Method
                            Form = $Form
                            Headers = $Headers
                        }
                        Invoke-RestMethod @params

                    }



                }

            }
        }
    }
}



function New-TdIncident {
    <#
.SYNOPSIS
		Creates a new incident

.DESCRIPTION
		This command creates a new incident in TOPdesk

.PARAMETER Action
		Initial action.
		The following html tags can be used to format the text:

		<i>
		<em>
		<b>
		<strong>
		<u>
		<a>
		<img> BASE64-encoding has to be used. Only pictures up to the size of 450x450 pixels are supported. Allowed picture-formats:
		gif, png, bmp, pcx, iff, ras, pnm, psd, jpg
		Example:
		<img src="data:image/png;base64,iVBORw0KGgoAAA...">

		Line breaks can be added via <br> tags and are automatically added after a closing <p> or <div>.
        Can be set by operators and persons.

.PARAMETER ActionInvisibleForCaller
        Whether the initial action is invisible for persons.
        Can only be set by operators.
        Default value is false

.PARAMETER CallTypeId
Call type by id.
Can be set by operators.
Cannot be provided for partials as its automatically copied from the main incident.
Can be set by persons only when the appropriate setting for the new call form is checked.

.PARAMETER BriefDescription
		Brief description for the incident. This can be set by operators.
		For partials, if not provided, will be automatically copied from the main incident.
		Can be set by persons only when the appropriate setting for the new call form is checked.

.PARAMETER CallerLookupEmail
        This is the email of the incident's caller. TOPdesk will fill the caller's details into the incident automatically.

        Lookup value for filling in a registered caller's contact details.
Can only be set by operators.
Cannot be provided for partials as its automatically copied from the main incident.
The caller is filled in automatically for persons.

.PARAMETER CallerLookupId
Id of the caller.

.PARAMETER EntryTypeId
Entry type by id.
Can only be set by operators.

.PARAMETER Status
		Status of the incident. Available values:
		FirstLine
		SecondLine
        Partial

.PARAMETER Request
		The initial request for the incident. You will likely want to use a here-string to construct the request of the incident.

		Line breaks can be added via <br> tags and are automatically added after a closing <p> or
		The following html tags can be used to format the text:

		<i>
		<em>
		<b>
		<strong>
		<u>
		<a>
		<img> BASE64-encoding has to be used. Only pictures up to the size of 450x450 pixels are supported. Allowed picture-formats:
		gif, png, bmp, pcx, iff, ras, pnm, psd, jpg

.PARAMETER Category
Category by name.
Can be set by operators.
For partials, if not provided, will be automatically copied from the main incident.
Can be set by persons only when the appropriate setting for the new call form is checked.
It is an error to provide both an id and a name.

.PARAMETER Subcategory
	Subcategory by name.
Can be set by operators.
For partials, if not provided, will be automatically copied from the main incident.
Can be set by persons only when the appropriate setting for the new call form is checked.
It is an error to provide both an id and a name. If a subcategory is provided without a category, the corresponding category will be filled in automatically, unless there are multiple matching categories, in which case the request will fail.

.PARAMETER ExternalNumber
External number.
Can only be set by operators.
For partials, if not provided, will be automatically copied from the main incident.

.PARAMETER MainIncidentId
Main incident id, required for creating a partial incident.
This must be an open, unarchived second line incident and visible to the operator.
It is an error to provide a main incident for non-partial incidents.
Can only be set by operators.

.PARAMETER ObjectName

Object by name.
Can be set by operators.
Cannot be provided for partials as its automatically copied from the main incident.
Can be set by persons only when the appropriate setting for the new call form is checked.

.PARAMETER LocationId

Location by id.
Can be set by operators.
Cannot be provided for partials as its automatically copied from the main incident.
Can be set by persons only when the appropriate setting for the new call form is checked.

.PARAMETER ImpactId
Impact by id.
Can only be set by operators.
Cannot be provided for partials as its automatically copied from the main incident.

.PARAMETER UrgencyId
Urgency by id.
Can only be set by operators.
Cannot be provided for partials as its automatically copied from the main incident.

.PARAMETER PriorityId
Priority by id.
Can only be set by operators.
Cannot be provided for partials as its automatically copied from the main incident.
Will be automatically filled in if you provide impact and/or urgency leading to a unique priority according to your priority matrix, and the same request doesn't provide a priority. For incidents with a linked SLA, if the priority provided cannot be found in the Service Level Priority List, the duration field of the incident will be emptied.

.PARAMETER DurationId
Duration by id.
Can only be set by operators.

.PARAMETER TargetDate
Target date.
Can only be set by operators.
Example: "targetDate" : "2015-11-15T14:00:00.000+0200"
The given time offset will be used. Without a given offset Zulu/UTC time will be assumed. E.g. 2015-10-28T10:30:00.000 is equivalent to 2015-10-28T10:30:00.000+0000

.PARAMETER OperatorId
Operator by id.
Can only be set by operators.
For partials, if not provided, will be automatically copied from the main incident.

.Parameter OperatorGroupId
Operator group by id.
Can be set by operators.
For partials, if not provided, will be automatically copied from the main incident.
Can be set by persons only when the appropriate setting for the new call form is checked.

.PARAMETER SupplierId
Supplier by id.
Can only be set by operators

.PARAMETER ProcessingStatusId
ProcessingStatus by id.
Can only be set by operators

.PARAMETER Responded

Whether the incident is responded.
SLM-licence is needed.
Can only be set by operators. When the setting "Status determines responded" is on, this will be filled automatically (manual setting is prohibited).

.PARAMETER ResponseDate
Response date.
SLM-licence is needed.
Can only be set by operators.
Will automatically be set to current date if left out and "responded : true" is set.
Example: "responseDate" : "2015-11-15T14:00:00.000+0200"
The given time offset will be used. Without a given offset Zulu/UTC time will be assumed. E.g. 2015-10-28T10:30:00.000 is equivalent to 2015-10-28T10:30:00.000+0000

.PARAMETER Completed
Whether the incident is completed.
Can only be set by operators.

.PARAMETER CompletedDate
Whether the incident is completed.
Can only be set by operators.

.PARAMETER Closed
Whether the incident is closed.
Can only be set by operators.
For partials, will be ignored. The value of completed will be used instead.

.PARAMETER ClosedDate
Closed date.
Can only be set by operators.
For partials, will be ignored. The value of completedDate will be used instead.
Example: "closedDate" : "2018-11-15T14:00:00.000+0200"
The given time offset will be used. Without a given offset Zulu/UTC time will be assumed. E.g. 2018-10-28T10:30:00.000 is equivalent to 2018-10-28T10:30:00.000+0000

.PARAMETER ClosureCodeId
Closure code by id.
Can only be set by operators.

.PARAMETER Costs
Costs.
Can only be set by operators.

.PARAMETER SlaId
SLA by id.
Can only be set by operators.

.PARAMETER OnHold
Specify whether the incident is on hold. On hold date will be filled accordingly. can only be set by operators.

.PARAMETER CallerPhoneNumber
Phone number of the caller.
Can only be set by operators.

.PARAMETER CallerMobileNumber
Mobile phone number of the caller.
Can only be set by operators.

.PARAMETER CallerEmail
Email of the caller.
Can only be set by operators.

.PARAMETER CallerDepartmentId
Department of the caller by id.
Can only be set by operators.

.PARAMETER CallerLocationId
Location of the caller by id.
Can only be set by operators.

.PARAMETER CallerBudgetHolderId
Budget holder of the caller by id.
Can only be set by operators.

.PARAMETER CallerPersonExtraFieldAId
Person extra a of the caller by id.
Can only be set by operators.

.PARAMETER CallerPersonExtraFieldBId
Person extra b of the caller by id.
Can only be set by operators.

.PARAMETER CallerBranchId
The caller branch by id. can only be set by operators.

.PARAMETER MajorCall
Whether the incident is a major call.
Can only be set by operators.

.PARAMETER MajorCallObjectId
Major call by id.
Can only be set by operators.

.PARAMETER PublishToSsd
Whether the incident should be published in the Self Service Desk; only major incidents can be published.
Can only be set by operators.

.PARAMETER Confirm
	If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

.PARAMETER WhatIf
		If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

.EXAMPLE
		PS > New-TdIncident -CallerLookupEmail 'user@Company.net' -Action 'Initial Action' -BriefDescription 'Example Incident' -Request 'Printer Assistance'
        This creates a basic incident for the Caller 'user@Company.net'

.EXAMPLE
    PS > New-TdIncident -CallerLookupEmail 'user@company.net' -Request 'Incident Request' -OperatorGroupId (Get-TdOperatorGroup 'TechSupport').id
    Creates a new incident and and assigns it to the Techsupport operator group
#>

    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/TOPdeskPS/New-TdIncident',
        SupportsShouldProcess = $true)]
    param
    (
        [string]
        $Action,

        [switch]
        $ActionInvisibleForCaller,

        [string]
        $EntryTypeId,

        [string]
        $CallTypeId,

        [string]$ObjectName,

        [string]$LocationId,

        [string]$ExternalNumber,

        [string]$Subcategory,

        [string]$MainIncidentId,

        [ValidateCount(0, 80)]
        [string]
        $BriefDescription,

        [Parameter()]
        [PSFValidatePattern('\w+([-+.'''''''']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*', ErrorMessage = '{0} is not a valid email address.')]
        [string]
        $CallerLookupEmail,


        [Alias('CallerId')]
        [string]
        $CallerLookupId,


        [ValidateSet('firstLine', 'secondLine', 'partial')]
        [string]
        $Status = 'firstLine',

        [string]
        $Request,

        [string]
        $CallerBranchId,

        [string]
        $Category,

        [string]$ImpactId,

        [string]$UrgencyId,

        [string]$PriorityId,

        [string]$DurationId,

        [string]$TargetDate,

        [string]$SlaId,

        [switch]$OnHold,


        # Processing

        [string]$OperatorId,

        [string]$OperatorGroupId,

        [string]$SupplierId,

        [string]$ProcessingStatusId,

        [switch]$Responded,

        [string]$ResponseDate,

        [switch]$Completed,

        [string]$CompletedDate,

        [string]$Closed,

        [string]$ClosedDate,

        [string]$ClosureCodeId,

        [string]$Costs,




        # Construct caller body



        [string]
        $CallerPhoneNumber,

        [string]
        $CallerMobileNumber,

        [string]
        $CallerEmail,

        [string]$CallerDepartmentId,

        [string]$CallerLocationId,

        [string]$CallerBudgetHolderId,

        [string]$CallerPersonExtraFieldAId,

        [string]$CallerPersonExtraFieldBId,

        # end construct caller body


        # Major Call
        [switch]$MajorCall,

        [string]$MajorCallObjectId,

        [switch]$PublishToSsd

    )

    begin {
        $IncidentURL = (Get-TdUrl) + '/tas/api/incidents'
    }

    process {
        Write-PSFMessage -Level InternalComment -Message "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-PSFMessage -Level InternalComment -Message "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"


        $Body = [PSCustomObject]@{ }
        $callerBody = [pscustomobject]@{ }

        switch ($PSBoundParameters.Keys) {
            Action {
                $Body | Add-Member -MemberType NoteProperty -Name 'action' -Value $Action
            }
            ActionInvisibleForCaller {
                $Body | Add-Member -MemberType NoteProperty -Name 'actionInvisibleForCaller' -Value $ActioninvisibleForCaller.tostring().tolower()
            }
            BriefDescription {
                $Body | Add-Member -MemberType NoteProperty -Name 'briefDescription' -Value $BriefDescription
            }
            EntryTypeId {
                $obj = [pscustomobject]@{
                    id = $EntryTypeId
                }
                $Body | Add-Member -MemberType NoteProperty -Name 'entryType' -Value $obj
            }

            ExternalNumber {
                $Body | Add-Member -MemberType NoteProperty -Name 'externalNumber' -Value $ExternalNumber
            }

            MainIncidentId {
                $Body | Add-Member -MemberType NoteProperty -Name 'mainIncident' -Value (
                    [pscustomobject]@{ id = $MainIncidentId } )
            }
            CallTypeId {
                $Body | Add-Member -Membertype NoteProperty -Name 'callType' -Value ([pscustomobject]@{id = $CallTypeId })
            }
            Status {

                # Make sure that the case is set properly
                switch ($Status) {
                    'firstline' {
                        $status = 'firstLine'
                    }
                    'secondline' {
                        $status = 'secondLine'
                    }
                    'partial' {
                        $status = 'partial'
                    }
                }

                $Body | Add-Member -MemberType NoteProperty -Name 'status' -Value $Status
            }
            Request {
                $Body | Add-Member -MemberType NoteProperty -Name 'request' -Value $Request

            }

            Subcategory {
                $SubcategoryValue = @{
                    name = $Subcategory
                }
                $Body | Add-Member -MemberType NoteProperty -Name 'subcategory' -Value $SubcategoryValue
            }
            Category {
                $CategoryValue = @{
                    name = $Category
                }
                $Body | Add-Member -MemberType NoteProperty -Name 'category' -Value $CategoryValue
            }

            #region Object/location

            ObjectName {
                $Body | Add-Member -MemberType NoteProperty -Name 'object' -Value (
                    [pscustomobject]@{ name = $ObjectName })
            }

            LocationId {
                $Body | Add-Member -MemberType NoteProperty -Name 'location' -Value (
                    [pscustomobject]@{ id = $LocationId }
                )
            }

            #endregion Object/location

            #region Processing
            OperatorId {
                $Body | Add-Member -Membertype NoteProperty -Name 'operator' -Value (
                    [pscustomobject]@{id = $OperatorId })
            }
            OperatorGroupId {
                $Body | Add-Member -Membertype NoteProperty -Name 'operatorGroup' -Value (
                    [pscustomobject]@{id = $operatorGroupId })
            }
            SupplierId {
                $Body | Add-Member -Membertype NoteProperty -Name 'supplier' -Value (
                    [pscustomobject]@{id = $SupplierId })
            }
            ProcessingStatusId {
                $Body | Add-Member -Membertype NoteProperty -Name 'processingStatus' -Value (
                    [pscustomobject]@{id = $ProcessingStatusId })
            }
            Responded {
                $Body | Add-Member -Membertype noteproperty -name 'responded' -Value $Responded.tostring().tolower()
            }
            ResponseDate {
                $Body | Add-Member -Membertype NoteProperty -Name 'responseDate' -Value $ResponseDate
            }
            Completed {
                $Body | Add-Member -Membertype noteproperty -name 'completed' -Value $Completed.tostring().tolower()
            }
            CompletedDate {
                $Body | Add-Member -Membertype NoteProperty -Name 'completedDate' -Value $CompletedDate
            }
            Closed {
                $Body | Add-Member -Membertype noteproperty -name 'Closed' -Value $Closed.tostring().tolower()
            }
            ClosedDate {
                $Body | Add-Member -Membertype NoteProperty -Name 'closedDate' -Value $ClosedDate
            }
            ClosureCodeId {
                $Body | Add-Member -Membertype NoteProperty -Name 'closureCode' -Value (
                    [pscustomobject]@{id = $ClosureCodeId })
            }
            Costs {
                $Body | Add-Member -Membertype NoteProperty -Name 'costs' -Value $Costs
            }
            #endregion Processing


            #region Planning

            ImpactId {
                $Body | Add-Member -MemberType NoteProperty -Name 'impact' -Value (
                    [pscustomobject]@{ id = $ImpactId })
            }


            UrgencyId {
                $Body | Add-Member -MemberType NoteProperty -Name 'urgency' -Value (
                    [pscustomobject]@{ id = $urgencyId })
            }
            PriorityId {
                $Body | Add-Member -MemberType NoteProperty -Name 'priority' -Value (
                    [pscustomobject]@{ id = $PriorityId })
            }
            DurationId {
                $Body | Add-Member -MemberType NoteProperty -Name 'duration' -Value (
                    [pscustomobject]@{ id = $DurationId })
            }
            TargetDate {
                $Body | Add-Member -MemberType NoteProperty -Name 'targetDate' -Value $TargetDate
            }
            SlaId {
                $Body | Add-Member -MemberType NoteProperty -Name 'sla' -Value (
                    [pscustomobject]@{ id = $SlaId })
            }
            OnHold {
                $Body | Add-Member -MemberType NoteProperty -Name 'onHold' -Value $Onhold.tostring().tolower()
            }

            #endregion Planning

            #region callerLookup Construction

            CallerLookupEmail {
                $Body | Add-Member -MemberType NoteProperty -Name 'callerLookup' -Value (
                    [pscustomobject]@{ email = $CallerLookupEmail }
                )
            }

            CallerLookupId {
                $Body | Add-Member -MemberType NoteProperty -Name 'callerLookup' -Value (
                    [pscustomobject]@{ id = $CallerLookupId }
                )
            }

            #endregion callerLookup construction

            #region Major Call
            MajorCall {
                $Body | Add-Member -MemberType NoteProperty -Name 'majorCall' -Value $Majorcall.tostring().tolower()
            }
            MajorCallObjectId {
                $Body | Add-Member -MemberType NoteProperty -Name 'majorCallObject' -Value (
                    [pscustomobject]@{ id = $MajorCallObjectId }
                )
            }
            PublishToSsd {
                $Body | Add-Member -MemberType NoteProperty -Name 'publishToSsd' -Value $PublishToSsd.tostring().tolower()

            }
            #endregion Major Call


            #region Construct CallerBody

            CallerBranchId {
                $obj = [pscustomobject]@{
                    'id' = $callerBranchId
                }

                $callerBody | Add-Member -MemberType noteproperty -Name 'branch' -value $obj
            }

            CallerPhoneNumber {
                $callerBody | Add-Member -MemberType NoteProperty -Name 'phoneNumber' -value $callerPhoneNumber
            }

            CallerMobileNumber {
                $callerBody | Add-Member -MemberType NoteProperty -Name 'mobileNumber' -Value $callerMobileNumber
            }

            CallerEmail {
                $callerBody | Add-Member -MemberType NoteProperty -Name 'email' -Value $callerEmail
            }

            callerDepartmentId {
                $obj = [pscustomobject]@{
                    id = $callerDepartmentId
                }
                $callerBody | Add-Member -MemberType NoteProperty -Name 'department' -Value $obj
            }

            CallerLocationId {
                $obj = [pscustomobject]@{
                    id = $callerlocationId
                }
                $callerBody | Add-Member -MemberType NoteProperty -Name 'location' -Value $obj
            }

            CallerBudgetHolderId {
                $obj = [pscustomobject]@{
                    id = $callerbudgetHolderId
                }
                $callerBody | Add-Member -MemberType NoteProperty -Name 'budgetHolder' -Value $obj
            }

            CallerPersonExtraFieldAId {
                $obj = [pscustomobject]@{
                    id = $callerPersonExtraFieldAId
                }
                $callerBody | Add-Member -MemberType NoteProperty -Name 'personExtraFieldA' -Value $obj
            }

            CallerPersonExtraFieldBId {
                $obj = [pscustomobject]@{
                    id = $callerPersonExtraFieldBId
                }
                $callerBody | Add-Member -MemberType NoteProperty -Name 'personExtraFieldB' -Value $obj
            }

            #endregion
        }


        $Body | Add-Member -MemberType NoteProperty -Name 'caller' -Value $callerBody

        $Params = @{
            'Uri' = $IncidentURL
            'Body' = $Body | ConvertTo-Json
            'Method' = 'Post'
        }
        if ($PSCmdlet.ShouldProcess("The Request" , "Creating new incident with body -- `n $($body | ConvertTo-Json)")) {
            Invoke-TdMethod @Params
        }
    }
}


function Send-TdIncidentFile {
    <#
    .SYNOPSIS
        Upload a file to an incident identified
    .DESCRIPTION
        Upload a file to an incident. You can make the file invisible to the caller and you can also add a description.
    .PARAMETER Number
        The number of the incident that you want to upload a file to.
    .PARAMETER File
        File that you want to upload.
    .PARAMETER InvisibleForCaller
        Whether you want to make this invisible to caller or not. The default is no.
    .PARAMETER Description
        Provide a description for the file.
    .EXAMPLE
        PS> Send-TdIncidentFile -File 'C:\TestFile.txt' -Number 'I1911-123' -InvisibleforCaller
        Uploads a file to an incident. and makes it invisible for caller.
    .EXAMPLE
        PS> Send-TdIncidentFile -File 'C:\ScanResult.txt' -Number 'I1911-123' -Description "Copy of the scan results from the target machine"
        Uploads a file to an incident with a description.
    #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Send-TdIncidentFile')]
    param (

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]
        $Number,

        [Parameter(Mandatory, ValueFromPipeline, ValuefromPipelineByPropertyName)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path)) {
                    throw "File or folder does not exist"
                }
                if (-Not ($_ | Test-Path -PathType Leaf)) {
                    throw "The Path argument must be a file. Folder paths are not allowed."
                }
                return $true
            })]
        [System.IO.FileInfo[]]
        $File,

        [Switch]
        $InvisibleForCaller,

        [string]
        $Description
    )

    process {
        $Body = [PSCustomObject]@{}

        foreach ($f in $File) {
            $Body | Add-Member -Name 'invisibleForCaller' -Value ($InvisibleForCaller.tostring().tolower()) -MemberType NoteProperty


            if ($Description) {
                $Body | Add-Member -Name 'description' -Value $Description -MemberType NoteProperty
            }

            $uri = "$(Get-TdUrl)/tas/api/incidents/number/$($Number.tolower())/attachments"

            $params = @{
                Body = $Body
                Uri = $Uri
                File = "$($f.fullname)"
                Method = 'Post'
            }
            Invoke-TdMethod @params
        }
    }
}


function Set-TdIncident {
    <#
	.SYNOPSIS
		Updates an incident

	.DESCRIPTION
		This command updates various properties of an incident.

	.PARAMETER Number
		Number of the TOPdesk incident that you want to modify.

	.PARAMETER Action
		Add an action.
        The following html tags can be used to format the text:

        <i>
        <em>
        <b>
        <strong>
        <u>
        <a>
        <img> BASE64-encoding has to be used. Only pictures up to the size of 450x450 pixels are supported. Allowed picture-formats:
        gif, png, bmp, pcx, iff, ras, pnm, psd, jpg
        Example:
        <img src="data:image/png;base64,iVBORw0KGgoAAA...">
        Line breaks can be added via <br> tags and are automatically added after a closing <p> or <div>.
        Can be set by operators and persons.

    .PARAMETER ActionInvisibleForCaller
        Whether the added action is invisible for persons.
        Can only be set by operators.

	.PARAMETER BriefDescription
		Brief description for the incident. This can be set by operators.
		For partials, if not provided, will be automatically copied from the main incident.
		Can be set by persons only when the appropriate setting for the new call form is checked.

	.PARAMETER Request
		The initial request for the incident. You will likely want to use a here-string to construct the request of the incident.

		Line breaks can be added via <br> tags and are automatically added after a closing <p> or
		The following html tags can be used to format the text:

		<i>
		<em>
		<b>
		<strong>
		<u>
		<a>
		<img> BASE64-encoding has to be used. Only pictures up to the size of 450x450 pixels are supported. Allowed picture-formats:
		gif, png, bmp, pcx, iff, ras, pnm, psd, jpg

	.PARAMETER Category
		The name of the category for the incident. Can be set by operators. If not provided to partial incidents, the category will be automatically copied from the main incident.

	.PARAMETER Subcategory
		The name of the category for the incident. Can be set by operators.
		If a subcategory is provided without a category, the corresponding category will be filledi n automatically, unless there are multiple matching categories, in which case the request will fail.
		If not provided to partial incidents, the category will be automatically copied from the main incident.

	.PARAMETER CallerEmail
        This is the email of the incident's caller. TOPdesk will fill the caller's details into the incident automatically.

    .PARAMETER EntryType
        Entry type by id.
        Can only be set by operators.

    .PARAMETER CallType
        Call type by id.
        Can only be set by operators.
        For partial incidents, this field is determined by the main incident and will give an error if provided in the request.

    .PARAMETER CallerBranch
        The caller branch by id.
        Can only be set by operators.

    .PARAMETER CallerEmail
        Email of the caller.
        Can only be set by operators

    .PARAMETER ClosureCode
        Closure code by id or name.
        Can only be set by operators.

    .PARAMETER Impact
        Impact by id.
        Can only be set by operators.
        For partial incidents, this field is determined by the main incident and will give an error if provided in the request.

    .PARAMETER Urgency
        Urgency by id.
        Can only be set by operators.
        For partial incidents, this field is determined by the main incident and will give an error if provided in the request.

    .PARAMETER Priority
    Priority by id.
    Can only be set by operators.
    For partial incidents, this field is determined by the main incident and will give an error if provided in the request.
    Will be automatically filled in if you provide impact and/or urgency leading to a unique priority according to your priority matrix, and the same request doesn't provide a priority. For incidents with a linked SLA, if the priority provided cannot be found in the Service Level Priority List, the duration field of the incident will be emptied.

    .PARAMETER ObjectId
        Object by id.
        Can only be set by operators.
        For partial incidents, this field is determined by the main incident and will give an error if provided in the request.

    .PARAMETER LocationId
        Location by id.
        Can only be set by operators.
        For partial incidents, this field is determined by the main incident and will give an error if provided in the request.

    .PARAMETER Operator

Operator by id.
Can only be set by operators.

.PARAMETER OperatorGroup
    Operator group by id.
Can only be set by operators.

.PARAMETER Supplier
    Supplier by id.
Can only be set by operators.
Cannot be filled in if the incident has a supplier service linked.

.PARAMETER ProcessingStatus
Processing status by id.
Can only be set by operators.

.PARAMETER Responded

Whether the incident is responded.
SLM-licence is needed.
Can only be set by operators. When the setting "Status determines responded" is on, this will be filled automatically (manual setting is prohibited).

.PARAMETER Completed
Whether the incident is completed.
Can only be set by operators.

.PARAMETER Closed
Whether the incident is closed.
Can only be set by operators and persons.

.PARAMETER Costs
Costs
Can only be set by operators.

.PARAMETER Duration

Duration by id.
Can only be set by operators.
Cannot be filled in if the incident has a supplier service linked.

    .PARAMETER TargetDate
    Target date. This includes the timezone information from the provided object.
Can only be set by operators.
Cannot be filled in if the incident has a supplier service linked.

    .PARAMETER OnHold
    sets the ticket to onhold.
    Can only be set by operators.

    .PARAMETER MajorCall
        Whether the incident is a major call.
        Can only be set by operators.

    .PARAMETER MajorCallObject
        Major call by id.
        Can only be set by operators.

    .PARAMETER PublishToSsd
        Whether the incident should be published in the Self Service Desk, only major incidents can be published.
        Can only be set by operators.

    .PARAMETER ExternalNumber
        External number.
        Can only be set by operators.

	.PARAMETER Confirm
		If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

	.PARAMETER WhatIf
		If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

	.EXAMPLE
		PS C:\> Set-TdIncident -IncidentNumber 'I1805-221' -Action 'Example Action'
		Updates incident I1805-221 with the action 'Example Action'
#>

    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/TOPdeskPS/Set-TdIncident',
        SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            position = 0)]
        [string]
        $Number,

        [string]
        $Action,

        [switch]
        $ActionInvisibleForCaller,

        [ValidateCount(0, 80)]
        [string]
        $BriefDescription,

        [string]
        $Request,

        [string]
        $Category,

        [string]
        $Subcategory,

        [PSFValidatePattern('\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*', ErrorMessage = '{0} is not a valid email address.')]
        [string]
        $CallerEmail,

        [string]
        $EntryType,

        [string]
        $ExternalNumber,

        [string]
        $CallerBranch,

        [string]
        $Impact,

        [string]
        $Urgency,

        [string]
        $Priority,

        [string]
        $ObjectId,

        [string]
        $LocationId,

        [string]
        $CallType,

        [string]
        $Operator,

        [string]
        $OperatorGroup,

        [string]
        $Supplier,

        [alias('Status')]
        [string]
        $ProcessingStatus,

        [Switch]
        $Responded,

        [switch]
        $Completed,

        [switch]
        $Closed,

        [string]
        $ClosureCode,

        [single]
        $Costs,

        [string]
        $Duration,

        [datetime]
        $TargetDate,

        [switch]
        $OnHold,

        [switch]
        $MajorCall,

        [string]
        $MajorCallObject,

        [switch]
        $PublishToSsd

    )
    <#TODO


        Responsedate
        completeddate

        closedDate

        feedbackRating
        feedbackMessage


        lots of free fields
        #>

    process {
        Write-PSFMessage -Level InternalComment -Message "ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-PSFMessage -Level InternalComment -Message "PSBoundParameters: $($PSBoundParameters | Out-String)"

        $IncidentURL = (Get-TdUrl) + "/tas/api/incidents/number/$($Number.ToLower())"

        $Body = [PSCustomObject]@{ }
        $callerBody = [PSCustomObject]@{ }

        switch ($PSBoundParameters.Keys) {
            Action {
                $Body | Add-Member -MemberType NoteProperty -Name 'action' -Value $Action
            }
            ActionInvisibleForCaller {
                $Body | Add-Member -MemberType NoteProperty -Name 'actionInvisibleForCaller' -Value ($ActionInvisibleForCaller.tostring().tolower())
            }
            BriefDescription {
                $Body | Add-Member -MemberType NoteProperty -Name 'briefDescription' -Value $BriefDescription
            }
            Status {
                $Body | Add-Member -MemberType NoteProperty -Name 'status' -Value $Status
            }
            Request {
                $Body | Add-Member -MemberType NoteProperty -Name 'request' -Value $Request
            }
            CallerEmail {
                $CallerLookup = @{ 'email' = $CallerEmail }
                $Body | Add-Member -MemberType NoteProperty -Name 'callerLookup' -Value $CallerLookup
            }
            ClosureCode {
                $val = @{id = $ClosureCode }
                $body | Add-Member -MemberType NoteProperty -name 'closureCode' -Value $val
            }
            Subcategory {
                $SubcategoryValue = @{
                    name = $Subcategory
                }
                $Body | Add-Member -MemberType NoteProperty -Name 'subcategory' -Value $SubcategoryValue
            }
            Category {
                $CategoryValue = @{
                    name = $Category
                }
                $Body | Add-Member -MemberType NoteProperty -Name 'category' -Value $CategoryValue
            }
            EntryType {
                $entryTypeValue = @{ id = $entryType }
                $Body | Add-Member -MemberType NoteProperty -Name 'entryType' -Value $EntryTypeValue
            }
            CallType {
                $callTypeValue = @{ id = $CallType }
                $Body | Add-Member -MemberType NoteProperty -Name 'callType' -Value $callTypeValue
            }
            ExternalNumber {
                $Body | Add-Member -MemberType NoteProperty -name 'externalNumber' -Value $ExternalNumber
            }

            Impact {
                $val = @{id = $Impact }
                $Body | Add-Member -MemberType NoteProperty -Name impact -Value $val
            }

            Urgency {
                $val = @{id = $urgency }
                $Body | Add-Member -MemberType NoteProperty -Name urgency -Value $val
            }

            Priority {
                $val = @{id = $Priority }
                $body | Add-Member -MemberType NoteProperty -name priority -Value $val
            }

            ObjectId {
                $val = @{id = $ObjectId }
                $body | Add-Member -MemberType NoteProperty -name object -Value $val
            }

            LocationId {
                $val = @{ id = $LocationId }
                $body | Add-Member -MemberType NoteProperty -name object -Value $val
            }

            Operator {
                $val = @{id = $Operator }
                $body | Add-Member -MemberType NoteProperty -name operator -Value $val
            }

            OperatorGroup {
                $val = @{id = $OperatorGroup }
                $body | Add-Member -MemberType NoteProperty -name operatorGroup -Value $val
            }

            Supplier {
                $val = @{id = $Supplier }
                $body | Add-Member -MemberType NoteProperty -name supplier -Value $val
            }

            ProcessingStatus {
                $val = @{id = $ProcessingStatus }
                $body | Add-Member -MemberType NoteProperty -name processingStatus -Value $val
            }
            Responded {
                $body | Add-Member -MemberType NoteProperty -name responded -Value ($Responded.tostring().tolower())
            }
            Completed {
                $body | Add-Member -MemberType NoteProperty -name completed -Value ($Completed.tostring().tolower())
            }

            Closed {
                $body | Add-Member -MemberType NoteProperty -name closed -Value ($closed.tostring().tolower())
            }

            Costs {
                $body | Add-Member -MemberType NoteProperty -name costs -Value $Costs
            }

            Duration {
                $val = @{id = $Duration }
                $body | Add-Member -MemberType NoteProperty -name duration -Value $val
            }
            TargetDate {
                $d = Get-Date $TargetDate -UFormat "%Y-%m-%dT%H:%M:%S.000%Z00"
                $Body | Add-Member -MemberType NoteProperty -Name targetDate -Value $d
            }

            OnHold {
                $body | Add-Member -MemberType NoteProperty -name onHold -Value ($OnHold.tostring().tolower())
            }

            MajorCall {
                $Body | Add-Member -MemberType NoteProperty -name majorCall -value ($MajorCall.tostring().tolower())
            }

            MajorCallObject {
                $val = @{id = $MajorCallObject }
                $Body | Add-Member -MemberType NoteProperty -Name majorCallObject -Value $val
            }

            PublishToSsd {
                $Body | Add-Member -MemberType NoteProperty -Name publishToSsd -Value ($PublishToSsd.tostring().tolower())
            }

            #region Caller Parameters
            CallerBranch {
                $caller = $true
                $val = @{id = $CallerBranch }
                $callerBody | Add-Member -MemberType NoteProperty -Name branch -Value $val
            }
            CallerEmail {
                $caller = $true
                $callerBody | Add-Member -MemberType NoteProperty -Name email -Value $CallerEmail
            }
            #endregion caller Parameters


        }
        if ($caller) { $Body | Add-Member -MemberType NoteProperty -Name caller -Value $callerBody }

        $Params = @{
            'Uri' = $IncidentURL
            'Body' = $Body | ConvertTo-Json
            'Method' = 'Put'
        }
        if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $IncidentUrl -Action "Sending $($Params.body | out-string) ")) {
            return
        }
        Invoke-TdMethod @Params
    }
}


function Set-TdIncidentTimeSpent {
    <#
.SYNOPSIS
    Register time spent on an incident
.DESCRIPTION
    Update the timespent on an incident. Can also add a note/reason and you can register time for another operator.

.PARAMETER Number
    The number of the incident that you want to update the timespent on.

.PARAMETER TimeSpent
    Time spent in minutes. Can be negative as long as the total registered time on the incident does not go below 0. Can not be 0.

.PARAMETER Notes
    Notes for the entry of registered time spent
.PARAMETER ReasonId
    The reason for the time spent by id.
.PARAMETER OperatorId
    Operator by id. If not set, currently logged in operator will be used.
.PARAMETER OperatorGroupId
    Operator group by id. Must match with the specified operator. If no operator specified, operator group will also be set as the operator.

.PARAMETER EntryDate
    Date for when the time spent should be registered. If not set, will be set to the current time.
"2015-11-15T14:00:00.000+0200"
The given time offset will be used. Without a given offset Zulu/UTC time will be assumed. E.g. 2015-10-28T10:30:00.000 is equivalent to 2015-10-28T10:30:00.000+0000
.PARAMETER Confirm
    If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
.PARAMETER WhatIf
    If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
.EXAMPLE
    PS C:\> Set-TdIncidentTimeSpent 'i1911-123' -TimeSpent 30 -Notes 'Installed Printer'
    registers 30 minutes on i1911-123
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Set-TdIncidentTimeSpent',
        SupportsShouldProcess = $true)]
    param
    (
        [Parameter(
            ValueFromPipelinebypropertyname = $true,
            position = 0)]
        [Alias('IncidentNumber')]
        [string]
        $Number,

        [Parameter(position = 1, Mandatory)]
        [int]
        $TimeSpent,

        [string]
        $EntryDate,

        [Parameter(position = 2)]
        [ValidateLength(0, 250)]
        [string]
        $Notes,

        [string]
        $ReasonId,


        [string]
        $OperatorId,

        [string]
        $OperatorGroupId
    )

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -Level InternalComment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -Level InternalComment

        $uri = "$(Get-TdUrl)/tas/api/incidents/number/$Number/timespent"
        $body = [PSCustomObject]@{}
        $params = @{ Membertype = 'Noteproperty'; InputObject = $body}

        Switch ($PSBoundParameters.Keys) {
            timeSpent {
                $params['Name'] = 'timeSpent'
                $params['Value'] = $timeSpent
                Add-Member @Params
            }
            notes {
                $params['Name'] = 'notes'
                $params['Value'] = $notes
                Add-Member @Params
            }
            entryDate {
                $params['Name'] = 'entryDate'
                $params['Value'] = $entryDate
                Add-Member @Params
            }
            reasonId {
                $reasonId = @{id = $reasonId}
                $params['Name'] = 'reason'
                $params['Value'] = $reason
                Add-Member @Params
            }
            operatorId {
                $operator = @{id = $operatorid}
                $params['Name'] = 'operator'
                $params['Value'] = $operator
                Add-Member @Params
            }
            operatorGroupId {
                $operatorGroup = @{id = $operatorGroupId}
                $params['Name'] = 'operatorGroup'
                $params['Value'] = $operatorGroup
                Add-Member @Params
            }

        }

        if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action "Sending body to $uri --- $($body | out-string)")) {
            return
        }
        $methodParams = @{
            Uri = $uri
            Body = ($body | ConvertTo-Json)
            Method = 'POST'
        }
        $res = Invoke-TdMethod @methodParams
        $res
    }
}



function Get-TdKnowledgeItem {
    <#
    .SYNOPSIS
        Returns Knowledge Items
    .DESCRIPTION
        Retrieve a list of knowledge items available to users of the Self-Service Portal. This is a GraphQL endpoint, which means the response object is fully determined by a user-provided string that describes:
        - which attributes to retrieve
        - which filters to apply
        This currently only works for person accounts, this will not work for Operator accounts.
     .PARAMETER Term
        This is the search term that you want to filter KIs on.
     .EXAMPLE
        PS C:\> Get-TdKnowledgeItem -Term 'printer'
        Gets list of all priorities

    #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdKnowledgeItem')]
    param (
        [string]$Term = ' '
    )
    $url = "$(Get-TdUrl)/tas/api/knowledgeBase/public"
    $body = "query { knowledgeItems(search: {term: `"$Term`"}) { id number translations { id languageId knowledgeItemId title description content }}}"
    $params = @{
        'Uri' = $url
        ContentType = 'text/plain'
        'Method' = 'POST'
        Body = $body
    }
    $res = Invoke-TdMethod @params
    $res.results.knowledgeItems
}


function Get-TdBranch {
    <#
    .SYNOPSIS
        Gets Branches
    .DESCRIPTION
        Gets Branches
    .PARAMETER Archived
        Whether to retrieve archived incidents. Doesn't return archived branches by default.
    .PARAMETER Name
        Name of the branch that you want returned.Wildcards are supported. Default value is '*'
    .EXAMPLE
        PS C:\> Get-TdBranch
        Gets Branches
    .EXAMPLE
        PS C:\> Get-TdBranch 'Main Office'
        Returns the 'Main Office' branch

    #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdBranch')]
    param (
        [Parameter(Position = 0)]
        [String]
        $Name = '*',

        [switch]
        $Archived


    )
    Write-PSFMessage -Level InternalComment -Message "Bound parameters: $($PSBoundParameters.Keys -join ", ")" -Tag 'debug', 'start', 'param'
    $uri = (Get-TdUrl) + '/tas/api/branches'
    Write-PSFMessage -Level InternalComment -Message "Branch url: $uri"

    if ($Archived) {
        $uri = "$uri/?archived=$($Archived.ToString().tolower())"
    }

    $Params = @{
        'uri' = $uri
    }
    $res = Invoke-TdMethod @Params
    $res | Where-Object Name -like $Name | Select-PSFObject -Typename 'TOPdeskPS.Branch' -KeepInputObject
}


function Get-TdBranchDetail {
    <#
.SYNOPSIS
    Gets details of a branch
.DESCRIPTION
    Gets details of a branch by branchId
.PARAMETER Branch
    ID of the branch. See Get-TdBranch
.EXAMPLE
    PS C:\> Get-TdBranchDetails -BranchId (Get-TdBranch -name 'examplebranch').id
    Returns details about 'examplebranch'
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdBranchDetail')]

    param
    (
        [Parameter(
            mandatory = $true,
            ParameterSetName = 'BranchId',
            ValueFromPipelineByPropertyName
        )]
        [Alias('Id')]
        $Branch
    )
    process {
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level internalcomment

        $uri = (Get-TdUrl) + "/tas/api/branches/id/$Branch"
        $res = Invoke-TdMethod -Uri $uri
        $res
    }
}



function Get-TdBranchFilter {
    <#
    .SYNOPSIS
        Returns branch filters
    .DESCRIPTION
        Returns branch filters for a provided operator, or returns a list of all branch filters.
    .PARAMETER Name
        Filter on the name. Wildcards supported.
    .PARAMETER Operator
        Id of the operator that you want branch filters for

    .EXAMPLE
        PS C:\> Get-TdBranchFilter
        Gets list of branch filters
    .EXAMPLE
    PS C:\> Get-TdOperator -name 'Andrew Pla' | Get-TdOperatorBranchFilter
    Returns branch filters for the provided operator
    #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdBranchFilter')]
    param (
        $Name = '*',

        [Parameter(Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName = 'Operator')]
        [Alias('id')]
        $Operator
    )
    process {
        Write-PSFMessage -Level InternalComment -Message "Bound parameters: $($PSBoundParameters.Keys -join ", ")" -Tag 'debug', 'start', 'param'
        if ($Operator) {
            $uri = "$(Get-TdUrl)/tas/api/operators/id/$Operator/filters/branch"
        }
        else {
            $uri = "$(Get-TdUrl)/tas/api/operators/filters/branch"
        }


        $res = Invoke-TdMethod -Uri $uri
        $res | Where-Object name -like $Name
    }
}


function Get-TdBudgetHolder {
    <#
.SYNOPSIS
    Returns budget holders
.DESCRIPTION
    Gets a list of budgetholders. Use the Name parameter to  filter.
.PARAMETER Name
    Filter based on Names. Wildcards accepted. Default Value = '*'
.EXAMPLE
    PS C:\> Get-TdBudgetHolder
    returns a list of budget holders
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdBudgetHolder')]

    param
    (
        $Name = '*'
    )
    begin {
        Write-PsfMessage "[$($MyInvocation.MyCommand.Name)] Function started" -level verbose
    }

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level internalcomment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level internalcomment

        $uri = (Get-TdUrl) + "/tas/api/budgetholders"
        $res = Invoke-TdMethod -Uri $uri | Where-Object Name -Like $Name
        $res
    }
    end {
        Write-PSFMessage "Function Complete" -level verbose
    }
}


function Get-TdCategoryFilter {
    <#
    .SYNOPSIS
        Get list of category filters
    .DESCRIPTION
        Get list of category filters or return the category filters for a provided user
    .PARAMETER Operator
        ID of the Operator. See Get-TdOperator
        .PARAMETER Name
            Filter based on the name. Wildcards accepted.
    .EXAMPLE
        PS C:\> Get-TdCategoryFilter
        Gets list of category filters
    .EXAMPLE
        PS C:\> Get-TdOperator 'First.Last' | Get-TdCategoryFilter
        Returns category filters for 'First.Last'
    .EXAMPLE
        PS C:\> Get-TdCategoryFilter -name
    #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdCategoryFilter')]
    param (
        [Parameter(Position = 0)]
        [string]
        $Name = '*',

        [Parameter(
            ParameterSetName = 'OperatorId',
            ValueFromPipelineByPropertyName
        )]
        [Alias('Id')]
        $Operator


    )
    process {
        Write-PSFMessage -Level InternalComment -Message "Bound parameters: $($PSBoundParameters.Keys -join ", ")" -Tag 'debug', 'start', 'param'

        switch ($PSCmdlet.ParameterSetName) {
            'OperatorId' {
                $uri = "$(Get-TdUrl)/tas/api/operators/id/$OperatorId/filters/category"
            }
            '__AllParameterSets' {
                $uri = "$(Get-TdUrl)/tas/api/operators/filters/category"
            }
        }
        $res = Invoke-TdMethod -Uri $uri
        $res | Where-object name -like $name
    }
}


function Get-TdCountry {
    <#
.SYNOPSIS
    gets list of countries
.DESCRIPTION
    gets list of countries
.PARAMETER Name
        Filter based on the name. Wildcards accepted.
.EXAMPLE
    PS C:\> Get-TdCountry
    gets list of countries
.EXAMPLE
    PS > Get-TdCountry 'USA'
    Returns the USA country
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdCountry')]

    param
    (
        [Parameter(Position = 0)]
        [string]
        $Name = '*'
    )
    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level internalcomment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level internalcomment

        $uri = (Get-TdUrl) + "/tas/api/countries"
        $res = Invoke-TdMethod -Uri $uri
        $res | Where-Object name -like $name | Select-PSFObject -Typename 'TOPdeskPS.BasicObj' -KeepInputObject
    }
}



function Get-TdDepartment {
    <#
.SYNOPSIS
    returns departments
.DESCRIPTION
    returns departments and their external links.
.PARAMETER Name
        Filter based on the name. Wildcards accepted.
.EXAMPLE
    PS> Get-TdDepartment
    returns list of departments
.EXAMPLE
    PS> Get-TdDepartment 'IT'
    Returns the IT department
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdDepartment')]

    param
    (
        [Parameter(Position = 0)]
        [string]
        $Name = '*'
    )

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level internalcomment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level internalcomment

        $uri = (Get-TdUrl) + "/tas/api/departments"
        $res = Invoke-TdMethod -Uri $uri
        $res | Where-object name -like $name
    }

}



function Get-TdLocation {
    <#
.SYNOPSIS
    returns list of locations
.DESCRIPTION
    returns list of locations
    .PARAMETER Archived
    Whether to return archived locations or not.
    .PARAMETER Name
    only return locations matching the pattern. Wildcards accepts
.EXAMPLE
    PS C:\> Get-TdLocation
    returns list of locations
.EXAMPLE
    PS> Get-TdLocation location2
    Returns location2
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdLocation')]

    param
    (
        [Parameter(Position = 0)]
        [System.String]
        $Name = '*',

        [Parameter()]
        [switch]$Archived


    )


    process {
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level internalcomment

        $uri = (Get-TdUrl) + "/tas/api/locations"
        if ($Archived) {$uri = "$uri/?archived=$($Archived.ToString().ToLower())"}
        $res = Invoke-TdMethod -Uri $uri
        $res | Where-Object name -like $name
    }

}



function Get-TdLocationDetail {
    <#
.SYNOPSIS
    Gets location details
.DESCRIPTION
    Returns details of location by id
.PARAMETER Location
    Id of the location that you want returned. See Get-TdLocation
.EXAMPLE
    PS C:\> Get-TdLocation | Get-TdLocationDetail
    returns details for all locations
.EXAMPLE
    PS> Get-TdLocation 'Mars' | Get-TdLocationDetail
    Returns details for the mars location
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdLocationDetail')]

    param
    (
        [Parameter(
            mandatory = $true,
            ValueFromPipelineByPropertyName
        )]
        [Alias('Id')]
        $Location
    )

    process {
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level internalcomment

        $uri = (Get-TdUrl) + "/tas/api/locations/id/$Location"
        $res = Invoke-TdMethod -Uri $uri
        $res
    }
}



function Get-TdLoggedInOperator {
    <#
    .DESCRIPTION
        Get Logged in Operator

        Get-TdLoggedInOperator
        returns the logged in Operator.
    .EXAMPLE
    Get-TdLoggedInOperator
    Returns the current operator
    #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/TOPdeskPS/Get-TdLoggedInOperator')]
    param()

    $url = "$(Get-TdUrl)/tas/api/operators/current"
    Invoke-TdMethod -Uri $url
}


function Get-TdLoggedInPerson {
    <#
    .DESCRIPTION
        Get Logged in person
    .EXAMPLE
        Get-TdLoggedInPerson
        returns the logged in person.
    #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/TOPdeskPS/Get-TdLoggedInPerson')]
    param()
    $url = "$(Get-TdUrl)/tas/api/persons/current"
    Invoke-TdMethod -Uri $url
}


function Get-TdOperator {
    <#
.SYNOPSIS
    returns list of operators
.DESCRIPTION
    returns list of operators
.PARAMETER Name
    human readable name to filter for operator by. Uses the dynamcName field
.PARAMETER ResultSize
	The amount of operators to be returned. Requests greater than 100 require multiple api calls
.PARAMETER FirstName
    Retrieve only operators with first name starting with this.
    .PARAMETER LastName
        Retrieve only operators with last name starting with this.
    .PARAMETER Archived
        Whether to return archived operators
    .PARAMETER TOPdeskLoginName
        Retrieve only operators with TOPdesk login name starting with this.
    .PARAMETER Email
        Retrieve only operators with email starting with this.
	.PARAMETER Start
		This is the offset at which you want to start listing incidents.

.EXAMPLE
    PS C:\> Get-TdOperator
    returns list of operators
.EXAMPLE
    PS C:\> Get-TdOperator -Name 'John Support'
    returns operator with name John Support (uses the dynamicName field)
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdOperator')]

    param
    (
        [Parameter(Position = 0)]
        [string]
        $TOPdeskLoginName,

        [ValidateRange(1, 100000)]
        [int]
        $ResultSize = 100,

        [int]
        $Start = 0,

        [string]
        $Email,

        [switch]$Archived,

        [string]$LastName,

        [string]$FirstName

    )
    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level internalcomment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level internalcomment

        $uri = (Get-TdUrl) + "/tas/api/operators/?"
        switch ($PSBoundParameters.Keys) {
            firstname {
                $uri = "$uri&firstname=$FirstName"
            }
            lastname {
                $uri = "$uri&lastname=$LastName"
            }
            Archived {
                $uri = "$uri&archived=$($archived.tostring().tolower())"
            }
            TOPdeskLoginName {
                $uri = "$uri&topdesk_login_name=$TOPdeskLoginName"
            }
            email {
                $uri = "$uri&email=$Email"
            }
        }

        if ($ResultSize -gt 100) {
            $pageSize = 100
        }
        else {
            $pageSize = $ResultSize
        }

        $uri = $uri.replace('?&', '?')
        $count = 0
        do {
            $operators = @()

            $remaining = $ResultSize - $count

            if ($remaining -le 100) {
                $pageSize = $remaining
                $status = 'finished'
            }

            $loopingUri = "$uri&start=$Start&page_size=$pageSize"
            $Params = @{
                'uri' = $loopingUri
            }

            $operators = Invoke-TdMethod @Params
            foreach ($op in $operators) {
                if ($op.id) { $op | Select-PSFObject -Typename 'TOPdeskPS.Operator' -KeepInputObject }
                else { $status = 'finished' }
            }


            if (($operators.count) -le $remaining) {
                Write-PSFMessage 'No operators remaining.'
                $status = 'finished'
            }

            $count += $operators.count
            $start += $PageSize

        }
        until ($status -like 'finished')

    }
}



function Get-TdOperatorAvatar {
    <#
.SYNOPSIS
    Returns avatar of operator
.DESCRIPTION
    Returns avatar of operator based on the operatorid
.PARAMETER OperatorId
    ID of the operator. See Get-TdOperator
.EXAMPLE
    PS C:\> Get-TdOperatorAvatar -OperatorId (Get-TdOperator -TOPdeskLoginName 'User@company.com').id
    Returns the Avatar for 'User@company.com'
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdOperatorAvatar')]

    param
    (
        [Parameter(
            mandatory = $true,
            ValueFromPipelineByPropertyName
        )]
        [Alias('Id')]
        $OperatorId
    )
    begin {
        Write-PsfMessage "[$($MyInvocation.MyCommand.Name)] Function started" -level verbose
    }

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level internalcomment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level internalcomment

        $uri = (Get-TdUrl) + "/tas/api/avatars/operator/$OperatorId"
        $res = Invoke-TdMethod -Uri $uri
        $res
    }
    end {
        Write-PSFMessage "Function Complete" -level verbose
    }
}



function Get-TdOperatorFilter {
    <#
    .SYNOPSIS
        Get list of Operator filters
    .DESCRIPTION
        Get list of Operator filters or return the Operator filters for a provided user
    .PARAMETER Operator
        ID of the Operator. See Get-TdOperator
        .PARAMETER Name
            Filter based on the name. Wildcards accepted.
    .EXAMPLE
        PS C:\> Get-TdOperatorFilter
        Gets list of Operator filters
    .EXAMPLE
        PS C:\> Get-TdOperator 'Johnny.cash' | Get-TdOperatorFilter
        Returns operator filters for the operator 'johnny.cash'
    .EXAMPLE
        PS C:\> Get-TdOperatorFilter 'Test*'
        Returns all operator filterns with a name starting with test
    #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdOperatorFilter')]
    param (
        [Parameter(Position = 0)]
        [string]
        $Name = '*',

        [Parameter(
            ParameterSetName = 'OperatorId',
            ValueFromPipelineByPropertyName
        )]
        [Alias('Id')]
        $Operator


    )
    process {
        Write-PSFMessage -Level InternalComment -Message "Bound parameters: $($PSBoundParameters | Out-String)" -Tag 'debug', 'start', 'param'

        switch ($PSCmdlet.ParameterSetName) {
            'OperatorId' {
                $uri = "$(Get-TdUrl)/tas/api/operators/id/$Operator/filters/operator"
            }
            '__AllParameterSets' {
                $uri = "$(Get-TdUrl)/tas/api/operators/filters/operator"
            }
        }
        $res = Invoke-TdMethod -Uri $uri
        $res | Where-object name -like $name
    }
}


function Get-TdOperatorGroup {
    <#
.SYNOPSIS
    Returns operator groups
.DESCRIPTION
    returns list of operator groups or groups for a provided operator.
.PARAMETER NameFragment
   Retrieve only operator groups with name starting with this. No wildcards
.PARAMETER OperatorId
    Id of the operator that you want to return operator groups for.
.PARAMETER ResultSize
    The number of results that you want returned.
.PARAMETER Start
    The offset at which to start listing the operator groups at. Must be greater or equal to 0, default is 0
.PARAMETER Archived
    Specify whether you want archived operator groups included
.EXAMPLE
    PS > Get-TdOperatorGroup -resultsize 1000
    returns up to 1000 operator groups.

.Example
    PS > Get-TdOperator | Get-TdOperatorGroup
    Returns operator groups for operators
#>

    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdOperatorGroup',
        DefaultParameterSetName = 'List')]
    param (
        [Parameter(Position = 0,
            ParameterSetName = 'List')]
        [string]$NameFragment,

        [Parameter(ValueFromPipelineByPropertyName, ParameterSetName = 'Operator')]
        [Alias('id')]
        $OperatorId,

        [Parameter(ParameterSetName = 'List')]
        [ValidateRange(1, 100000)]
        [int]
        $ResultSize = 100,

        [Parameter(ParameterSetName = 'List')]
        [switch]
        $Archived,

        [Parameter(ParameterSetName = 'List')]
        [int]
        $Start = 0
    )

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level InternalComment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level InternalComment

        switch ($PsCmdlet.ParameterSetName) {
            Operator {
                $uri = "$(Get-TdUrl)/tas/api/operators/id/$OperatorId/operatorgroups"
                $res = Invoke-TdMethod -Uri $uri
                $res
            }

            List {
                $uri = (Get-TdUrl) + "/tas/api/operatorgroups/?"


                if ($Archived) {
                    $uri = "$uri&archived=$($archived.tostring().tolower())"
                }
                if ($NameFragment) {
                    $uri = "$uri&name=$NameFragment"
                }


                if ($ResultSize -gt 100) { $pageSize = 100 }
                else { $pageSize = $ResultSize }

                $uri = $uri.Replace('?&', '?')
                $count = 0


                do {
                    $groups = @()

                    $remaining = $ResultSize - $count
                    Write-PSFMessage "$remaining groups remaining"

                    if ($remaining -le 100) {
                        $pageSize = $remaining
                        $status = 'finished'
                    }

                    $loopingUri = "$uri&start=$Start&page_size=$pageSize"

                    $Params = @{
                        'uri' = $loopingUri.replace('?&', '?')
                    }

                    $groups = Invoke-TdMethod @Params
                    foreach ($group in $groups) {
                        if ($group.id) { $group }
                        else { $status = 'finished' }
                    }
                    if (($groups.count) -eq $remaining) {
                        Write-PSFMessage 'No groups remaining.'
                        $status = 'finished'
                    }


                    $remaining = $ResultSize - $count
                    if ($remaining -eq 0) { $status = 'finished' }
                    $count += $groups.count
                    $start += $PageSize
                }
                until ($status -like 'finished')
            }
        }
    }
}



function Get-TdOperatorGroupMember {
    <#
.SYNOPSIS
    get the operators of an operator group
.DESCRIPTION
    returns the members of an operator group
.PARAMETER OperatorGroup
    Id of the operator group that you want members for
.EXAMPLE
    PS C:\> Get-TdOperatorGroup TechSupport | Get-TdOperatorGroupMember
    Return members of the TechSupport operator group
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdOperatorGroupMember')]

    param
    (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('id')]
        [string]
        $OperatorGroup
    )

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level InternalComment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level InternalComment

        $uri = "$(Get-TdUrl)/tas/api/operatorgroups/id/$operatorGroup/operators"
        $res = Invoke-TdMethod -Uri $uri
        $res
    }
}



function Get-TdPermissionGroup {
    <#
.SYNOPSIS
    returns list of permission groups
.DESCRIPTION
    returns list of permission groups
.PARAMETER Name
    Name of the operator group that you want returned. Wildcards are supported. Default value is '*'
.PARAMETER Operator
    Id of the operator that you want to return the permission groups for
.EXAMPLE
    PS C:\> Get-TdPermissionGroup
    returns list of permission groups
.EXAMPLE
    PS C:\>  Get-TdOperator -TOPdeskloginName 'Juanita Smith' | Get-TdPermissionGroup
    returns permission groups for Juanita Smith
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdPermissionGroup')]

    param (
        [Parameter(Position = 0)]
        [Alias('GroupName')]
        [system.string]$Name = '*',

        [Parameter(ParameterSetName = 'Operator', ValueFromPipelineByPropertyName)]
        [Alias('id')]
        [string]
        $Operator
    )

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level internalcomment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level internalcomment

        switch ($PsCmdlet.ParameterSetName) {
            __AllParameterSets {
                $uri = (Get-TdUrl) + "/tas/api/permissiongroups"
                $res = Invoke-TdMethod -Uri $uri
                $res  | Where-Object name -like $Name
            }

            Operator {
                $uri = "$(get-tdurl)/tas/api/operators/id/$Operator/permissiongroups"
                $res = Invoke-TdMethod -Uri $uri
                $res
            }
        }
    }

}



function Get-TdPerson {
    <#
    .SYNOPSIS
        Gets persons
    .DESCRIPTION
        Gets persons

    .PARAMETER ResultSize
    The amount of operators to be returned. Requests greater than 100 require multiple api calls. Useful if you want to return all operators

    .PARAMETER Start
		This is the offset at which you want to start listing incidents. This is useful if you want to grab more than 100 incidents.
		The default value is 0.
    .PARAMETER Archived
        Whether to retrieve archived
    .PARAMETER FirstName
        Retrieve only persons with first name starting with this
    .PARAMETER LastName
        Retrieve only persons with last name starting with this
    .PARAMETER NetworkLoginName
        Retrieve only users with network login nmae starting with this. Parameter is ignored for SSP users.
    .PARAMETER SspLoginName
        Retrieve only persons with Self Service Portal name starting with this. Parameter is ignored for SSP users.
    .PARAMETER Email
        Retrieve only persons with email starting with this
    .PARAMETER MobileNumber
     Retrieve only per sons with mobile number ending with this. Spaces and dashes are ignored. For example: 6-12345678 will match both +316 12345678 and 06 1234 5678
    .EXAMPLE
        PS C:\> Get-TdPerson -FirstName 'Bob' -Archived
            Returns all persons with the firstname starting with Bob. This will also search archived files.
    .EXAMPLE
        PS C:\> Get-TdPerson -Email 'User@company.com' | Format-List *
            Returns the person whose email is 'user@company.com' and displays all details of the result.

    #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdPerson')]
    param (
        [system.string]$FirstName,

        [system.string]$Email,

        [Alias('Surname')]
        [system.string]$LastName,

        [system.string]$NetworkLoginName,

        [System.String]$SspLoginName,

        [system.string]$MobileNumber,

        [switch]$Archived,

        [ValidateRange(1, 100000)]
        [int]
        $ResultSize = 100,

        [int]$Start = 0
    )
    Write-Verbose "Bound parameters: $($PSBoundParameters.Keys -join ", ")"
    $uri = (Get-TdUrl) + '/tas/api/persons?'

    if ($PSBoundParameters.keys -contains 'FirstName') {
        $uri = "$uri&firstname=$FirstName"
    }

    if ($PSBoundParameters.keys -contains 'lastname') {
        $uri = "$uri&lastname=$LastName"
    }

    if ($PSBoundParameters.keys -contains 'NetworkLoginName') {
        $uri = "$uri&network_login_name=$NetworkLoginName"
    }

    if ($PSBoundParameters.keys -contains 'SspLoginName') {
        $uri = "$uri&ssp_login_name=$SspLoginName"
    }

    if ($PSBoundParameters.keys -contains 'email') {
        $uri = "$uri&email=$email"
        Write-Verbose "email added - $uri"
    }

    if ($PSBoundParameters.keys -contains 'MobileNumber') {
        $uri = "$uri&mobile_number=$MobileNumber"
    }

    if ($PSBoundParameters.keys -contains 'Archived') {
        $uri = "$uri&archived=true"
    }

    Write-Verbose $uri

    #region Send Multiple requests to until the resultsize is met

    #define pagesize outside the loop so we can set the pagesize

    if ($ResultSize -gt 100) {
        $pageSize = 100
    }
    else {
        $pageSize = $ResultSize
    }

    $uri = $uri.replace('?&', '?')
    $count = 0

    $status = 'not finished'

    do {

        $persons = @()

        $remaining = $ResultSize - $count

        if ($remaining -le 100) { $status = 'finished'; $pagesize = $remaining }

        $loopingUri = "$uri&start=$Start&page_size=$pageSize"
        $Params = @{
            'uri' = $loopingUri
        }

        $persons = Invoke-TdMethod @Params

        foreach ($p in $persons) {
            if ($p.id) { $p | Select-PSFObject -Typename 'TOPdeskPS.Person' -KeepInputObject }

            # end the loop if the api doesn't return a person id.
            else { $status = 'finished' }
        }

        $count += $persons.count
        $start += $PageSize

    }
    until ($status -like 'finished')
}


function Get-TdPersonAvatar {
    <#
.SYNOPSIS
    Returns the avatar of a person
.DESCRIPTION
Returns the avatar of a person by the persons id.
.PARAMETER PersonId
    Gets the image used as an avatar by person id
.EXAMPLE
    PS C:\> Get-TdPerson | Get-TdPersonAvatar
    returns all avatars
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdPersonAvatar')]

    param
    (
        [Parameter(
            mandatory = $true,
            ParameterSetName = 'PersonId',
            ValueFromPipelineByPropertyName
        )]
        [Alias('Id')]
        $PersonId
    )
    begin {
        Write-PsfMessage "[$($MyInvocation.MyCommand.Name)] Function started" -level verbose
    }

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level internalcomment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level internalcomment

        $uri = "$(Get-TdUrl)/tas/api/persons/id/$PersonId/avatar"
        $res = Invoke-TdMethod -Uri $uri
        $res
    }
    end {
        Write-PSFMessage "Function Complete" -level verbose
    }
}



function Get-TdPersonGroup {
    <#
.SYNOPSIS
    returns list of person groups
.DESCRIPTION
    returns list of person groups
.PARAMETER NameFragment
   Retrieve only person groups with name starting with this. No wildcards
.PARAMETER ResultSize
    The number of results that you want returned.
.PARAMETER Start
    The offset at which to start listing the operator groups at. This parameter is likely not used since Resultsize takes of this for you.
.PARAMETER Archived
    Specify whether you want archived operator groups included

.EXAMPLE
    PS> Get-TdPersonGroup -ResultSize 500 -Archived
    returns up to 500 person groups. Includes archived groups
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdPersonGroup')]


    param (
        [Parameter(Position = 0,
            ParameterSetName = 'List')]
        [string]$NameFragment,

        [Parameter(ParameterSetName = 'List')]
        [ValidateRange(1, 100000)]
        [int]
        $ResultSize = 100,

        [Parameter(ParameterSetName = 'List')]
        [switch]
        $Archived,

        [Parameter(ParameterSetName = 'List')]
        [int]
        $Start = 0
    )

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level internalcomment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level internalcomment

        $uri = (Get-TdUrl) + "/tas/api/persongroups/?"


        if ($Archived) {
            $uri = "$uri&archived=$($archived.tostring().tolower())"
        }
        if ($NameFragment) {
            $uri = "$uri&name=$NameFragment"
        }


        if ($ResultSize -gt 100) { $pageSize = 100 }
        else { $pageSize = $ResultSize }

        $uri = $uri.Replace('?&', '?')
        $count = 0


        do {
            $groups = @()

            $remaining = $ResultSize - $count

            if ($remaining -le 100) {
                $pageSize = $remaining
                $status = 'finished'
            }

            $loopingUri = "$uri&start=$Start&page_size=$pageSize"

            $Params = @{
                'uri' = $loopingUri.replace('?&', '?')
            }

            $groups = Invoke-TdMethod @Params
            foreach ($group in $groups) {
                if ($group.id) { $group }
                else { $status = 'finished' }
            }
            if (($groups.count) -eq $remaining) {
                $status = 'finished'
            }


            $remaining = $ResultSize - $count
            if ($remaining -eq 0) { $status = 'finished' }
            $count += $groups.count
            $start += $PageSize
        }
        until ($status -like 'finished')
    }
}


function Get-TdSupplier {
    <#
.SYNOPSIS
    returns list of suppliers
.DESCRIPTION
    returns list of suppliers
.EXAMPLE
    PS C:\> Get-TdSuppliers
    returns list of suppliers
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdSupplier')]

    param
    (

    )
    begin {
        Write-PsfMessage "[$($MyInvocation.MyCommand.Name)] Function started" -level verbose
    }

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level internalcomment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level internalcomment

        $uri = (Get-TdUrl) + "/tas/api/suppliers"
        $res = Invoke-TdMethod -Uri $uri
        $res
    }
    end {
        Write-PSFMessage "Function Complete" -level verbose
    }
}


function Get-TdSupplierContact {
    <#
.SYNOPSIS
    Gets list of supplier  contacts
.DESCRIPTION
    Returns list of supplier contacts
.PARAMETER Name
retrieve only suppliers with names starting with this string
.PARAMETER PageSize
The amount of suppliers to be returned per request. Must be between 1 and 10000, default is 1000.
.PARAMETER Archived
    Whether to retrieve archived incidents.
.PARAMETER PageSize
    The amount of incidents to be returned per request. The default value is 10 and the maximum value is 100.
.PARAMETER Start
    This is the offset at which you want to start listing suppliers at.
    The default value is 0.
.PARAMETER SupplierId
    ID of the Supplier. See Get-TdSupplier
.EXAMPLE
    PS C:\> Get-TdSuppliercontact
    Returns list of supplier contacts
.EXAMPLE
    PS C:\> Get-TdSupplier -Name 'Sample Supplier' | Get-TdSupplierContact
    Returns list of Supplier contracts from supplier 'Sample Supplier'
#>
#TODO figure out what's going on here
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Get-TdSupplierContact')]

    param
    (
        [Parameter(
            ValueFromPipelineByPropertyName
        )]
        [Alias('Id')]
        $SupplierId,

        [ValidateRange(1, 100)]
        [int]
        $PageSize = 10,

        [int]
        $Start = 0,

        [switch]
        $Archived,

        [system.string]
        $Name
    )
    begin {
        Write-PsfMessage "[$($MyInvocation.MyCommand.Name)] Function started" -level verbose
    }

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level internalcomment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level internalcomment
        $uri = (Get-TdUrl) + "/tas/api/supplierContacts"
        $uri = "$uri/?start=$Start&page_size=$PageSize"
        if ($PSBoundParameters.keys -contains 'Name') {
            $uri = "$uri&name=$Name"
        }

        if ($PSBoundParameters.keys -contains 'Archived') {
            $uri = "$uri&archived=$($Archived.tostring().tolower())"
        }
        $res = Invoke-TdMethod -Uri $uri
        $res
    }
    end {
        Write-PSFMessage "Function Complete" -level verbose
    }
}



function New-TdBranch {
    <#
.SYNOPSIS
    Creates a new branch
.DESCRIPTION
    creates a new branch
.PARAMETER Name
    Name of the branch
.PARAMETER Specification
    Branch specification
.PARAMETER ClientReferenceNumber
    Client Reference Number
.PARAMETER Phone
    Phone Number
.PARAMETER Fax
    Fax Number
.PARAMETER Email
    email address
.PARAMETER Website
    Website URL
.PARAMETER BranchType
    Define the type of branch. Optional values: 'independentBranch', 'headBranch', 'hasAHeadBranch'
.PARAMETER HeadBranchId
    ID of head branch
.PARAMETER Address
    Address
.PARAMETER OptionalFields1
    optional
.PARAMETER OptionalFields2
    optional
.PARAMETER PostalAddress
    Postal Address
.PARAMETER Confirm
    If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
.PARAMETER WhatIf
    If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
.EXAMPLE
    PS C:\> New-TdBranch -Name 'New Branch' -Branch Type 'independentBranch' -Phone '555-555-5555'
    creates a new branch
.EXAMPLE
    PS C:\> New-TdBranch -Name 'Subsidiary of AlphaBranch' -BranchType 'hasAHeadBranch' -HeadBranchId (Get-TdBranch -name 'AlphaBranch').id
.LINK
    https://developers.topdesk.com/explorer/?page=supporting-files?/
#>
    #TODO Update help

    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/New-TdBranch',
        SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Specification,

        [string]$ClientReferenceNumber,

        [string]$Phone,

        [string]$fax,

        [string]$Email,

        [string]$Website,

        [Parameter(Mandatory)]
        [ValidateSet('independentBranch', 'headBranch', 'hasAHeadBranch')]
        [string]$BranchType,

        [Alias('HeadBranch')]
        $HeadBranchId,
        [hashtable]$Address,
        [hashtable]$PostalAddress,
        [hashtable]$OptionalFields1,
        [hashtable]$OptionalFields2

    )
    begin {
        Write-PsfMessage "[$($MyInvocation.MyCommand.Name)] Function started" -level verbose
    }

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level internalcomment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level internalcomment

        $uri = (Get-TdUrl) + "/tas/api/branches"
        $body = [PSCustomObject]@{}
        switch ($PSBoundParameters.Keys) {
            Name {
                $Body | Add-Member -MemberType NoteProperty -Name 'name' -Value $Name
            }
            Specification {
                $Body | Add-Member -MemberType NoteProperty -Name 'specification' -Value $Specification
            }
            ClientReferenceNumber {
                $Body | Add-Member -MemberType NoteProperty -Name 'clientReferenceNumber' -Value $ClientReferenceNumber
            }
            Phone {
                $Body | Add-Member -MemberType NoteProperty -Name 'phone' -Value $Phone
            }
            Fax {
                $body | Add-Member -TypeName NoteProperty -Name 'fax' -Value $Fax
            }
            Email {
                $body | Add-Member -TypeName NoteProperty -Name 'email' -Value $Email
            }
            Website {
                $Body | Add-Member -MemberType NoteProperty -Name 'website' -Value $Website
            }
            BranchType {
                $Body | Add-Member -MemberType NoteProperty -Name 'branchType' -Value $BranchType
            }
            HeadBranchId {
                $HeadBranch = @{
                    id = $HeadBranchId
                }
                $Body | Add-Member -MemberType NoteProperty -Name 'headBranch' -Value $HeadBranch
            }
            Address {
                $Body | Add-Member -MemberType NoteProperty -Name 'address' -Value $Address
            }
            PostalAddress {
                $Body | Add-Member -MemberType NoteProperty -Name 'postalAddress' -Value $PostalAddress
            }
            OptionalFields1 {
                $Body | Add-Member -MemberType NoteProperty -Name 'optionalFields1' -Value $OptionalFields1
            }
            OptionalFields2 {
                $Body | Add-Member -MemberType NoteProperty -Name 'optionalFields2' -Value $OptionalFields2
            }

        }



        if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action 'Sending Request')) {
            return
        }
        Invoke-TdMethod -Uri $uri -Body ($body | Convertto-json) -Method 'POST'
    }
    end {
        Write-PSFMessage "Function Complete" -level verbose
    }
}



function New-TdBudgetHolder {
    <#
    .SYNOPSIS
        Creates new BudgetHolder
    .DESCRIPTION
        creates new budgetholder
    .PARAMETER Name
        The name of the budget holder.
    .PARAMETER ExternalLinkID
        Id of the entity in the external system
    .PARAMETER Confirm
        If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
    .PARAMETER WhatIf
        If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
    .PARAMETER ExternalLinkType
        The Type of the link.
    .EXAMPLE
    PS C:\> New-TdBudgetHolder -Name 'Management'
    Creates a new budget holdernamed 'management'
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/New-TdBudgetHolder',
        SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory, ParameterSetName = 'Name')]
        [System.string]$Name,

        [Parameter(Mandatory, ParameterSetName = 'ExternalLink')]
        [System.String]$externalLinkId,

        [Parameter(Mandatory, ParameterSetName = 'ExternalLink')]
        [System.string]$ExternalLinkType
    )

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level internalcomment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level internalcomment

        $uri = (Get-TdUrl) + "/tas/api/budgetholders"
        $body = [PSCustomObject]@{}

        $Body | Add-Member -MemberType NoteProperty -Name 'name' -Value $name
        if ($pscmdlet.ParameterSetName -eq 'ExternalLink') {
            $externalLink = [PSCustomObject]@{
                id = $ExternalLinkId
                type = $ExternalLinkType
            }
            $body | Add-Member -MemberType NoteProperty -Name 'externalLink' -Value $externalLink
        }
        if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action 'Sending Request')) {
            return
        }
        Invoke-TdMethod -Uri $uri -Body ($body | Convertto-json) -Method POST
    }

}



function New-TdDepartment {
    <#
.SYNOPSIS
    Creates a new Department
.DESCRIPTION
    Creates a new department
.PARAMETER Name
    Name of new department
.PARAMETER ExternalLinkId
    external link ID
.PARAMETER Confirm
    If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
.PARAMETER WhatIf
    If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
.EXAMPLE
    PS C:\> New-TdDepartment -Name 'TestDepartment'
    Creates a new Department named 'TestDepartment'
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/New-TdDepartment',
        SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory, ParameterSetName = 'Name')]
        [string]$Name,
        [Parameter(Mandatory, ParameterSetName = 'ExternalLink')]
        [string]$externalLinkId
    )

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level internalcomment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level internalcomment

        $uri = (Get-TdUrl) + "/tas/api/departments"
        $body = [PSCustomObject]@{}

        $body | Add-Member -MemberType NoteProperty -Name 'name' -Value $name
        if ($pscmdlet.ParameterSetName -eq 'ExternalLink') {
            $externalLink = [PSCustomObject]@{
                id = $ExternalLinkId
                type = $ExternalLinkType
            }
            $body | Add-Member -MemberType NoteProperty -Name 'externalLink' -Value $externalLink
        }

        if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action 'Sending Request')) {
            return
        }
        Invoke-TdMethod -Uri $uri -Body ($body | Convertto-json) -Method POST
    }

}



function New-TdOperator {
    <#
    .SYNOPSIS
        Create an operator
    .DESCRIPTION
        Create new operators. Operator must have create permission on operators

    .PARAMETER SurName
        Surname of the operator

    .PARAMETER FirstName
        Firstname of the operator

    .PARAMETER Gender
        The gender of the operator

    .PARAMETER EmployeeNumber
        The employee number of the operator

    .PARAMETER Telephone
        The telephone number for the operator
    .PARAMETER MobileNumber
        Mobile number for the operator

    .PARAMETER NetworkLoginName
        The network login name for the operator

        .PARAMETER Email
            Email address of the operator

    .PARAMETER BranchId
        The id of the branch that you want to give the operator

    .PARAMETER Location
        Location id of the operator

    .PARAMETER Department
        The department id of the operator
    .PARAMETER BudgetHolder
        The budget holder id of the operator
    .PARAMETER LoginPermission
        specify whether the operator has the permission to log on

    .PARAMETER LoginName
        Login name, operator requires permission “Settings > Login Settings”
        Is mandatory when loginPermission is set to true.
    .PARAMETER Password
        Password, operator requires permission "Settings > Login Settings".
        Is mandatory when “Functional Settings > Login Settings > Operator’s Section > Password mandatory on Operator card” is set.
    .PARAMETER Tasks
        Specify the tasks that you want the operator to have.
    .PARAMETER Confirm
        If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
    .PARAMETER WhatIf
        If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
    .EXAMPLE
        PS C:\> New-TdOperator -Surname 'Smith' -firstname 'John' -branchId (Get-TdBranch -Name HQ).id
        Creates a new operator name John Smith in the HQ branch
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/New-TdOperator',
        SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory)]
        [ValidateLength(0, 50)]
        $SurName,

        [ValidateLength(0, 30)]
        [string]
        $FirstName,

        [ValidateSet('UNDEFINED', 'MALE', 'FEMALE')]
        [string]
        $Gender,

        [ValidateLength(0, 20)]
        [string]
        $EmployeeNumber,

        [ValidateLength(0, 25)]
        [string]
        $Telephone,

        [ValidateLength(0, 25)]
        [string]
        $MobileNumber,

        [ValidateLength(0, 100)]
        [string]
        $NetworkLoginName,

        [ValidateLength(0, 100)]
        [string]
        $Email,

        [Parameter(Mandatory)]
        [string]
        $BranchId,

        [string]
        $Location,

        [string]
        $Department,

        [string]
        $BudgetHolder,

        [switch]
        $LoginPermission,

        [ValidateLength(0, 100)]
        [string]
        $LoginName,

        [securestring]
        $Password,

        [ValidateSet(
            'installer',
            'firstLineCallOperator',
            'secondLineCallOperator',
            'problemManager',
            'problemOperator',
            'changeCoordinator',
            'changeActivitiesOperator',
            'requestForChangeOperator',
            'extensiveChangeOperator',
            'simpleChangeOperator',
            'scenarioManager',
            'planningActivityManager',
            'projectCoordinator',
            'projectActiviesOperator',
            'stockManager',
            'reservationsOperator',
            'serviceOperator',
            'externalHelpDeskParty',
            'contractManager',
            'operationsOperator',
            'operationsManager',
            'knowledgeBaseManager',
            'accountManager'
        )]
        [string[]]
        $Tasks

    )


    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -Level InternalComment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -Level InternalComment

        $uri = "$(Get-TdUrl)/tas/api/operators"
        $body = [PSCustomObject]@{}
        $memberParams = @{ Membertype = 'Noteproperty'; InputObject = $body}
        Switch ($PSBoundParameters.Keys) {
            SurName {
                $memberParams['Name'] = 'surName'
                $memberParams['Value'] = $surName
                Add-member @memberParams
            }
            firstName {
                $memberParams['Name'] = 'firstName'
                $memberParams['Value'] = $firstName
                Add-Member @memberParams
            }
            gender {
                $memberParams['Name'] = 'gender'
                $memberParams['Value'] = $gender
                Add-Member @memberParams
            }
            employeeNumber {
                $memberParams['Name'] = 'employeeNumber'
                $memberParams['Value'] = $employeeNumber
                Add-Member @memberParams
            }
            telephone {
                $memberParams['Name'] = 'telephone'
                $memberParams['Value'] = $telephone
                Add-Member @memberParams
            }
            mobileNumber {
                $memberParams['Name'] = 'mobileNumber'
                $memberParams['Value'] = $mobileNumber
                Add-Member @memberParams
            }
            networkLoginName {
                $memberParams['Name'] = 'networkLoginName'
                $memberParams['Value'] = $networkLoginName
                Add-Member @memberParams
            }
            email {
                $memberParams['Name'] = 'email'
                $memberParams['Value'] = $email
                Add-Member @memberParams
            }
            branchId {
                $memberParams['Name'] = 'branch'
                $memberParams['Value'] = @{id = $BranchId}
                Add-Member @memberParams
            }
            location {
                $memberParams['Name'] = 'location'
                $memberParams['Value'] = @{id = $location}
                Add-Member @memberParams
            }
            department {
                $memberParams['Name'] = 'department'
                $memberParams['Value'] = @{id = $department}
                Add-Member @memberParams
            }

            budgetHolder {
                $memberParams['Name'] = 'budgetHolder'
                $memberParams['Value'] = @{id = $budgetHolder}
                Add-Member @memberParams
            }
            loginPermission {
                $memberParams['Name'] = 'loginPermission'
                $memberParams['Value'] = $loginPermission.tostring().tolower()
                Add-Member @memberParams
            }
            loginName {
                $memberParams['Name'] = 'loginName'
                $memberParams['Value'] = $loginName
                Add-Member @memberParams
            }
            password {
                $cred = New-Object pscredential ('user', $password)
                $memberParams['Name'] = 'password'
                $memberParams['Value'] = $cred.GetNetworkCredential().password
                Add-Member @memberParams
            }
            Tasks {
                foreach ($t in $Tasks) {
                    $body | Add-Member -MemberType NoteProperty -Name $t -Value 'true'
                }
            }
        }
        #region tasks

        #endregion tasks



        if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action "Sending Body: $($Body | Out-String)")) {
            return
        }
        $methodParams = @{
            Uri = $uri
            Body = ($body | ConvertTo-Json)
            Method = 'POST'
        }
        $res = Invoke-TdMethod @methodParams
        $res
    }

}



function New-TdOperatorGroup {
    <#
.SYNOPSIS
    Create an operator group
.DESCRIPTION
    Create an operator group
.PARAMETER Branch
    Id of the branch that is assigned to the operator group
.PARAMETER GroupName
    Operator Group Name
.PARAMETER Contact
    Hashtable containing the values that you want to set. valid properties are telephone, faxNumber, and email.
.PARAMETER Confirm
    If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
.PARAMETER WhatIf
    If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
.EXAMPLE
    PS C:\> New-TdOperatorGroup -Branch (Get-TdBranch 'Miami').id -GroupName 'Miami Group'
    Creates a new operator group named 'Miami Group' that is attached ot the Miami branch
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/New-TdOperatorGroup',
        SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory)]
        [string]
        $Branch,

        [Parameter(Mandatory)]
        [ValidateLength(0, 30)]
        [string]
        $GroupName,

        [Parameter()]
        [hashtable]
        $Contact
    )
    process {
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -Level InternalComment

        $uri = "$(Get-TdUrl)/tas/api/operatorgroups"
        $body = [PSCustomObject]@{}
        $addMemberParams = @{ Membertype = 'Noteproperty'; InputObject = $body}


        switch ($PSBoundParameters.Keys) {
            GroupName {
                $addMemberParams['Name'] = 'groupName'
                $addMemberParams['Value'] = $GroupName
                Add-Member @addMemberParams
            }

            Branch {
                $addMemberParams['Name'] = 'branch'
                $addMemberParams['Value'] = @{id = $Branch}
                Add-Member @addMemberParams
            }

            Contact {
                $addMemberParams['Name'] = 'contact'
                $addMemberParams['Value'] = $Contact
                Add-Member @addMemberParams
            }

        }

        if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action 'Sending Request')) {
            return
        }
        $methodParams = @{
            Uri = $uri
            Body = ($body | ConvertTo-Json)
            Method = 'POST'
        }
        $res = Invoke-TdMethod @methodParams
        $res
    }
}



function New-TdPerson {
    <#
    .SYNOPSIS
        Creates new persons
    .DESCRIPTION
        Creates new persons in TOPdesk. Logged in operator must have:
        Create permissions on persons
        Login data write permissions to set login name and password
    .PARAMETER Surname
        Surname of the person
    .PARAMETER BranchId
        Id of the person's branch. This is mandatory. See examples for mobileNumber
    .PARAMETER FirstName
        Firstname of the person
    .PARAMETER FirstInitials
        Firstinitials of the person
    .PARAMETER Prefixes
        Prefixes of the person
    .PARAMETER Gender
        Gender of the user. default value is 'UNDEFINED'
    .PARAMETER EmployeeNumber
        EmployeeNumber of the user
    .PARAMETER NetworkLoginName
        NetworkLoginName for the user
    .PARAMETER LocationId
        LocationId of the person
    .PARAMETER DepartmentId
        DepartmentId of the person
    .PARAMETER DepartmentFree
            Department text-field (has to be used when “Modules Settings > Supporting Files > Department(person) > Plain text field” is set)
    .PARAMETER TasLoginName
        Login name, operator requires permission “Settings > Login Settings”
    .PARAMETER Password
        Password, operator requires permission "Settings > Login Settings". Is mandatory when “Functional Settings > Login Settings > Self Service Portal > Password mandatory on Person card” is set.
    .PARAMETER PhoneNumber
        PhoneNumber of the person
    .PARAMETER MobileNumber
        MobileNumber of the person
    .PARAMETER Fax
        Fax of the person
    .PARAMETER Email
        Email address of the user.
    .PARAMETER JobTitle
        Job title of the person
    .PARAMETER showBudgetholder
        Person can see requests with the same budget holder
    .PARAMETER showDepartment
        Person can see requests with the same department
    .PARAMETER ShowBranch
        Person can see requests with the same branch
    .PARAMETER showSubsidiaries
        Person can see requests with subsidiary branches (showBranches has to be true as well)
    .PARAMETER AuthorizeAll
    Person Person can authorize requests with the same department, budget holder, branch or subsidiary branch (only works when the person is a manager)
    .PARAMETER AuthorizeDepartment
    Person can authorize requests from the same department (only works when the person is a manager)
   .PARAMETER AuthorizeBudgetHolder
   Person can authorize requests with the same budget holder (only works when the person is a manager)
   .PARAMETER AuthorizeBranch
        Person can authorize requests from the same branch (only works when the person is a manager)
    .PARAMETER authorizeSubsidiaryBranches
        Person can authorize requests from the subsidiary branches (only works when the person is a manager and authorizeBranch is true)
   .PARAMETER IsManager
        Specify if the person is a manager
    .PARAMETER ManagerId
        Id of the person's manager.
    .PARAMETER BudgetHolderId
        The Id of the poerson's budgetholder
    .PARAMETER Confirm
		If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
	.PARAMETER WhatIf
		If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
    .EXAMPLE
        PS C:\> New-TdPerson -LastName 'Doe' -BranchId (Get-TdBranch -Name 'Los Angeles').id
        This is the minimum required to create a person: BranchId and a lastname.
    .EXAMPLE
        PS C:\> New-TdPerson -LastName 'Doe' -FirstName 'John' -NetworkLoginName 'john.doe@company.com' -BranchId (Get-TdBranch -Name 'Los Angeles').id
        This creates a user with serveral properties and uses Get-TdBranch to get the branch id.
        #>
    [CmdletBinding(DefaultParameterSetName = 'BranchName',
        SupportsShouldProcess = $true,
        HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/New-TdPerson')]
    param (
        [Alias('LastName')]
        [Parameter(Mandatory)]
        [string]$Surname,

        [string]$BranchId,
        [string]$FirstName,
        [string]$FirstInitials,
        [string]$Prefixes,
        [string]$Gender = 'UNDEFINED',
        [string]$EmployeeNumber,
        [string]$NetworkLoginName,
        [string]$LocationId,
        [string]$DepartmentId,
        [string]$DepartmentFree,
        [string]$TasLoginName,
        [securestring]$Password,
        [string]$PhoneNumber,
        [string]$MobileNumber,
        [string]$Fax,

        [alias('EmailAddress')]
        [string]$Email,

        [string]$JobTitle,
        [switch]$ShowBudgetholder,
        [switch]$ShowDepartment,
        [switch]$ShowBranch,
        [switch]$ShowSubsidiaries,
        [switch]$AuthorizeAll,
        [switch]$AuthorizeDepartment,
        [switch]$AuthorizeBudgetHolder,
        [switch]$AuthorizeBranch,
        [switch]$AuthorizeSubsidiaryBranches,
        [switch]$IsManager,
        [string]$ManagerId,
        [string]$BudgetholderID

    )

    begin {
        $uri = (Get-TdUrl) + '/tas/api/persons'
    }

    process {
        Write-PSFMessage -Level InternalComment -Message "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-PSFMessage -Level InternalComment -Message "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"


        Write-PSFMessage "Going through all parameters and generating body" -Level debug
        $body = [PSCustomObject]@{}
        switch ($PSBoundParameters.Keys) {
            Surname {
                Write-PSFMessage -Level InternalComment -Message "Adding Surname to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'surName' -Value $Surname
            }
            FirstName {
                Write-PSFMessage -Level InternalComment -Message "Adding FirstName to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'firstName' -Value $FirstName
            }
            FirstInitials {
                Write-PSFMessage -Level InternalComment -Message "Adding FirstInitials to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'firstInitials' -Value $FirstInitials
            }
            Prefixes {
                Write-PSFMessage -Level InternalComment -Message "Adding Prefixes to Body"
                $Body | Add-Member -MemberType NoteProperty -Name prefixes -Value $Prefixes
            }
            Gender {
                Write-PSFMessage -Level InternalComment -Message "Adding Gender to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'gender' -Value $Gender
            }
            EmployeeNumber {
                Write-PSFMessage -Level InternalComment -Message "Adding EmployeeNumber to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'employeeNumber' -Value $EmployeeNumber
            }
            NetworkLoginName {
                Write-PSFMessage -Level InternalComment -Message "Adding NetworkLoginName to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'networkLoginName' -Value $NetworkLoginName
            }
            DepartmentFree {
                Write-PSFMessage -Level InternalComment -Message "Adding DepartmentFree to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'departmentFree' -Value $DepartmentFree
            }
            TasLoginName {
                Write-PSFMessage -Level InternalComment -Message "Adding TasLoginName to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'tasLoginName' -Value $TasLoginName
            }
            Password {
                Write-PSFMessage -Level InternalComment -Message "Adding Password to Body"
                $cred = New-Object pscredential ('user', $Password)
                $Body | Add-Member -MemberType NoteProperty -Name 'password' -Value $cred.getnetworkcredential().password
            }
            PhoneNumber {
                Write-PSFMessage -Level InternalComment -Message "Adding PhoneNumber to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'phoneNumber' -Value $PhoneNumber
            }
            MobileNumber {
                Write-PSFMessage -Level InternalComment -Message "Adding MobileNumber to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'mobileNumber' -Value $MobileNumber
            }
            Fax {
                Write-PSFMessage -Level InternalComment -Message "Adding Fax to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'fax' -Value $Fax
            }
            Email {
                Write-PSFMessage -Level InternalComment -Message "Adding Email to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'email' -Value $Email
            }
            JobTitle {
                Write-PSFMessage -Level InternalComment -Message "Adding JobTitle to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'jobTitle' -Value $JobTitle
            }
            showBudgetholder {
                Write-PSFMessage -Level InternalComment -Message "Adding showBudgetholder to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'showBudgetholder' -Value $showBudgetholder.ToString().ToLower()
            }
            showDepartment {
                Write-PSFMessage -Level InternalComment -Message "Adding showDepartment to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'showDepartment' -Value $showDepartment.ToString().ToLower()
            }
            showSubsidiaries {
                Write-PSFMessage -Level InternalComment -Message "Adding showSubsidiaries to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'showSubsidiaries' -Value $showSubsidiaries.ToString().ToLower()
            }
            authorizeAll {
                Write-PSFMessage -Level InternalComment -Message "Adding authorizeAll to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'authorizeAll' -Value $authorizeAll.ToString().ToLower()
            }
            authorizeDepartment {
                Write-PSFMessage -Level InternalComment -Message "Adding authorizeDepartment to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'authorizeDepartment' -Value $authorizeDepartment.ToString().ToLower()
            }
            authorizeBudgetholder {
                Write-PSFMessage -Level InternalComment -Message "Adding authorizeBudgetholder to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'authorizeBudgetholder' -Value $authorizeBudgetholder.ToString().ToLower()
            }
            authorizeBranch {
                Write-PSFMessage -Level InternalComment -Message "Adding authorizeBranch to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'authorizeBranch' -Value $authorizeBranch.ToString().ToLower()
            }
            authorizeSubsidiaryBranches {
                Write-PSFMessage -Level InternalComment -Message "Adding authorizeSubsidiaryBranches to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'authorizeSubsidiaryBranches' -Value $authorizeSubsidiaryBranches.ToString().ToLower()
            }
            isManager {
                Write-PSFMessage -Level InternalComment -Message "Adding isManager to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'isManager' -Value $isManager.ToString().ToLower()
            }

            BranchId {
                $branchIdObject = @{
                    id = $BranchId
                }
                Write-PSFMessage -Level InternalComment -Message "Adding branchId to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'branch' -Value $branchIdObject
            }

            managerId {
                $managerIdObject = @{
                    id = $managerId
                }
                Write-PSFMessage -Level InternalComment -Message "Adding budgetHolderId to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'manager' -Value $managerIdObject
            }
            budgetHolderId {
                $budgetHolderIdObject = @{
                    id = $budgetHolderId
                }
                Write-PSFMessage -Level InternalComment -Message "Adding budgetHolderId to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'budgetHolder' -Value $budgetHolderIdObject
            }

            locationId {
                $locationIdObject = @{
                    id = $locationId
                }
                Write-PSFMessage -Level InternalComment -Message "Adding locationId to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'locationId' -Value $locationIdObject
            }

            departmentId {
                $departmentIdObject = @{
                    id = $departmentId
                }
                Write-PSFMessage -Level InternalComment -Message "Adding departmentId to Body"
                $Body | Add-Member -MemberType NoteProperty -Name 'department' -Value $departmentIdObject
            }



        }

       	$Params = @{
            'Uri' = $uri
            'Body' = $Body | ConvertTo-Json
            'Method' = 'Post'
        }

        if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action 'creating new person')) {
            return
        }
        Invoke-TdMethod @params
    }

    end {
    }
}


function Set-TdBranch {
    <#
.SYNOPSIS
    update a branch by id
.DESCRIPTION
    update branch
.PARAMETER BranchId
    ID of the branch. See Get-TdBranch
.PARAMETER Name
    Name of the branch
.PARAMETER Specification
    Branch specification
.PARAMETER ClientReferenceNumber
    Client Reference Number
.PARAMETER Phone
    Phone Number
.PARAMETER Fax
    Fax Number
.PARAMETER Email
    email address
.PARAMETER Website
    Website URL
.PARAMETER BranchType
    Define the type of branch. Optional values: 'independentBranch', 'headBranch', 'hasAHeadBranch'
.PARAMETER HeadBranchId
    ID of head branch
.PARAMETER Address
    Hashtable containing address values
.PARAMETER PostalAddress
    Hashtable containing postal address values
.PARAMETER OptionalFields1
    optional see docs
.PARAMETER OptionalFields2
    optional see docs
.PARAMETER Confirm
    If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
.PARAMETER WhatIf
    If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
.EXAMPLE
    PS C:\> Set-TdBranch -BranchId (Get-TdBranch -Name 'Test Branch').id -Phone '555-555-5555'
    Updates the Test Branch phone number.
#>

    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Set-TdBranch',
        SupportsShouldProcess = $true)]
    param
    (
        [Parameter(
            mandatory = $true,
            ParameterSetName = 'BranchId',
            ValueFromPipelineByPropertyName
        )]
        [Alias('Id')]
        $BranchId,

        [System.String]$Name,

        [system.string]$Specification,

        [System.String]$ClientReferenceNumber,

        [System.String]$Phone,

        [System.String]$fax,

        [System.String]$Email,

        [System.String]$Website,


        [ValidateSet('independentBranch', 'headBranch', 'hasAHeadBranch')]
        [System.String]$BranchType,

        [Alias('HeadBranch')]
        $HeadBranchId,

        [hashtable]$Address,
        [hashtable]$PostalAddress,
        [hashtable]$OptionalFields1,
        [hashtable]$OptionalFields2

    )
    begin {
        Write-PsfMessage "[$($MyInvocation.MyCommand.Name)] Function started" -level verbose
    }

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level internalcomment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level internalcomment

        $uri = (Get-TdUrl) + "/tas/api/branches/id/$BranchId"
        $body = [PSCustomObject]@{}
        switch ($PSBoundParameters.Keys) {
            Name {
                $Body | Add-Member -MemberType NoteProperty -Name 'name' -Value $Name
            }
            Specification {
                $Body | Add-Member -MemberType NoteProperty -Name 'specification' -Value $Specification
            }
            ClientReferenceNumber {
                $Body | Add-Member -MemberType NoteProperty -Name 'clientReferenceNumber' -Value $ClientReferenceNumber
            }
            Phone {
                $Body | Add-Member -MemberType NoteProperty -Name 'phone' -Value $Phone
            }
            Fax {
                $body | Add-Member -Membertype NoteProperty -Name 'fax' -Value $Fax
            }
            Email {
                $body | Add-Member -Membertype NoteProperty -Name 'email' -Value $Email
            }
            Website {
                $Body | Add-Member -MemberType NoteProperty -Name 'website' -Value $Website
            }
            BranchType {
                $Body | Add-Member -MemberType NoteProperty -Name 'branchType' -Value $BranchType
            }
            HeadBranchId {
                $HeadBranch = @{
                    id = $HeadBranchId
                }
                $Body | Add-Member -MemberType NoteProperty -Name 'headBranch' -Value $HeadBranch
            }
            Address {
                $Body | Add-Member -MemberType NoteProperty -Name 'address' -Value $Address
            }
            PostalAddress {
                $Body | Add-Member -MemberType NoteProperty -Name 'postalAddress' -Value $PostalAddress
            }
            OptionalFields1 {
                $Body | Add-Member -MemberType NoteProperty -Name 'optionalFields1' -Value $OptionalFields1
            }
            OptionalFields2 {
                $Body | Add-Member -MemberType NoteProperty -Name 'optionalFields2' -Value $OptionalFields2
            }
        }

        if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action 'Sending Request')) {
            return
        }
        Invoke-TdMethod -Uri $uri -Body ($body | Convertto-json) -Method 'PUT'
    }
    end {
        Write-PSFMessage "Function Complete" -level verbose
    }

}



function Set-TdOperator {
    <#
.SYNOPSIS
    Update operators
.DESCRIPTION
    Update an operator by id. You can update the various properties of an operator. You can also archive an operator if you provide an archive. Same thing goes for Unarchiving a user. Due to api limitiations Archive/Unarchive requests may not be combined with updates to other properties of a user. They must be sent in seperate requests.

.PARAMETER Operator
Id of the operator that you want to edit

.PARAMETER SurName
Surname of the operator

.PARAMETER FirstName
    Firstname of the operator

.PARAMETER Gender
    The gender of the operator

.PARAMETER EmployeeNumber
        The employee number of the operator

    .PARAMETER Telephone
            The telephone number for the operator
.PARAMETER MobileNumber
        Mobile number for the operator

   .PARAMETER NetworkLoginName
        The network login name for the operator

.PARAMETER Email
    Email address of the operator

.PARAMETER Branch
    The id of the branch that you want to give the operator

.PARAMETER Location
    Location id of the operator

.PARAMETER Department
    The department id of the operator

.PARAMETER BudgetHolder
        The budget holder id of the operator

.PARAMETER LoginPermission
specify whether the operator has the permission to log on

.PARAMETER LoginName
    Login name, operator requires permission “Settings > Login Settings”
Is mandatory when loginPermission is set to true.

.PARAMETER Password
    Password, operator requires permission "Settings > Login Settings".
Is mandatory when “Functional Settings > Login Settings > Operator’s Section > Password mandatory on Operator card” is set.

.PARAMETER TasksToAdd
    All of the tasks that you want to grant the operator

.PARAMETER TasksToRemove
    All of the tasks that you wish to revoke from the operator

.PARAMETER ArchiveReason
        Id of the archive reason that will be used to archive the operator. See Get-TdArchiveReason
.PARAMETER Unarchive
        Specify if you want to unarchive an operator.

.PARAMETER Confirm
    If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

.PARAMETER WhatIf
    If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

.EXAMPLE
    PS> Get-TdOperator -TOPdeskLoginName 'first.last' | Set-TdOperator -Surname 'UpdatedSurname'

    Updates the surname of the first.last operator.

.EXAMPLE
    PS> Set-TdOperator -id $operator.id -password (read-host -assecurestring) -Login

    Update the password for the operator stored in the $operator variable

.EXAMPLE
    PS> Get-TdOperator -TOPdeskLoginName 'first.last' | Set-TdOperator -ArchiveReason (Get-TdArchiveReason 'no longer employed').id -LoginPermission:$false

.EXAMPLE
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Set-TdOperator',
        SupportsShouldProcess = $true)]

    param
    (
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName
        )]
        [Alias('id')]
        $Operator,

        [Parameter(ParameterSetName = 'Modify')]
        [ValidateLength(0, 50)]
        $SurName,

        [Parameter(ParameterSetName = 'Modify')]
        [ValidateLength(0, 30)]
        [string]
        $FirstName,

        [Parameter(ParameterSetName = 'Modify')]
        [ValidateSet('UNDEFINED', 'MALE', 'FEMALE')]
        [string]
        $Gender,

        [Parameter(ParameterSetName = 'Modify')]
        [ValidateLength(0, 20)]
        [string]
        $EmployeeNumber,

        [Parameter(ParameterSetName = 'Modify')]
        [ValidateLength(0, 25)]
        [string]
        $Telephone,

        [Parameter(ParameterSetName = 'Modify')]
        [ValidateLength(0, 25)]
        [string]
        $MobileNumber,

        [Parameter(ParameterSetName = 'Modify')]
        [ValidateLength(0, 100)]
        [string]
        $NetworkLoginName,

        [Parameter(ParameterSetName = 'Modify')]
        [ValidateLength(0, 100)]
        [string]
        $Email,

        [Parameter(ParameterSetName = 'Modify')]
        [string]
        $Branch,

        [Parameter(ParameterSetName = 'Modify')]
        [string]
        $Location,

        [Parameter(ParameterSetName = 'Modify')]
        [string]
        $Department,

        [Parameter(ParameterSetName = 'Modify')]
        [string]
        $BudgetHolder,

        [Parameter(ParameterSetName = 'Modify')]
        [switch]
        $LoginPermission,

        [Parameter(ParameterSetName = 'Modify')]
        [ValidateLength(0, 100)]
        [string]
        $LoginName,

        [Parameter(ParameterSetName = 'Modify')]
        [securestring]
        $Password,

        [Parameter(ParameterSetName = 'Modify')]
        [ValidateSet(
            'installer',
            'firstLineCallOperator',
            'secondLineCallOperator',
            'problemManager',
            'problemOperator',
            'changeCoordinator',
            'changeActivitiesOperator',
            'requestForChangeOperator',
            'extensiveChangeOperator',
            'simpleChangeOperator',
            'scenarioManager',
            'planningActivityManager',
            'projectCoordinator',
            'projectActiviesOperator',
            'stockManager',
            'reservationsOperator',
            'serviceOperator',
            'externalHelpDeskParty',
            'contractManager',
            'operationsOperator',
            'operationsManager',
            'knowledgeBaseManager',
            'accountManager'
        )]
        [string[]]
        $TasksToAdd,

        [Parameter(ParameterSetName = 'Modify')]
        [ValidateSet(
            'installer',
            'firstLineCallOperator',
            'secondLineCallOperator',
            'problemManager',
            'problemOperator',
            'changeCoordinator',
            'changeActivitiesOperator',
            'requestForChangeOperator',
            'extensiveChangeOperator',
            'simpleChangeOperator',
            'scenarioManager',
            'planningActivityManager',
            'projectCoordinator',
            'projectActiviesOperator',
            'stockManager',
            'reservationsOperator',
            'serviceOperator',
            'externalHelpDeskParty',
            'contractManager',
            'operationsOperator',
            'operationsManager',
            'knowledgeBaseManager',
            'accountManager'
        )]
        [string[]]
        $TasksToRemove,

        [Parameter(ParameterSetName = 'Archive')]
        [string]
        $ArchiveReason,

        [Parameter(ParameterSetName = 'Unarchive')]
        [switch]
        $Unarchive
    )

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -level InternalComment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -level InternalComment

        $body = [PSCustomObject]@{}
        $memberParams = @{ Membertype = 'Noteproperty'; InputObject = $body}

        Switch ($PsCmdlet.ParameterSetName) {

            Archive {
                $uri = "$(Get-TdUrl)/tas/api/operators/id/$Operator/archive"

                $memberParams['name'] = 'id'
                $memberParams['value'] = $ArchiveReason
                Add-member @memberParams
                $methodParams = @{
                    Uri = $uri
                    Body = ($body | ConvertTo-Json)
                    Method = 'PATCH'
                }
                if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action "Sending Body: $($Body | Out-String)")) {
                    return
                }
                $res = Invoke-TdMethod @methodParams
                $res
            }

            Unarchive {
                $uri = "$(Get-TdUrl)/tas/api/operators/id/$Operator/unarchive"
                $methodParams = @{
                    Uri = $uri
                    Body = ($body | ConvertTo-Json)
                    Method = 'PATCH'
                }
                if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action "Sending Body: $($Body | Out-String)")) {
                    return
                }
                $res = Invoke-TdMethod @methodParams
                $res
            }

            Modify {
                $uri = "$(Get-TdUrl)/tas/api/operators/id/$Operator"
                Switch ($PSBoundParameters.Keys) {
                    SurName {
                        $memberParams['Name'] = 'surName'
                        $memberParams['Value'] = $surName
                        Add-member @memberParams
                    }
                    firstName {
                        $memberParams['Name'] = 'firstName'
                        $memberParams['Value'] = $firstName
                        Add-Member @memberParams
                    }
                    gender {
                        $memberParams['Name'] = 'gender'
                        $memberParams['Value'] = $gender
                        Add-Member @memberParams
                    }
                    employeeNumber {
                        $memberParams['Name'] = 'employeeNumber'
                        $memberParams['Value'] = $employeeNumber
                        Add-Member @memberParams
                    }
                    telephone {
                        $memberParams['Name'] = 'telephone'
                        $memberParams['Value'] = $telephone
                        Add-Member @memberParams
                    }
                    mobileNumber {
                        $memberParams['Name'] = 'mobileNumber'
                        $memberParams['Value'] = $mobileNumber
                        Add-Member @memberParams
                    }
                    networkLoginName {
                        $memberParams['Name'] = 'networkLoginName'
                        $memberParams['Value'] = $networkLoginName
                        Add-Member @memberParams
                    }
                    email {
                        $memberParams['Name'] = 'email'
                        $memberParams['Value'] = $email
                        Add-Member @memberParams
                    }
                    branch {
                        $memberParams['Name'] = 'branch'
                        $memberParams['Value'] = @{id = $branch}
                        Add-Member @memberParams
                    }
                    location {
                        $memberParams['Name'] = 'location'
                        $memberParams['Value'] = @{id = $location}
                        Add-Member @memberParams
                    }
                    department {
                        $memberParams['Name'] = 'department'
                        $memberParams['Value'] = @{id = $department}
                        Add-Member @memberParams
                    }

                    budgetHolder {
                        $memberParams['Name'] = 'budgetHolder'
                        $memberParams['Value'] = @{id = $budgetHolder}
                        Add-Member @memberParams
                    }
                    loginPermission {
                        $memberParams['Name'] = 'loginPermission'
                        $memberParams['Value'] = $loginPermission.tostring().tolower()
                        Add-Member @memberParams
                    }
                    loginName {
                        $memberParams['Name'] = 'loginName'
                        $memberParams['Value'] = $loginName
                        Add-Member @memberParams
                    }
                    password {
                        $cred = New-Object pscredential ('user', $password)
                        $memberParams['Name'] = 'password'
                        $memberParams['Value'] = $cred.GetNetworkCredential().password
                        Add-Member @memberParams
                    }
                    TaskstoAdd {
                        foreach ($t in $TaskstoAdd) {
                            $body | Add-Member -MemberType NoteProperty -Name $t -Value 'true'
                        }
                    }
                    TaskstoRemove {
                        foreach ($t in $TaskstoRemove) {
                            $body | Add-Member -MemberType NoteProperty -Name $t -Value 'false'
                        }
                    }
                }

                $methodParams = @{
                    Uri = $uri
                    Body = ($body | ConvertTo-Json)
                    Method = 'PATCH'
                }
                if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action "Sending Body: $($Body | Out-String)")) {
                    return
                }
                $res = Invoke-TdMethod @methodParams
                $res

            }
        }
    }

}


function Set-TdOperatorBranchFilter {
    <#
.SYNOPSIS
    Link and unlink branch filters from an operator
.DESCRIPTION
    Link and unlink branch filters from an operator
.PARAMETER Operator
    Id of the operator that you want to link/unlink filters from
.PARAMETER Link
    Ids of the filters that you want to link to the operator
.PARAMETER Unlink
    Ids of the filters that you want to unlink from the operator
.PARAMETER Confirm
    If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
.PARAMETER WhatIf
    If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
.EXAMPLE
    PS C:\> Get-TdOperator -name 'John Smith' | Set-TdOperatorBranchFilter -link (Get-TdBranchFilter -name 'BranchFilter1').id
    Links John Smith to the BranchFilter1 branch filter
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Set-TdOperatorBranchFilter',
        SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('id')]
        $Operator,

        [Parameter(ParameterSetName = 'Link')]
        [string[]]
        $Link,

        [Parameter(ParameterSetName = 'Unlink')]
        [string[]]
        $Unlink
    )

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -Level InternalComment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -Level InternalComment

        $uri = "$(Get-TdUrl)/tas/api/operators/id/$Operator/filters/branch"
        $body = [PSCustomObject]@{}

        switch ($PSBoundParameters.keys) {
            Link {
                $body = [PSCustomObject]@{}
                $memberParams = @{ Membertype = 'Noteproperty'; InputObject = $body}

                foreach ($l in $Link) {
                    $memberParams['Name'] = 'id'
                    $memberParams['Value'] = $l
                    Add-Member @memberParams
                }
                $methodParams = @{
                    Uri = $uri
                    Body = ($body | ConvertTo-Json)
                    Method = 'POST'
                }
                if (($body | ConvertTo-Json).count -eq 1) {
                    $methodParams['body'] = "[$($body | Convertto-json)]"
                }

                if (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action "Sending Request:$($body | ConvertTo-Json)") {
                    $res = Invoke-TdMethod @methodParams
                    $res
                }

            }
            Unlink {
                $body = [PSCustomObject]@{}
                $memberParams = @{ Membertype = 'Noteproperty'; InputObject = $body}
                foreach ($l in $UnLink) {
                    #$memberParams['inputobject'] = $linkBody
                    $memberParams['Name'] = 'id'
                    $memberParams['Value'] = $l
                    Add-Member @memberParams
                }
                $methodParams = @{
                    Uri = $uri
                    Body = ($body | ConvertTo-Json)
                    Method = 'DELETE'
                }
                if (($body | convertto-json).count -eq 1) {
                    $methodParams['body'] = "[$($body | Convertto-json)]"
                }

                if (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action "Sending Request:$($body | ConvertTo-Json)") {
                    $res = Invoke-TdMethod @methodParams
                    $res
                }
            }
        }
    }

}



function Set-TdOperatorCategoryFilter {
    <#
.SYNOPSIS
    Link and unlink Category filters from an operator
.DESCRIPTION
    Link and unlink Category filters from an operator
.PARAMETER Operator
    Id of the operator that you want to link/unlink filters from
.PARAMETER Link
    Ids of the filters that you want to link to the operator
.PARAMETER Unlink
    Ids of the filters that you want to unlink from the operator
.PARAMETER Confirm
    If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
.PARAMETER WhatIf
    If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
.EXAMPLE
    PS C:\> Get-TdOperator -name 'John Smith' | Set-TdOperatorCategoryFilter -link (Get-TdCategoryFilter -name 'CategoryFilter1').id
    Links John Smith to the CategoryFilter1 Category filter
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Set-TdOperatorCategoryFilter',
        SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('id')]
        $Operator,

        [Parameter(ParameterSetName = 'Link')]
        [string[]]
        $Link,

        [Parameter(ParameterSetName = 'Unlink')]
        [string[]]
        $Unlink
    )

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -Level InternalComment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -Level InternalComment

        $uri = "$(Get-TdUrl)/tas/api/operators/id/$Operator/filters/category"
        $body = [PSCustomObject]@{}

        switch ($PSBoundParameters.keys) {
            Link {
                $body = [PSCustomObject]@{}
                $memberParams = @{ Membertype = 'Noteproperty'; InputObject = $body}

                foreach ($l in $Link) {
                    $memberParams['Name'] = 'id'
                    $memberParams['Value'] = $l
                    Add-Member @memberParams
                }
                $methodParams = @{
                    Uri = $uri
                    Body = ($body | ConvertTo-Json)
                    Method = 'POST'
                }
                if (($body | ConvertTo-Json).count -eq 1) {
                    $methodParams['body'] = "[$($body | Convertto-json)]"
                }

                if (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action "Sending Request:$($body | ConvertTo-Json)") {
                    $res = Invoke-TdMethod @methodParams
                    $res
                }

            }
            Unlink {
                $body = [PSCustomObject]@{}
                $memberParams = @{ Membertype = 'Noteproperty'; InputObject = $body}
                foreach ($l in $UnLink) {
                    #$memberParams['inputobject'] = $linkBody
                    $memberParams['Name'] = 'id'
                    $memberParams['Value'] = $l
                    Add-Member @memberParams
                }
                $methodParams = @{
                    Uri = $uri
                    Body = ($body | ConvertTo-Json)
                    Method = 'DELETE'
                }
                if (($body | convertto-json).count -eq 1) {
                    $methodParams['body'] = "[$($body | Convertto-json)]"
                }

                if (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action "Sending Request:$($body | ConvertTo-Json)") {
                    $res = Invoke-TdMethod @methodParams
                    $res
                }
            }
        }
    }

}



function Set-TdOperatorGroup {
    <#
.SYNOPSIS
    Updates operator groups
.DESCRIPTION
    Updates a provided operator group. Requires write permission on operator groups. Can also be used to Archive/Unarchive operator groups.
.PARAMETER OperatorGroup
    Id of the operator group to modify
.PARAMETER Branch
    Id of the branch that is assigned to the operator group
.PARAMETER GroupName
    Operator Group Name
.PARAMETER Contact
    Hashtable containing the values that you want to set. valid properties are telephone, faxNumber, and email.
.PARAMETER ArchiveReason
    The archiving reason id. Mandatory when no default reason is set.
.PARAMETER Archive
    Specify if you want to archive an operator group
.PARAMETER UnArchive
    Specify when you want to bring an operator group from being archived
.PARAMETER Confirm
    If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
.PARAMETER WhatIf
    If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
.EXAMPLE
    PS C:\> Get-TdOperatorGroup 'TechSupport' | Set-TdOperatorGroup -Groupname 'TechSupport New'
    Updates the name of the operator group
.EXAMPLE
    PS> Get-TdOperatorGroup 'HR' | Set-TdOperatorGroup -Contact @{telephone = '123-456-7890'; email = 'test@testing.com'}
    Updates the contact email and telephone.
.EXAMPLE
    PS> Get-TdOperatorGroup 'TechSupport' | Set-TdOperatorGroup -Archive -ArchiveReason (Get-TdArchiveReason 'No Longer Val*').id
    Archives the operator group and applies the archive reason 'No longer valid'
.EXAMPLE
    PS> Get-TdOperatorGroup 'TechSupport' -Archived | Set-TdOperatorGroup -UnArchive
    UnArchive the operator group. Note that we had to specify -Archived on Get-TdOperatorGroup
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Set-TdOperatorGroup',
        SupportsShouldProcess = $true)]
    param
    (
        [Parameter(ParameterSetName = 'Update')]
        $Branch,

        [Parameter(ParameterSetName = 'Update')]
        [ValidateLength(0, 30)]
        [string]
        $GroupName,

        [Parameter(ParameterSetName = 'Update')]
        [hashtable]
        $Contact,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('id')]
        [string]
        $OperatorGroup,

        [Parameter(ParameterSetName = 'Archive')]
        [switch]
        $Archive,

        [Parameter(ParameterSetName = 'Archive')]
        [string]
        $ArchiveReason,

        [Parameter(ParameterSetName = 'UnaArchive')]
        [switch]
        $UnArchive
    )
    process {
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -Level InternalComment
        Write-PSFMessage "ParameterSetName: $($PSCmdlet.ParameterSetName)" -Level InternalComment

        $body = [PSCustomObject]@{}
        $addMemberParams = @{ Membertype = 'Noteproperty'; InputObject = $body}

        switch ($PSCmdlet.ParameterSetName) {
            Update {
                $uri = "$(Get-TdUrl)/tas/api/operatorgroups/id/$OperatorGroup"
                switch ($PSBoundParameters.Keys) {
                    GroupName {
                        $addMemberParams['Name'] = 'groupName'
                        $addMemberParams['Value'] = $GroupName
                        Add-Member @addMemberParams
                    }

                    Branch {
                        $addMemberParams['Name'] = 'branch'
                        $addMemberParams['Value'] = @{id = $Branch}
                        Add-Member @addMemberParams
                    }

                    Contact {
                        $addMemberParams['Name'] = 'contact'
                        $addMemberParams['Value'] = $Contact
                        Add-Member @addMemberParams
                    }

                }

                if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action 'Sending Request')) {
                    return
                }
                $methodParams = @{
                    Uri = $uri
                    Body = ($body | ConvertTo-Json)
                    Method = 'PUT'
                }
                $res = Invoke-TdMethod @methodParams
                $res

            }

            Archive {
                $uri = "$(Get-TdUrl)/tas/api/operatorgroups/id/$OperatorGroup/archive"
                if ($ArchiveReason) {
                    $addMemberParams['Name'] = 'id'
                    $addMemberParams['Value'] = $ArchiveReason
                    Add-member @addMemberParams
                }
                if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action 'Sending Archive Request')) {
                    return
                }
                $methodParams = @{
                    Uri = $uri
                    Body = ($body | ConvertTo-Json)
                    Method = 'PUT'
                }
                $res = Invoke-TdMethod @methodParams
                $res
            }

            UnaArchive {
                $uri = "$(Get-TdUrl)/tas/api/operatorgroups/id/$OperatorGroup/unarchive"

                if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action 'Sending UnArchive Request')) {
                    return
                }
                $methodParams = @{
                    Uri = $uri
                    Method = 'PUT'
                }
                $res = Invoke-TdMethod @methodParams
                $res
            }
        }

    }
}



function Set-TdOperatorOperatorFilter {
    <#
.SYNOPSIS
    Link and unlink Operator filters from an operator
.DESCRIPTION
    Link and unlink Operator filters from an operator
.PARAMETER Operator
    Id of the operator that you want to link/unlink filters from
.PARAMETER Link
    Ids of the filters that you want to link to the operator
.PARAMETER Unlink
    Ids of the filters that you want to unlink from the operator
.PARAMETER Confirm
    If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
.PARAMETER WhatIf
    If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
.EXAMPLE
    PS C:\> Get-TdOperator -name 'John Smith' | Set-TdOperatorOperatorFilter -link (Get-TdOperatorFilter -name 'OperatorFilter1').id
    Links John Smith to the OperatorFilter1 Operator filter
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Set-TdOperatorOperatorFilter',
        SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('id')]
        $Operator,

        [Parameter(ParameterSetName = 'Link')]
        [string[]]
        $Link,

        [Parameter(ParameterSetName = 'Unlink')]
        [string[]]
        $Unlink
    )

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -Level InternalComment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -Level InternalComment

        $uri = "$(Get-TdUrl)/tas/api/operators/id/$Operator/filters/operator"
        $body = [PSCustomObject]@{}

        switch ($PSBoundParameters.keys) {
            Link {
                $body = [PSCustomObject]@{}
                $memberParams = @{ Membertype = 'Noteproperty'; InputObject = $body}

                foreach ($l in $Link) {
                    $memberParams['Name'] = 'id'
                    $memberParams['Value'] = $l
                    Add-Member @memberParams
                }
                $methodParams = @{
                    Uri = $uri
                    Body = ($body | ConvertTo-Json)
                    Method = 'POST'
                }
                if (($body | ConvertTo-Json).count -eq 1) {
                    $methodParams['body'] = "[$($body | Convertto-json)]"
                }

                if (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action "Sending Request:$($body | ConvertTo-Json)") {
                    $res = Invoke-TdMethod @methodParams
                    $res
                }

            }
            Unlink {
                $body = [PSCustomObject]@{}
                $memberParams = @{ Membertype = 'Noteproperty'; InputObject = $body}
                foreach ($l in $UnLink) {
                    $memberParams['Name'] = 'id'
                    $memberParams['Value'] = $l
                    Add-Member @memberParams
                }
                $methodParams = @{
                    Uri = $uri
                    Body = ($body | ConvertTo-Json)
                    Method = 'DELETE'
                }
                if (($body | convertto-json).count -eq 1) {
                    $methodParams['body'] = "[$($body | Convertto-json)]"
                }

                if (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action "Sending Request:$($body | ConvertTo-Json)") {
                    $res = Invoke-TdMethod @methodParams
                    $res
                }
            }
        }
    }

}



function Set-TdOperatorOperatorGroup {
    <#
.SYNOPSIS
    Link and unlink operator groups from an operator
.DESCRIPTION
    link and unlink operator groups from an operator
.PARAMETER OperatorId
    Id of the operator that you want to link/unlink operator groups from
.PARAMETER LinkId
    ids of groups that you want to link
.PARAMETER UnlinkId
    ids of groups that you want to unlink.
.PARAMETER Confirm
    If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
.PARAMETER WhatIf
    If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
.EXAMPLE
    PS C:\> Get-TdOperator 'Test User' | Set-TdOperatorOperatorGroup -LinkId (Get-TdOperatorGroup 'Group1').id
    Link the group1 operatorgroup to Test User
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Set-TdOperatorOperatorGroup',
        SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('id')]
        $OperatorId,

        [Parameter(ParameterSetName = 'Link')]
        [string[]]
        $LinkId,

        [Parameter(ParameterSetName = 'Unlink')]
        [string[]]
        $UnlinkId
    )

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -Level InternalComment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -Level InternalComment

        $uri = "$(Get-TdUrl)/tas/api/operators/id/$OperatorId/operatorgroups"
        $body = [PSCustomObject]@{}
        switch ($PSBoundParameters.keys) {
            LinkId {
                $body = [PSCustomObject]@{}
                $memberParams = @{ Membertype = 'Noteproperty'; InputObject = $body}

                foreach ($l in $LinkId) {
                    $memberParams['Name'] = 'id'
                    $memberParams['Value'] = $l
                    Add-Member @memberParams
                }
                $methodParams = @{
                    Uri = $uri
                    Body = ($body | ConvertTo-Json)
                    Method = 'POST'
                }
                if (($body | ConvertTo-Json).count -eq 1) {
                    $methodParams['body'] = "[$($body | Convertto-json)]"
                }

                if (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action "Sending Request:$($body | ConvertTo-Json)") {
                    $res = Invoke-TdMethod @methodParams
                    $res
                }

            }
            UnlinkId {
                $body = [PSCustomObject]@{}
                $memberParams = @{ Membertype = 'Noteproperty'; InputObject = $body}
                foreach ($l in $UnLinkId) {
                    $memberParams['Name'] = 'id'
                    $memberParams['Value'] = $l
                    Add-Member @memberParams
                }
                $methodParams = @{
                    Uri = $uri
                    Body = ($body | ConvertTo-Json)
                    Method = 'DELETE'
                }
                if (($body | convertto-json).count -eq 1) {
                    $methodParams['body'] = "[$($body | Convertto-json)]"
                }

                if (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action "Sending Request:$($body | ConvertTo-Json)") {
                    $res = Invoke-TdMethod @methodParams
                    $res
                }
            }
        }
    }
}



function Set-TdOperatorPermissionGroup {
    <#
.SYNOPSIS
    Link and unlink operator groups from an operator
.DESCRIPTION
    link and unlink operator groups from an operator
.PARAMETER Operator
    Id of the operator that you want to link/unlink operator groups from
.PARAMETER Link
ids of groups that you want to link
.PARAMETER Unlink
ids of groups that you want to unlink
.PARAMETER Confirm
    If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
.PARAMETER WhatIf
    If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
.EXAMPLE
    PS C:\> Get-TdOperator 'Test User' | Set-TdOperatorPermissionGroup -Link (Get-TdPermissionGroup 'Group1').id
    Link the group1 PermissionGroup to Test User
#>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Set-TdOperatorPermissionGroup',
        SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('id')]
        $Operator,

        [Parameter(ParameterSetName = 'Link')]
        [string[]]
        $Link,

        [Parameter(ParameterSetName = 'Unlink')]
        [string[]]
        $Unlink
    )

    process {
        Write-PsfMessage "ParameterSetName: $($PsCmdlet.ParameterSetName)" -Level InternalComment
        Write-PSfMessage "PSBoundParameters: $($PSBoundParameters | Out-String)" -Level InternalComment

        $uri = "$(Get-TdUrl)/tas/api/operators/id/$Operator/permissiongroups"
        $body = [PSCustomObject]@{}
        switch ($PSBoundParameters.keys) {
            Link {
                $body = [PSCustomObject]@{}
                $memberParams = @{ Membertype = 'Noteproperty'; InputObject = $body}

                foreach ($l in $Link) {
                    $memberParams['Name'] = 'id'
                    $memberParams['Value'] = $l
                    Add-Member @memberParams
                }
                $methodParams = @{
                    Uri = $uri
                    Body = ($body | ConvertTo-Json)
                    Method = 'POST'
                }
                if (($body | ConvertTo-Json).count -eq 1) {
                    $methodParams['body'] = "[$($body | Convertto-json)]"
                }

                if (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action "Sending Request:$($body | ConvertTo-Json)") {
                    $res = Invoke-TdMethod @methodParams
                    $res
                }

            }
            Unlink {
                $body = [PSCustomObject]@{}
                $memberParams = @{ Membertype = 'Noteproperty'; InputObject = $body}
                foreach ($l in $UnLink) {
                    $memberParams['Name'] = 'id'
                    $memberParams['Value'] = $l
                    Add-Member @memberParams
                }
                $methodParams = @{
                    Uri = $uri
                    Body = ($body | ConvertTo-Json)
                    Method = 'DELETE'
                }
                if (($body | convertto-json).count -eq 1) {
                    $methodParams['body'] = "[$($body | Convertto-json)]"
                }

                if (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action "Sending Request:$($body | ConvertTo-Json)") {
                    $res = Invoke-TdMethod @methodParams
                    $res
                }
            }
        }
    }
}



function Set-TdPerson {
    <#
    .SYNOPSIS
        Modify properties on a person
    .DESCRIPTION
        Creates new persons in TOPdesk. Logged in operator must have:
        Write permissions on persons; Branch filters apply
        Login data write permissions to set login name and password
    .PARAMETER PersonId
        The Id of the person you are interacting with.
    .PARAMETER Surname
        Surname of the person
    .PARAMETER BranchId
        Id of the person's branch. This is mandatory. See examples for mobileNumber
    .PARAMETER FirstName
        Firstname of the person
    .PARAMETER FirstInitials
        Firstinitials of the person
    .PARAMETER Prefixes
        Prefixes of the person
    .PARAMETER Gender
        Gender of the user. default value is 'UNDEFINED'
    .PARAMETER EmployeeNumber
        EmployeeNumber of the user
    .PARAMETER NetworkLoginName
        NetworkLoginName for the user
    .PARAMETER LocationId
        LocationId of the person
    .PARAMETER DepertmentId
        DepartmentId of the person
    .PARAMETER DepartmentFree
            Department text-field (has to be used when “Modules Settings > Supporting Files > Department(person) > Plain text field” is set)
    .PARAMETER TasLoginName
        Login name, operator requires permission “Settings > Login Settings”
    .PARAMETER Password
        Password, operator requires permission "Settings > Login Settings". Is mandatory when “Functional Settings > Login Settings > Self Service Portal > Password mandatory on Person card” is set.
    .PARAMETER PhoneNumber
        PhoneNumber of the person
    .PARAMETER MobileNumber
        MobileNumber of the person
    .PARAMETER Fax
        Fax of the person
    .PARAMETER Email
        Email address of the user.
    .PARAMETER JobTitle
        Job title of the person
    .PARAMETER showBudgetholder
        Person can see requests with the same budget holder
    .PARAMETER showDepartment
        Person can see requests with the same department
    .PARAMETER ShowBranch
        Person can see requests with the same branch
    .PARAMETER showSubsidiaries
        Person can see requests with subsidiary branches (showBranches has to be true as well)
    .PARAMETER AuthorizeAll
    Person Person can authorize requests with the same department, budget holder, branch or subsidiary branch (only works when the person is a manager)
    .PARAMETER AuthorizeDepartment
    Person can authorize requests from the same department (only works when the person is a manager)
   .PARAMETER AuthorizeBudgetHolder
   Person can authorize requests with the same budget holder (only works when the person is a manager)
   .PARAMETER AuthorizeBranch
        Person can authorize requests from the same branch (only works when the person is a manager)
    .PARAMETER authorizeSubsidiaryBranches
        Person can authorize requests from the subsidiary branches (only works when the person is a manager and authorizeBranch is true)
   .PARAMETER IsManager
        Specify if the person is a manager
    .PARAMETER ManagerId
        Id of the person's manager.
    .PARAMETER BudgetHolderId
        The Id of the person's budgetholder
    .PARAMETER DepartmentId
        The Id of the person's department
    .PARAMETER Confirm
		If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

	.PARAMETER WhatIf
		If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

    .EXAMPLE
        PS C:\> Set-TdPerson -LastName 'Doe' -BranchId (Get-TdBranch -Name 'Los Angeles').id
        Updates the Lastname and Branch
    .EXAMPLE
        PS C:\> New-TdPerson -LastName 'Doe' -FirstName 'John' -NetworkLoginName 'john.doe@company.com' -BranchId (Get-TdBranch -Name 'Los Angeles').id
        This creates a user with serveral properties and uses Get-TdBranch to get the branch id.
        #>
    [CmdletBinding(DefaultParameterSetName = 'BranchName',
        SupportsShouldProcess = $true,
        HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Set-TdPerson')]
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [string]$PersonId,

        [Alias('LastName')]
        [string]$Surname,

        [string]$BranchId,
        [string]$FirstName,
        [string]$FirstInitials,
        [string]$Prefixes,
        [string]$Gender = 'UNDEFINED',
        [string]$EmployeeNumber,
        [string]$NetworkLoginName,
        [string]$LocationId,
        [string]$DepartmentId,
        [string]$DepartmentFree,
        [string]$TasLoginName,
        [securestring]$Password,
        [string]$PhoneNumber,
        [string]$MobileNumber,
        [string]$Fax,

        [alias('EmailAddress')]
        [string]$Email,

        [string]$JobTitle,
        [switch]$ShowBudgetholder,
        [switch]$ShowDepartment,
        [switch]$ShowBranch,
        [switch]$ShowSubsidiaries,
        [switch]$AuthorizeAll,
        [switch]$AuthorizeDepartment,
        [switch]$AuthorizeBudgetHolder,
        [switch]$AuthorizeBranch,
        [switch]$AuthorizeSubsidiaryBranches,
        [switch]$IsManager,
        [string]$ManagerId,
        [string]$BudgetholderID
    )

    process {

        $uri = (Get-TdUrl) + "/tas/api/persons/id/$PersonId"
        Write-PSFMessage "uri -$uri" -Level InternalComment


        $body = [PSCustomObject]@{}
        switch ($PSBoundParameters.Keys) {
            Surname {
                $Body | Add-Member -MemberType NoteProperty -Name 'surName' -Value $Surname
            }
            FirstName {
                $Body | Add-Member -MemberType NoteProperty -Name 'firstName' -Value $FirstName
            }
            FirstInitials {
                $Body | Add-Member -MemberType NoteProperty -Name 'firstInitials' -Value $FirstInitials
            }
            Prefixes {
                $Body | Add-Member -MemberType NoteProperty -Name prefixes -Value $Prefixes
            }
            Gender {
                $Body | Add-Member -MemberType NoteProperty -Name 'gender' -Value $Gender
            }
            EmployeeNumber {
                $Body | Add-Member -MemberType NoteProperty -Name 'employeeNumber' -Value $EmployeeNumber
            }
            NetworkLoginName {
                $Body | Add-Member -MemberType NoteProperty -Name 'networkLoginName' -Value $NetworkLoginName
            }
            DepartmentFree {
                $Body | Add-Member -MemberType NoteProperty -Name 'departmentFree' -Value $DepartmentFree
            }
            TasLoginName {
                $Body | Add-Member -MemberType NoteProperty -Name 'tasLoginName' -Value $TasLoginName
            }
            Password {
                $cred = New-Object pscredential ('user', $Password)
                $Body | Add-Member -MemberType NoteProperty -Name 'password' -Value $cred.getnetworkcredential().password
            }
            PhoneNumber {
                $Body | Add-Member -MemberType NoteProperty -Name 'phoneNumber' -Value $PhoneNumber
            }
            MobileNumber {
                $Body | Add-Member -MemberType NoteProperty -Name 'mobileNumber' -Value $MobileNumber
            }
            Fax {
                $Body | Add-Member -MemberType NoteProperty -Name 'fax' -Value $Fax
            }
            Email {
                $Body | Add-Member -MemberType NoteProperty -Name 'email' -Value $Email
            }
            JobTitle {
                $Body | Add-Member -MemberType NoteProperty -Name 'jobTitle' -Value $JobTitle
            }
            showBudgetholder {
                $Body | Add-Member -MemberType NoteProperty -Name 'showBudgetholder' -Value $showBudgetholder.ToString().ToLower()
            }
            showDepartment {
                $Body | Add-Member -MemberType NoteProperty -Name 'showDepartment' -Value $showDepartment.ToString().ToLower()
            }
            showSubsidiaries {
                $Body | Add-Member -MemberType NoteProperty -Name 'showSubsidiaries' -Value $showSubsidiaries.ToString().ToLower()
            }
            authorizeAll {
                $Body | Add-Member -MemberType NoteProperty -Name 'authorizeAll' -Value $authorizeAll.ToString().ToLower()
            }
            authorizeDepartment {
                $Body | Add-Member -MemberType NoteProperty -Name 'authorizeDepartment' -Value $authorizeDepartment.ToString().ToLower()
            }
            authorizeBudgetholder {
                $Body | Add-Member -MemberType NoteProperty -Name 'authorizeBudgetholder' -Value $authorizeBudgetholder.ToString().ToLower()
            }
            authorizeBranch {
                $Body | Add-Member -MemberType NoteProperty -Name 'authorizeBranch' -Value $authorizeBranch.ToString().ToLower()
            }
            authorizeSubsidiaryBranches {
                $Body | Add-Member -MemberType NoteProperty -Name 'authorizeSubsidiaryBranches' -Value $authorizeSubsidiaryBranches.ToString().ToLower()
            }
            isManager {
                $Body | Add-Member -MemberType NoteProperty -Name 'isManager' -Value $isManager.ToString().ToLower()
            }

            BranchId {
                $branchIdObject = @{
                    id = $BranchId
                }
                $Body | Add-Member -MemberType NoteProperty -Name 'branch' -Value $branchIdObject
            }

            managerId {
                $managerIdObject = @{
                    id = $managerId
                }
                $Body | Add-Member -MemberType NoteProperty -Name 'manager' -Value $managerIdObject
            }
            budgetHolderId {
                $budgetHolderIdObject = @{
                    id = $budgetHolderId
                }
                $Body | Add-Member -MemberType NoteProperty -Name 'budgetHolder' -Value $budgetHolderIdObject
            }

            locationId {
                $locationIdObject = @{
                    id = $locationId
                }
                $Body | Add-Member -MemberType NoteProperty -Name 'locationId' -Value $locationIdObject
            }

            departmentId {
                $departmentIdObject = @{
                    id = $departmentId
                }
                $Body | Add-Member -MemberType NoteProperty -Name 'departmentId' -Value $departmentIdObject
            }
        }

       	$Params = @{
            Uri = $uri
            Body = $Body | ConvertTo-Json
            Method = 'put'
        }
        if ($PSCmdlet.ShouldProcess("The changes" , "Changing person $PersonId")) {
            Invoke-TdMethod @Params
        }
    }
}


function Send-TdNotification {
    <#
    .SYNOPSIS
        Create custom task notifications
    .DESCRIPTION
        Uses the TOPdesk Task Notification api to display task notifications. This can display toast notifications through both Chrome and Firefox.
    .PARAMETER Title
        The title of the custom notification. It will be displayed as the first line of the notification.
    .PARAMETER Body
        The body of the custom notification. It will be displayed as the second line of the notification.
    .PARAMETER Url
        A link that will be opened if the receiver of the notification clicks on the notification. It must start with '/tas/secure/’
    .PARAMETER OperatorId
        List of operator UUIDs to specify which operators this task notification will be sent to. Both ‘operatorGroupIds’ and 'operatorIds can’t be empty at the same time. Non-existing operators will be silently ignored.
    .PARAMETER OperatorGroupId
        List of operator group UUIDs to specify which operators this task notification will be sent to. Both ‘operatorGroupIds’ and ‘operatorIds’ can’t be empty at the same time. Non-existing operator groups will be silently ignored.
    .EXAMPLE
        PS C:\> Send-TdNotification -Title 'Example notification' -Body 'Your assistance is needed' -OperatorId (Get-TdOperator 'FirstLast@company.com').id
        Sends a notificiation
    #>
    [CmdletBinding(HelpUri = 'https://andrewpla.github.io/TOPdeskPS/commands/Send-TdNotification')]
    param (
        [system.string]
        [Parameter(Mandatory)]
        $Title,

        [system.string]
        $Body,

        [ValidateScript( {
                if ($_ -notlike '/tas/secure/*') {
                    throw 'Url must start with /tas/secure/'
                }
                $true
            })]
        [system.string]
        $Url,

        [Parameter(ParameterSetName = 'Operator', Mandatory)]
        [string[]]
        $OperatorId,

        [Parameter(ParameterSetName = 'OperatorGroup', Mandatory)]
        [string[]]
        $OperatorGroupId
    )
    [array]$OperatorId = $OperatorId
    [array]$OperatorGroupId = $OperatorGroupId

    $uri = "$(Get-TdUrl)/tas/api/tasknotifications/custom"

    $internalBody = [PSCustomObject]@{
        title = $Title
    }
    if ($Body) {$internalBody |Add-Member -Name 'body' -Value $Body -MemberType noteproperty}
    if ($url) {$internalBody | Add-Member -Name 'url' -Value $url -MemberType noteproperty}


    if ($OperatorId) { $internalBody | Add-Member -Name 'operatorIds' -Value $operatorId -MemberType noteproperty }
    if ($OperatorGroupId) { $internalBody | Add-Member -Name 'operatorGroupIds' -Value $operatorGroupId -MemberType noteproperty }
    $Params = @{
        'Uri' = $Uri
        'Body' = $internalBody | ConvertTo-Json
        'Method' = 'Post'
    }
    Invoke-TdMethod @Params
}


$params = @{
	
	Module	    = 'TOPdeskPS';
	Name	    = 'url';
	Value	    = $null;
	Initialize  = $true;
	Validation  = 'string'
	Description = 'This is the address of your TOPdesk instance. EX: Company.TopDesk.net '
}
Set-PSFConfig @params

$params = @{
	
	Module	    = 'TOPdeskPS';
	Name	    = 'TdCategory';
	Value	    = $null;
	Initialize  = $true;
	Validation  = 'string'
	Description = 'These are the categories from your TOPdesk environment'
}
Set-PSFConfig @params

<#
# Example:
Register-PSFTeppScriptblock -Name "TOPdeskPS.alcohol" -ScriptBlock { 'Beer','Mead','Whiskey','Wine','Vodka','Rum (3y)', 'Rum (5y)', 'Rum (7y)' }
#>

<#
# Example:
Register-PSFTeppArgumentCompleter -Command Get-Alcohol -Parameter Type -Name TOPdeskPS.alcohol
#>

New-PSFLicense -Product 'TOPdeskPS' -Manufacturer 'AndrewPla' -ProductVersion $PSModuleVersion -ProductType Module -Name MIT -Version "1.0.0.0" -Date (Get-Date "2018-08-11") -Text @"
Copyright (c) 2018 AndrewPla

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"@
#endregion Load compiled code

