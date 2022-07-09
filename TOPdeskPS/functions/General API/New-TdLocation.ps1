function New-TdLocation {
    <#
	.SYNOPSIS
		
	.DESCRIPTION
		
    .PARAMETER branchID
        The ID of the branch.
    .PARAMETER locationName
        The name of the new location.
	.EXAMPLE
        PS C:\> 
	#>

    [CmdletBinding(HelpUri = 'https://developers.topdesk.com/explorer/?page=supporting-files#/Locations/createLocation',
        SupportsShouldProcess = $true)]
    param
    (
		[Parameter(Mandatory = $true)]
		[system.string]
		$branchID,

		[Parameter(Mandatory = $true)]
		[system.string]
		$locationName

    )

    process {
        Write-PSFMessage -Level InternalComment -Message "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        $uri = (Get-TdUrl) + "/tas/api/locations"

		$branch = [PSCustomObject]@{
		    "id" = $branchID
		}

        $body = [PSCustomObject]@{
		'name' = $locationName
		'branch' = $branch 
		}

		Write-PSFMessage "$($Body | ConvertTo-Json | Out-String)" -Level debug

	   $params = @{
            'Uri' = $uri
            'Body' = $body | ConvertTo-Json
            'Method' = 'Post'
        }
        if (-not (Test-PSFShouldProcess -PSCmdlet $PSCmdlet -Target $uri -Action 'Geting dropdown option id.')) {
            return
        }
        Invoke-TdMethod @params | Select-Object -ExpandProperty id
    }
}
