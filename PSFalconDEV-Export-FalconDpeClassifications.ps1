<#
.SYNOPSIS
    Export Falcon Data Protection Classifications to CSV

.DESCRIPTION
    Retrieves all Data Protection Classifications and their detailed information from a Falcon CID
    and exports them to a CSV file. The classification properties (including rules) are serialized
    to JSON format within the CSV for easy import into another tenant.

.PARAMETER ClientId
    Falcon API Client ID (32-character string)

.PARAMETER ClientSecret
    Falcon API Client Secret (40-character string)

.PARAMETER Cloud
    Falcon cloud region (optional). Valid values: eu-1, us-gov-1, us-1, us-2

.PARAMETER MemberCid
    Child CID to export from (optional, for Flight Control/MSSP environments)

.EXAMPLE
    .\Export-FalconDpeClassifications.ps1 -ClientId "abc123..." -ClientSecret "xyz789..."
    Exports all DPE classifications from a parent CID to a timestamped CSV file

.EXAMPLE
    .\Export-FalconDpeClassifications.ps1 -ClientId "abc123..." -ClientSecret "xyz789..." -MemberCid "child-cid-12345678"
    Exports all DPE classifications from a specific child CID in a Flight Control environment

.NOTES
    Requires PSFalcon module version 2.0 or higher
        As of April 2026, this script uses the dev branch of PSFalcon. Available here: https://github.com/CrowdStrike/psfalcon/tree/dev
        Update line 38 to indicate the location of your dev version of PSFalcon
    Output file format: FalconDpeClassifications_YYYYMMDD_HHMMSS.csv
#>

#Requires -Version 5.1
using module "PATHTOYOURDEVBRANCHOFPSFALCON/psfalcon-dev/PSFalcon.psm1"

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidatePattern('^\w{32}$')]
    [string]$ClientId,
    
    [Parameter(Mandatory=$true)]
    [ValidatePattern('^\w{40}$')]
    [string]$ClientSecret,
    
    [Parameter()]
    [ValidateSet('eu-1', 'us-gov-1', 'us-1', 'us-2')]
    [string]$Cloud,
    
    [Parameter()]
    [ValidatePattern('^\w{32}$')]
    [string]$MemberCid
)

begin {
    # Build token parameters
    $TokenParam = @{}
    @('ClientId', 'ClientSecret', 'Cloud', 'MemberCid').foreach{
        if ($PSBoundParameters.$_) {
            $TokenParam[$_] = $PSBoundParameters.$_
        }
    }
}

process {
    try {
        # Authenticate
        Request-FalconToken @TokenParam
        
        if ((Test-FalconToken).Token -eq $true) {
            Write-Host "✓ Authentication successful" -ForegroundColor Green
            
            # Step 1: Get all Data Protection Classification IDs
            Write-Host "Retrieving Data Protection Classification IDs..." -ForegroundColor Cyan
            $classificationIds = Get-FalconDpeClassification -All
            
            if (-not $classificationIds -or $classificationIds.Count -eq 0) {
                Write-Warning "No classifications found."
                return
            }
            
            Write-Host "Found $($classificationIds.Count) classification(s)" -ForegroundColor Green
            
            # Step 2: Retrieve detailed information for each classification
            Write-Host "Retrieving detailed information..." -ForegroundColor Cyan
            $classificationDetails = @()
            
            # Get detailed information for all classifications
            $details = Get-FalconDpeClassification -Ids $classificationIds
            
            if ($details) {
                foreach ($detail in $details) {
                    Write-Host "  Processing: $($detail.name)" -ForegroundColor Gray
                    
                    # Flatten classification_properties for better CSV export
                    $flattenedDetail = [PSCustomObject]@{
                        id                        = $detail.id
                        cid                       = $detail.cid
                        name                      = $detail.name
                        created_by                = $detail.created_by
                        modified_by               = $detail.modified_by
                        modified_at               = $detail.modified_at
                        classification_properties = if ($detail.classification_properties) { 
                            ($detail.classification_properties | ConvertTo-Json -Compress -Depth 10) 
                        } else { 
                            $null 
                        }
                    }
                    
                    $classificationDetails += $flattenedDetail
                }
            }
            
            if ($classificationDetails.Count -eq 0) {
                Write-Warning "No classification details retrieved."
                return
            }
            
            # Step 3: Save details to CSV file
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $outputFile = "FalconDpeClassifications_$timestamp.csv"
            
            Write-Host "Exporting to CSV: $outputFile" -ForegroundColor Cyan
            $classificationDetails | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
            
            # Get the full path of the exported file
            $fullPath = (Resolve-Path $outputFile).Path
            
            Write-Host "`nExport complete!" -ForegroundColor Green
            Write-Host "Total classifications exported: $($classificationDetails.Count)" -ForegroundColor Green
            Write-Host "File location: $fullPath" -ForegroundColor Yellow
            
            # Display summary
            Write-Host "`nSummary:" -ForegroundColor Cyan
            $classificationDetails | Format-Table id, name, created_by, modified_at -AutoSize
        }
        
    } catch {
        Write-Error $_
    } finally {
        if ((Test-FalconToken).Token -eq $true) {
            Revoke-FalconToken
        }
    }
}
