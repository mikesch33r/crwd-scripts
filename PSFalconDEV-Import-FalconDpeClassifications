<#
.SYNOPSIS
    Import Falcon Data Protection Classifications from CSV

.DESCRIPTION
    Reads a CSV file containing exported Data Protection Classifications and creates them in a
    target Falcon CID. Each classification name is appended with "_local" to distinguish from
    the originals. Classification properties including rules are parsed from JSON and recreated
    with proper data type handling for arrays and null values.

.PARAMETER CsvPath
    Path to the CSV file containing exported classifications

.PARAMETER ClientId
    Falcon API Client ID (32-character string)

.PARAMETER ClientSecret
    Falcon API Client Secret (40-character string)

.PARAMETER Cloud
    Falcon cloud region (optional). Valid values: eu-1, us-gov-1, us-1, us-2

.PARAMETER MemberCid
    Child CID to import into (optional, for Flight Control/MSSP environments)

.EXAMPLE
    .\Import-FalconDpeClassifications.ps1 -CsvPath "FalconDpeClassifications_20260407_143022.csv" -ClientId "abc123..." -ClientSecret "xyz789..."
    Imports classifications from CSV into a parent CID, appending "_local" to each name

.EXAMPLE
    .\Import-FalconDpeClassifications.ps1 -CsvPath "export.csv" -ClientId "abc123..." -ClientSecret "xyz789..." -MemberCid "child-cid-87654321"
    Imports classifications into a specific child CID in a Flight Control environment

.NOTES
    Requires PSFalcon module version 2.0 or higher
        As of April 2026, this script uses the dev branch of PSFalcon. Available here: https://github.com/CrowdStrike/psfalcon/tree/dev
        Update line 38 to indicate the location of your dev version of PSFalcon
    Creates an import results CSV file: FalconDpeClassifications_ImportResults_YYYYMMDD_HHMMSS.csv
    Auto-generated fields (id, created_time_stamp, modified_time_stamp) are removed from rules before import
#>

#Requires -Version 5.1
using module "PATHTOYOURDEVBRANCHOFPSFALCON/psfalcon-dev/PSFalcon.psm1"

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$CsvPath,
    
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
            
            # Verify CSV file exists
            if (-not (Test-Path $CsvPath)) {
                Write-Error "CSV file not found: $CsvPath"
                return
            }
            
            # Import classifications from CSV
            Write-Host "Reading classifications from CSV..." -ForegroundColor Cyan
            $classifications = Import-Csv -Path $CsvPath
            
            if (-not $classifications -or $classifications.Count -eq 0) {
                Write-Warning "No classifications found in CSV file."
                return
            }
            
            Write-Host "Found $($classifications.Count) classification(s) to import" -ForegroundColor Green
            
            # Track results
            $successCount = 0
            $failureCount = 0
            $results = @()
            
            # Create each classification in the new tenant
            foreach ($classification in $classifications) {
                # Add "_local" suffix to the name
                $newName = "$($classification.name)_local"
                
                Write-Host "`nProcessing: $($classification.name) -> $newName" -ForegroundColor Cyan
                
                try {
                    # Convert classification_properties from JSON string back to object
                    $classificationProps = $null
                    if ($classification.classification_properties -and 
                        $classification.classification_properties -ne "" -and 
                        $classification.classification_properties -ne "null") {
                        
                        # Parse the JSON string to a PowerShell object
                        $classificationProps = $classification.classification_properties | ConvertFrom-Json -Depth 10
                        
                        # Fix data type issues and remove auto-generated fields in rules
                        if ($classificationProps.rules) {
                            $cleanedRules = @()
                            
                            foreach ($rule in $classificationProps.rules) {
                                # Create a new rule object with only the fields we want to send
                                $cleanedRule = @{}
                                
                                # Copy over the fields we want, excluding auto-generated ones
                                $fieldsToInclude = @(
                                    'description',
                                    'detection_severity',
                                    'enable_local_application_groups',
                                    'enable_printer_egress',
                                    'enable_usb_devices',
                                    'enable_web_locations',
                                    'notify_end_user',
                                    'response_action',
                                    'trigger_detection',
                                    'user_scope',
                                    'web_locations_scope'
                                )
                                
                                foreach ($field in $fieldsToInclude) {
                                    if ($rule.PSObject.Properties[$field]) {
                                        $cleanedRule[$field] = $rule.$field
                                    }
                                }
                                
                                # Handle array fields specially
                                # Fix web_locations
                                if ($rule.PSObject.Properties['web_locations']) {
                                    if ($rule.web_locations -is [string]) {
                                        if ($rule.web_locations -eq "null" -or $rule.web_locations -eq "") {
                                            $cleanedRule['web_locations'] = $null
                                        } else {
                                            $cleanedRule['web_locations'] = @($rule.web_locations)
                                        }
                                    } elseif ($rule.web_locations -eq $null) {
                                        $cleanedRule['web_locations'] = $null
                                    } else {
                                        $cleanedRule['web_locations'] = $rule.web_locations
                                    }
                                }
                                
                                # Fix ad_groups
                                if ($rule.PSObject.Properties['ad_groups']) {
                                    if ($rule.ad_groups -is [string]) {
                                        if ($rule.ad_groups -eq "null" -or $rule.ad_groups -eq "") {
                                            $cleanedRule['ad_groups'] = $null
                                        } else {
                                            $cleanedRule['ad_groups'] = @($rule.ad_groups)
                                        }
                                    } elseif ($rule.ad_groups -eq $null) {
                                        $cleanedRule['ad_groups'] = $null
                                    } else {
                                        $cleanedRule['ad_groups'] = $rule.ad_groups
                                    }
                                }
                                
                                # Fix ad_users
                                if ($rule.PSObject.Properties['ad_users']) {
                                    if ($rule.ad_users -is [string]) {
                                        if ($rule.ad_users -eq "null" -or $rule.ad_users -eq "") {
                                            $cleanedRule['ad_users'] = $null
                                        } else {
                                            $cleanedRule['ad_users'] = @($rule.ad_users)
                                        }
                                    } elseif ($rule.ad_users -eq $null) {
                                        $cleanedRule['ad_users'] = $null
                                    } else {
                                        $cleanedRule['ad_users'] = $rule.ad_users
                                    }
                                }
                                
                                # Fix local_application_groups
                                if ($rule.PSObject.Properties['local_application_groups']) {
                                    if ($rule.local_application_groups -is [string]) {
                                        if ($rule.local_application_groups -eq "null" -or $rule.local_application_groups -eq "") {
                                            $cleanedRule['local_application_groups'] = $null
                                        } else {
                                            $cleanedRule['local_application_groups'] = @($rule.local_application_groups)
                                        }
                                    } elseif ($rule.local_application_groups -eq $null) {
                                        $cleanedRule['local_application_groups'] = $null
                                    } else {
                                        $cleanedRule['local_application_groups'] = $rule.local_application_groups
                                    }
                                }
                                
                                # Convert hashtable to PSCustomObject
                                $cleanedRules += [PSCustomObject]$cleanedRule
                            }
                            
                            # Replace the rules with cleaned versions
                            $classificationProps.rules = $cleanedRules
                        }
                        
                        Write-Host "  Parsed $($classificationProps.rules.Count) rule(s)" -ForegroundColor Gray
                    }
                    
                    # Create the classification in the new tenant with "_local" suffix
                    if ($classificationProps) {
                        $newClassification = New-FalconDpeClassification -Name $newName -ClassificationProperties $classificationProps
                    } else {
                        $newClassification = New-FalconDpeClassification -Name $newName
                    }
                    
                    if ($newClassification) {
                        Write-Host "  ✓ Successfully created: $newName" -ForegroundColor Green
                        Write-Host "    New ID: $($newClassification.id)" -ForegroundColor Gray
                        $successCount++
                        
                        $results += [PSCustomObject]@{
                            OriginalName = $classification.name
                            NewName      = $newName
                            OriginalId   = $classification.id
                            NewId        = $newClassification.id
                            Status       = "Success"
                            Error        = $null
                        }
                    } else {
                        Write-Warning "  ✗ Failed to create: $newName - No response received"
                        $failureCount++
                        
                        $results += [PSCustomObject]@{
                            OriginalName = $classification.name
                            NewName      = $newName
                            OriginalId   = $classification.id
                            NewId        = $null
                            Status       = "Failed"
                            Error        = "No response received"
                        }
                    }
                    
                } catch {
                    Write-Warning "  ✗ Failed to create: $newName"
                    Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Red
                    $failureCount++
                    
                    $results += [PSCustomObject]@{
                        OriginalName = $classification.name
                        NewName      = $newName
                        OriginalId   = $classification.id
                        NewId        = $null
                        Status       = "Failed"
                        Error        = $_.Exception.Message
                    }
                }
            }
            
            # Summary
            Write-Host "`n========================================" -ForegroundColor Cyan
            Write-Host "Import Summary" -ForegroundColor Cyan
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host "Total classifications processed: $($classifications.Count)" -ForegroundColor White
            Write-Host "Successfully created: $successCount" -ForegroundColor Green
            Write-Host "Failed: $failureCount" -ForegroundColor $(if ($failureCount -gt 0) { "Red" } else { "White" })
            
            # Export results to CSV
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $resultsFile = "FalconDpeClassifications_ImportResults_$timestamp.csv"
            $results | Export-Csv -Path $resultsFile -NoTypeInformation -Encoding UTF8
            
            $resultsPath = (Resolve-Path $resultsFile).Path
            Write-Host "`nImport results saved to: $resultsPath" -ForegroundColor Yellow
            
            # Display detailed results
            Write-Host "`nDetailed Results:" -ForegroundColor Cyan
            $results | Format-Table OriginalName, NewName, OriginalId, NewId, Status -AutoSize
            
            # Show failures if any
            if ($failureCount -gt 0) {
                Write-Host "`nFailed Classifications:" -ForegroundColor Red
                $results | Where-Object { $_.Status -eq "Failed" } | 
                    Format-Table OriginalName, NewName, Error -AutoSize
            }
        }
        
    } catch {
        Write-Error $_
    } finally {
        if ((Test-FalconToken).Token -eq $true) {
            Revoke-FalconToken
        }
    }
}
