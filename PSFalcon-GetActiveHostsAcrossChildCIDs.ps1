# Copyright CrowdStrike 2023

# By accessing or using this script, sample code, application programming interface, tools, and/or associated documentation (if any) (collectively, “Tools”), You (i) represent and warrant that You are entering into this Agreement on behalf of a company, organization or another legal entity (“Entity”) that is currently a customer or partner of CrowdStrike, Inc. (“CrowdStrike”), and (ii) have the authority to bind such Entity and such Entity agrees to be bound by this Agreement.
# CrowdStrike grants Entity a non-exclusive, non-transferable, non-sublicensable, royalty free and limited license to access and use the Tools solely for Entity’s internal business purposes and in accordance with its obligations under any agreement(s) it may have with CrowdStrike. Entity acknowledges and agrees that CrowdStrike and its licensors retain all right, title and interest in and to the Tools, and all intellectual property rights embodied therein, and that Entity has no right, title or interest therein except for the express licenses granted hereunder and that Entity will treat such Tools as CrowdStrike’s confidential information.
# THE TOOLS ARE PROVIDED “AS-IS” WITHOUT WARRANTY OF ANY KIND, WHETHER EXPRESS, IMPLIED OR STATUTORY OR OTHERWISE. CROWDSTRIKE SPECIFICALLY DISCLAIMS ALL SUPPORT OBLIGATIONS AND ALL WARRANTIES, INCLUDING WITHOUT LIMITATION, ALL IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT. IN NO EVENT SHALL CROWDSTRIKE BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THE TOOLS, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Directions:
# Be sure that you have an API in your Parent CID with Hosts: Read & Write permissions and Flight Control: Read permission.
# Run the script and add the parameters required when prompted ($ClientID, $ClientSecret).

#Requires -Version 5.1
using module @{ ModuleName = 'PSFalcon'; ModuleVersion = '2.0' }

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\w{32}$')]
    [string] $ClientId,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\w{40}$')]
    [string] $ClientSecret,

    [Parameter()]
    [ValidateSet('eu-1', 'us-gov-1', 'us-1', 'us-2')]
    [string] $Cloud,

    [Parameter()]
    [ValidatePattern('^\w{32}$')]
    [array] $MemberCids

)

begin {
    $TokenParam = @{}
    @('ClientId', 'ClientSecret', 'Cloud').foreach{
        if ($PSBoundParameters.$_) {
            $TokenParam[$_] = $PSBoundParameters.$_
        }
    }
    if (!$MemberCids) {
        # Gather available Member CIDs
        Request-FalconToken @TokenParam
        if ((Test-FalconToken).Token -eq $true) {
            [array] $MemberCids = (Get-FalconMemberCid -Detailed -All | Where-Object {
                $_.status -eq 'active' }).child_cid
            Revoke-FalconToken
        }
    }
}

process {
    
    #Generate CSV file
    $outputPath = "falcon-hostcount-$(Get-Date -Format 'yyyy-MM-dd-HHmm').csv"
    "CID,falcon-hostcount" | Out-File -FilePath $outputPath -Force
    
    #Calculate date for host filter
    $sevenDaysAgo = (Get-Date).AddDays(-7).ToString("yyyy-MM-dd")
    $filter = "last_seen:>='$sevenDaysAgo'"


    #Gather host count per child CID
    foreach ($Cid in $MemberCids) {
        try {
            Request-FalconToken @TokenParam -MemberCid $Cid
            if ((Test-FalconToken).Token -eq $true) {
                # Check for active hosts
                $activeHosts = Get-FalconHost -Filter $filter
                $activeHostCount = ($activeHosts | Measure-Object).Count
                
                #Write to console
                Write-Host "Active Falcon hosts within CID $cid in the past 7 days: $activeHostCount"

                #Append to CSV file
                "$cid,$activeHostCount" | Out-File -FilePath $outputPath -Append
            }
        } catch {
            Write-Error $_
        } finally {
            if ((Test-FalconToken).Token -eq $true) {
                Revoke-FalconToken
            }
            Start-Sleep -Seconds 5
        }
    }
Write-Host "Complete! Host Counts saved to $outputPath"
}
