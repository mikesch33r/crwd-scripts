These scripts can be useful for different tasks in coordination with CrowdStrike Falcon. 

Split-File: useful way to break a large file up for upload to Falcon using RTR 'get' file command. 

PSFalcon-DuplicateIOAExclusionAcrossChildCIDs: used with PSFalcon module to copy an IOA exclusion that was created in one child CID and recreate that same exclusion across all of the other child CIDs in a multi-tenant Falcon architecture.

PSFalcon-DuplicateIOARuleAcrossChildCIDs:
  Take an API client/secret from the parent as input
  Also take the child/parent CID value and the IOA rule name (that you already created) as inputs
  Find the IOA rule you created and store the information about the rule
  Find the IOA rule group for said rule and store its information
  In other child CIDs (or in a list of CIDs you specify in the optional parameter “MemberCids”…)
    Check to see if the IOA rule group already exists
      Create the IOA rule group if not
    Re-create the IOA rule in the IOA rule group
  Wait a few seconds for rate limiting, and then move on to the next CID

PSFalcon-GetActiveHostsAcrossMemberCIDs:
  Take an API from the parent as input, quickly authenticate through each child/member CID and gather a host count of active hosts in the last 7 days. Write the results to a CSV file.
