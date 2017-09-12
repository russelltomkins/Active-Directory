<#
  .SYNOPSIS
  Name: Query-KerberosDelegations.ps1
  Version: 1.0
  Author: Russell Tomkins - Microsoft Premier Field Engineer
  Blog: https://aka.ms/russellt

  Source: https://www.github.com/russelltomkins/Active-Directory

  .DESCRIPTION
  Queries an Active Directory Domain for all accounts with the ability to
  delegate credentials to other Kerberos enabled services
  
  Refer to this blog post for more details
  https://blogs.technet.microsoft.com/russellt/2017/04/11/understanding-kerberos-delegation

  .EXAMPLE
  Query local Domain Controller foer Kerberos Delegations
  .\Query-KerberosDelegations.ps1 

  .EXAMPLE
  Query a remote Domain Controller for Kerberos Delegations 
  .\Query-KerberosDelegations.ps1 

  .PARAMETER Server
  The FQDN of the domain controller to query. Can be short name if search suffix 
    
  LEGAL DISCLAIMER
  This Sample Code is provided for the purpose of illustration only and is not
  intended to be used in a production environment.  THIS SAMPLE CODE AND ANY
  RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
  EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
  MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant You a
  nonexclusive, royalty-free right to use and modify the Sample Code and to
  reproduce and distribute the object code form of the Sample Code, provided
  that You agree: (i) to not use Our name, logo, or trademarks to market Your
  software product in which the Sample Code is embedded; (ii) to include a valid
  copyright notice on Your software product in which the Sample Code is embedded;
  and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and
  against any claims or lawsuits, including attorneys fees, that arise or result
  from the use or distribution of the Sample Code.
   
  This posting is provided "AS IS" with no warranties, and confers no rights. Use
  of included script samples are subject to the terms specified
  at http://www.microsoft.com/info/cpyright.htm.
  #>
# -----------------------------------------------------------------------------------
# Main Script
# -----------------------------------------------------------------------------------
[CmdletBinding()]
    Param (
    [Parameter(Mandatory=$false)][ValidateNotNullOrEmpty()][String]$Server="localhost")
# Initialize the Output object, AD attributes and Get-ADObject Queries (I know, to 
# lazy to craft and ldap filter)
$Rows = @()
$Properties = "useraccountcontrol","msDS-LastSuccessfulInteractiveLogonTime","lastLogonTimestamp","msDS-AllowedToDelegateTo","SAMAccountName","servicePrincipalName"
$Queries = @{	'Kerberos Only Unconstrained Delegation' ='(useraccountcontrol -band 524288)'; `
		'Kerberos Only Constrained Delegation'='(msDS-AllowedToDelegateTo -like "*")'; `
		'Any Authentication Protocol Constrained' = '(useraccountcontrol -band  "16777216") -and (msDS-AllowedToDelegateTo -like "*")'; `
		'Any Authentication Protocol Unconstrained' = '(useraccountcontrol -band  "16777216") -and (msDS-AllowedToDelegateTo -notlike "*")'}

# Loop through each Configuration Type
ForEach($Query in $Queries.Keys){
	ForEach($Result in (Get-ADObject -Filter $Queries.Item($Query) -Properties $Properties)) {
		$Row = "" | Select Name,Type,DelegationType,SAMAccountName,SPN,TargetSPN,LastLogon,DN
		$Row.Name = $Result.Name
		$Row.SAMAccountName = $Result.SAMAccountName
		$Row.SPN = $Result.servicePrincipalName -Join "|"
		$Row.Type = (Get-Culture).TextInfo.ToTitleCase($Result.ObjectClass)
		$Row.DelegationType = $Query
		If ($Result."msDS-AllowedToDelegateTo" -ne $Null){$Row.TargetSPN = $Result."msDS-AllowedToDelegateTo" -Join "|"}
		Else { $Row.TargetSPN = "Unconstrained"}
		If ($Result.lastLogonTimestamp -ne $Null){$Row.LastLogon = [datetime]$Result.lastLogonTimestamp} 
		Else {$Row.LastLogon = "Null"}
		$Row.DN = $Result.DistinguishedName
		$Rows += $Row
	}
}
# Spit it all out
$Rows | Export-CSV -NoTypeInformation ".\KerberosDelegation.csv"
Write-Host $Rows.Count"Kerberos delegations written to .\KerberosDelegation.csv" -ForeGroundColor Green
# -----------------------------------------------------------------------------
# End of Script
# -----------------------------------------------------------------------------
