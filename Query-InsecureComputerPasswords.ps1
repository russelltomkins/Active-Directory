<#
  .SYNOPSIS
  Name: Query-InsecureComputerPasswords.ps1
  Version: 1.0
  Author: Russell Tomkins - Microsoft Premier Field Engineer
  Blog: https://aka.ms/russellt
  Source: https://www.github.com/russelltomkins/Active-Directory

  .DESCRIPTION
  Queries an Active Directory Domain for all computer accounts and attempts to login
  to them with the default reset password or a blank password.

  .EXAMPLE
  .\Query-InsecureComputerPasswords.ps1
  Quees the Domain for all Computer accounts with insecure password


  .EXAMPLE
  .\Query-InsecureComputerPasswords.ps1 -Server "dc1.contoso.com" -SearchBase "OU=Workstations,DC=contoso,DC=com"
  Queries an OU/Container for all Computer accounts with insecure passwords against DC1.contoso.com 

  .PARAMETER Server
  The FQDN of the AD Domain Controller to execute the query against. Default is localhost.

  .PARAMETER SearchBase
  Provide the full DistinguishedName of the organizational unit or container to begin the search at.
    
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
  [Parameter(Mandatory=$false)][ValidateNotNullOrEmpty()][String]$Server="localhost",
	[Parameter(Mandatory=$false)][ValidateNotNullOrEmpty()][String]$SearchBase)

# Preparation
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
$DSAccountManagement = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Domain')
$Rows = @()

# Retrieve all of the computer accounts form the Domain or OU.
If ($SerachBase) {
	$AllComputers = Get-ADObject -LDAPFilter '(objectClass=Computer)' -properties sAMAccountName,WhenCreated,pwdLastSet,LastLogonTimeStamp -SearchBase $SearchBase }
else {
	$AllComputers = Get-ADObject -LDAPFilter '(objectClass=Computer)' -properties sAMAccountName,WhenCreated,pwdLastSet,LastLogonTimeStamp}

# Loop through every returned computer account

ForEach($Computer in $AllComputers){

	# Attempt to login with a blank Password
	If ($DSAccountManagement.ValidateCredentials($Computer.sAMAccountName,'')) {
    	$Row = "" | Select PasswordType,DistinguishedName,sAMAccountName,WhenCreated,pwdLastSet,LastLogonTimeStamp
  	$Row.PasswordType = "Blank"
	$Row.DistinguishedName = $Computer.DistinguishedName
    	$Row.sAMAccountName = $Computer.sAMAccountName
	$Row.WhenCreated = $Computer.WhenCreated
	$Row.pwdLastSet = [DateTime]::FromFileTime($Computer.pwdLastSet)
	$Row.LastLogonTimeStamp = [DateTime]::FromFileTime($Computer.LastLogonTimeStamp)
    	
    
    # Add it to our collection and proceed to the next account
    $Rows += $Row
    Continue
	}

	# Try a Default Reset Password - First 14 characters of sAMAccountName in lowercase
	# Strip the $ sign and reduce to 14 characters if longer.
	$ResetPassword = ($Computer.sAMAccountName).replace('$','').ToLower()
	If($RestPassword.Length -ge 13){
		$ResetPassword = ($ResetPassword.SubString(0,14))
  }

  # Attempt to auth with the reset password
  If ($DSAccountManagement.ValidateCredentials($Computer.sAMAccountName,$ResetPassword)) {
	$Row = "" | Select PasswordType,DistinguishedName,sAMAccountName,WhenCreated,pwdLastSet,LastLogonTimeStamp
  	$Row.PasswordType = "Reset"
	$Row.DistinguishedName = $Computer.DistinguishedName
    	$Row.sAMAccountName = $Computer.sAMAccountName
	$Row.WhenCreated = $Computer.WhenCreated
	$Row.pwdLastSet = [DateTime]::FromFileTime($Computer.pwdLastSet)
	$Row.LastLogonTimeStamp = [DateTime]::FromFileTime($Computer.LastLogonTimeStamp)
    
    # Add it to our collection and proceed to the next account
    $Rows += $Row
  }
} # Next computer account

# Dump it all out to a CSV.
$Rows | Out-Gridview -Wait -Title "Insecure Computer Passwords"
Write-Host $Rows.Count "records saved to .\InsecureComputerPasswords.csv"
$Rows | Export-CSV -NoTypeInformation .\InsecureComputerPasswords.csv

# -----------------------------------------------------------------------------------
# End of Main Script
# -----------------------------------------------------------------------------------