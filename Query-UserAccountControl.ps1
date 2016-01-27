<#-----------------------------------------------------------------------------
Russell Tomkins
Microsoft Premier Field Engineer

Name:           Query-UserAccountControl.ps1
Description:    Exports an individual CSV for each UAC Flag all User and 
                Computer accounts. Assists in identifying accounts with 
                specific configurations such as Kerberos Delegations.
Usage:          .\Query-UserAccountControl.ps1 [-Server <domaincontrollerfqdn>]
                .\Query-UserAccountControl.ps1 -Server "dc1.contoso.com"
                Simply execute the script in the folder you wish to generate 
                the .CSV files into. Results will only include accounts the 
                executing user has privileges to read the userAccountControl
                attribute of. 
                If the server is in another domain, the calling user must also
                have privileges to query that domain. 
Date:           1.0 - 27-01-2016 - RT - Initial Release
                1.1 - 27-01-2016 - RT - Minor Updates
-------------------------------------------------------------------------------
Disclaimer
The sample scripts are not supported under any Microsoft standard support 
program or service. 
The sample scripts are provided AS IS without warranty of any kind. Microsoft
further disclaims all implied warranties including, without limitation, any 
implied warranties of merchantability or of fitness for a particular purpose.
The entire risk arising out of the use or performance of the sample scripts and 
documentation remains with you. In no event shall Microsoft, its authors, or 
anyone else involved in the creation, production, or delivery of the scripts be
liable for any damages whatsoever (including, without limitation, damages for 
loss of business profits, business interruption, loss of business information, 
or other pecuniary loss) arising out of the use of or inability to use the 
sample scripts or documentation, even if Microsoft has been advised of the 
possibility of such damages.
-----------------------------------------------------------------------------#>
# -----------------------------------------------------------------------------
# Begin Main Script
# -----------------------------------------------------------------------------
# Prepare Variables
Param (
        [parameter(Mandatory=$false,Position=0)][String]$Server = "localhost")
               
# Build the Lookup HashTable. 
# More details can be found here 
# https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx

$UACLookUp = @{1 = "SCRIPT|0x0001";
                2 = "ACCOUNTDISABLE|0x0002";
                8 = "HOMEDIR_REQUIRED|0x0008";
                16 = "LOCKOUT|0x0010";
                32 = "PASSWD_NOTREQD|0x0020";
                64 = "PASSWD_CANT_CHANGE|0x0040";
                128 = "ENCRYPTED_TEXT_PWD_ALLOWED|0x0080";
                256 = "TEMP_DUPLICATE_ACCOUNT|0x0100";
                512 = "NORMAL_ACCOUNT|0x0200";
                2048 = "INTERDOMAIN_TRUST_ACCOUNT|0x0800";
                4096 = "WORKSTATION_TRUST_ACCOUNT|0x1000";
                8192 = "SERVER_TRUST_ACCOUNT|0x2000";
                65536 = "DONT_EXPIRE_PASSWORD|0x10000";
                131072 = "MNS_LOGON_ACCOUNT|0x20000";
                262144 = "SMARTCARD_REQUIRED|0x40000";
                524288 = "TRUSTED_FOR_DELEGATION|0x80000";
                1048576 = "NOT_DELEGATED|0x100000";
                2097152 = "USE_DES_KEY_ONLY|0x200000";
                4194304 = "DONT_REQ_PREAUTH|0x400000";
                8388608 = "PASSWORD_EXPIRED|0x800000";
                16777216 = "TRUSTED_TO_AUTH_FOR_DELEGATION|0x1000000";
                67108864 = "PARTIAL_SECRETS_ACCOUNT|0x04000000"}

#Loop through each Bitwise value and generate a CSV for affected User and Computer Accounts
ForEach($Value in $UACLookUp.Keys){
	
	# Prepare Our Variables
	$Description = $UACLookup.Item($Value)
	$FileName = $Description.Split("|",2)[0]
	$Filter = "useraccountcontrol -band $Value"
	$Properties = "useraccountcontrol","msDS-LastSuccessfulInteractiveLogonTime","lastLogonTimestamp"

	# Grab the details for both User and Computer Accounts and Output to CSV
	Get-ADUser -Server $Server -Filter $Filter -Properties $Properties| Export-CSV -NoTypeInformation "U-$FileName.csv"
    Get-ADComputer -Server $Server -Filter $Filter -Properties $Properties| Export-CSV -NoTypeInformation "C-$FileName.csv"
} # Process the Next UAC Value

# -----------------------------------------------------------------------------
# End of Script
# -----------------------------------------------------------------------------

