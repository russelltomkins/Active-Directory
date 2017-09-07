<#
  .SYNOPSIS
  Name: DC-TLSandCert-Audit.ps1

  Version: 1.1
  Author: Russell Tomkins - Microsoft Premier Field Engineer
  Blog: https://aka.ms/russellt

  Performs an audit of all TLS Protocols and Certificates from
  all AD Forest Domain Controllers

  Source: https://www.github.com/russelltomkins/Active-Directory
  
  Massive Credits to Chris Duck for the TLS protocol checking logic
  Source: http://blog.whatsupduck.net/2014/10/checking-ssl-and-tls-versions-with-powershell.html
#>

# -----------------------------------------------------------------------------------
# Delegate Callback for SslStream.AuthenticateAsClient
# -----------------------------------------------------------------------------------#
$RemoteCertificateValidationCallback  = {
    param (
        [object] $Sender,
        [System.Security.Cryptography.X509Certificates.X509Certificate] $Certificate,
        [System.Security.Cryptography.X509Certificates.X509Chain] $Chain,
        [System.Net.Security.SslPolicyErrors] $SslPolicyErrors
    )
    
    # Extract the appropraite failure reason
	If ($SSLPolicyErrors.ToString() -eq 'RemoteCertificateChainErrors'){
		$Row.ErrorStatus = $Chain.ChainStatus[0].StatusInformation}
	Else{
		$Row.ErrorStatus = $SSLPolicyErrors.ToString()}

	# Always Return True so the SSLStream doesn't close and we can't extract the Certificate.
	return $True
}


# -----------------------------------------------------------------------------------
# Test-LDAPS Function
# -----------------------------------------------------------------------------------

function Test-LDAPS ($ServerName){

    # Extract the SSL Protocols
    $ProtocolNames = [System.Security.Authentication.SslProtocols] | gm -static -MemberType Property | ?{$_.Name -notin @("Default","None")} | %{$_.Name}

    # Build the Custom PSO
	$Row = '' | select Server,Port,SSL2,SSL3,TLS,TLS11,TLS12,ErrorStatus,Subject,SAN,Issuer,ValidFrom, ValidTo, ThumbPrint,Keylength,SignatureAlgorithm,V1TemplateName,V2TemplateName,SKI,AKI,BKU,EKU,AppPolicies
	$Row.Server = $ServerName
	$Row.Port = $Port

    # Loop through each SSL/TLS Protocol
	ForEach($ProtocolName in $ProtocolNames){
	       
           $Socket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
	       $Socket.Connect($ServerName, $Port)
	       try {
			$NetStream = New-Object System.Net.Sockets.NetworkStream($Socket, $true)
			$SslStream = New-Object System.Net.Security.SslStream($NetStream, $false, $RemoteCertificateValidationCallback)
			$SslStream.AuthenticateAsClient($ServerName, $Null, $ProtocolName, $false )
			$Row.$ProtocolName = $true
	        $RemoteCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SslStream.RemoteCertificate	
        } catch  {
            $Row.$ProtocolName = $false
        } finally {
            If($RemoteCertificate){
			    
                # Grab the Basics
                $Row.Subject = $RemoteCertificate.Subject
				$Row.Issuer = $RemoteCertificate.Issuer
				$Row.ValidFrom = $RemoteCertificate.NotBefore
				$Row.ValidTo = $RemoteCertificate.NotAfter
				$Row.Thumbprint = $RemoteCertificate.Thumbprint
				$Row.Keylength = $RemoteCertificate.PublicKey.Key.KeySize
		        $Row.SignatureAlgorithm = $RemoteCertificate.SignatureAlgorithm.FriendlyName

                # Grab the Trickier Ones
				Try {$Row.SAN = ($RemoteCertificate.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.17'}).Format(0)} Catch{}
				Try {$Row.V1TemplateName = ($RemoteCertificate.Extensions | Where-Object {$_.Oid.Value -eq '1.3.6.1.4.1.311.20.2'}).Format(0)} Catch{}
				Try {$Row.V2TemplateName = ($RemoteCertificate.Extensions | Where-Object {$_.Oid.Value -eq '1.3.6.1.4.1.311.21.7'}).Format(0)} Catch{}
				Try {$Row.SKI = ($RemoteCertificate.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.14'}).Format(0)} Catch{}
				Try {$Row.AKI = ($RemoteCertificate.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.35'}).Format(0)} Catch{}
				Try {$Row.BKU = ($RemoteCertificate.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.15'}).Format(0)} Catch{}
				Try {$Row.EKU = ($RemoteCertificate.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.37'}).Format(0)} Catch{}
				Try {$Row.AppPolicies = ($RemoteCertificate.Extensions | Where-Object {$_.Oid.Value -eq '1.3.6.1.4.1.311.21.10'}).Format(0)} Catch{}
				Try {$Row.CDP = ($RemoteCertificate.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.31'}).Format(0)} Catch{}
				Try {$Row.AIA = ($RemoteCertificate.Extensions | Where-Object {$_.Oid.Value -eq '1.3.6.1.5.5.7.1.1'}).Format(0)} Catch{}
			}
			$SslStream.Close()
        }	# End Try/Catch/Finally
    }	# End For
    $Global:DC_Certs+= $Row
}
# -----------------------------------------------------------------------------------
# End of Test-LDAPS Function
# -----------------------------------------------------------------------------------
# -----------------------------------------------------------------------------------
# Main Script
# -----------------------------------------------------------------------------------

# Some Prep Work
Import-Module ActiveDirectory
$Port = "636"	# Optionally you could use 3269 for GC-S
$ForestDCs = @()	# Our list of all Forest domain controllers
$Global:DC_Certs = @()		# Our list of DC's and their certificate status

# Lets retrieve every domain controller in the forest
$ADForest = Get-ADForest
ForEach($Domain in $ADForest.Domains) {
	$DomainDCs = Get-ADDomainController -server $Domain -Filter *
	$ForestDCS += $DomainDCs.HostName 
	}

# Loop through all of our DC's and retrieve their certificate status.
ForEach($ServerName in $ForestDCs)
	{
	Test-LDAPS ($ServerName)
	}

#Export it Out and also Display

$DC_Certs | out-gridview -Title "Domain Controller TLS and Certificate Audit"
$DC_Certs | export-csv -notypeinformation -path .\DC-TLSandCert-Audit.csv
Write-Host $DC_Certs.Count "records saved to .\DC-TLSandCert-Audit.csv"

# -----------------------------------------------------------------------------------
# End of Script
# -----------------------------------------------------------------------------------

