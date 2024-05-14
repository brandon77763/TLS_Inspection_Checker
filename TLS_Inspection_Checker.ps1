# Function to get the SSL certificate from a URL
function Get-SslCertificate {
    param (
        [string]$url,
        [int]$port
    )

    try {
        $client = New-Object System.Net.Sockets.TcpClient($url, $port)
        $sslStream = New-Object System.Net.Security.SslStream($client.GetStream(), $false, ({ $true }))

        try {
            $sslStream.AuthenticateAsClient($url)
            $cert = $sslStream.RemoteCertificate
            $sslStream.Close()
            $client.Close()
            return $cert
        } catch [System.Security.Authentication.AuthenticationException] {
            $errorMessage = $_.Exception.Message
            Write-Host "Certificate error: $errorMessage"
            return $null
        }
    } catch {
        $errorMessage = $_.Exception.Message
        Write-Host "Failed to connect to $url : $errorMessage"
        return $null
    }
}

# Function to check for "Cato" in the certificate chain
function Check-TlsInspection {
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert
    )

    # Get the certificate chain
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.Build($cert) | Out-Null

    $inspectionDetected = $false

    foreach ($chainElement in $chain.ChainElements) {
        if ($chainElement.Certificate.Subject -like "*SomeTextInCert*") {
            $inspectionDetected = $true
            break
        }
    }

    return $inspectionDetected
}

# Main loop
while ($true) {
    Clear-Host
    Write-Host "This script is used to determine if InterCertAuth is doing TLS inspection on a specific site." -ForegroundColor Blue
    Write-Host "Please enter the website URL below (e.g., google.com)" -ForegroundColor Blue
    $url = Read-Host "Website URL"
    $port = 443

    $cert = Get-SslCertificate -url $url -port $port

    if ($cert -ne $null) {
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cert)
        $inspectionDetected = Check-TlsInspection -cert $cert

        if ($inspectionDetected) {
            Write-Host "TLS inspection detected for $url. 'Cato' found in certificate chain." -ForegroundColor Red
        } else {
            Write-Host "No TLS inspection detected for $url. 'Cato' not found in certificate chain." -ForegroundColor Green
        }
    } else {
        Write-Host "Could not retrieve the certificate for $url." -ForegroundColor Yellow
    }

    Write-Host "Press Enter to check another website, or close the script to exit."
    Read-Host
}
