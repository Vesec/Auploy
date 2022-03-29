


Set-Hostname
Install-WindowsFeature
New-NetFirewallRule -DisplayName "Allow IPv4 Ping Inbound" -Name "Allow IPv4 Ping Inbound" -direction Inbound -IcmpType 8 -Protocol ICMPv4 -Action Allow
New-NetFirewallRule -DisplayName "Allow IPv4 Ping Outbound" -Name "Allow IPv4 Ping Outbound" -direction Outbound -IcmpType 8 -Protocol ICMPv4 -Action Allow