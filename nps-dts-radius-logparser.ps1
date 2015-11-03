# Log parser for MS NPS dts RADIUS logs
# v 0.0.2 / 20120412
# Author: Jochen Bartl <jochen.bartl@gmail.com>
# Contributor: CircaLucid

Param(
  [string]$filename,
  [string]$filter
)
if(-not($filename)){$filename = Read-Host "File Name?" }

$AUTHENTICATION_TYPE = @{
    1 = "PAP";
    2 = "CHAP";
    3 = "MS-CHAP";
    4 = "MS-CHAP v2";
    5 = "EAP";
    7 = "None";
    8 = "Custom";
    11 = "PEAP";
}

$PACKET_TYPES = @{
	1 = "Access-Request";
	2 = "Access-Accept";
	3 = "Access-Reject";
	4  = "Accounting-Request";
	11 = "Access-Challenge";
}

$REASON_CODES = @{
	0 = "IAS_SUCCESS";
	1 = "IAS_INTERNAL_ERROR";
	2 = "IAS_ACCESS_DENIED";
	3 = "IAS_MALFORMED_REQUEST";
	4 = "IAS_GLOBAL_CATALOG_UNAVAILABLE";
	5 = "IAS_DOMAIN_UNAVAILABLE";
	6 = "IAS_SERVER_UNAVAILABLE";
	7 = "IAS_NO_SUCH_DOMAIN";
	8 = "IAS_NO_SUCH_USER";
	16 = "IAS_AUTH_FAILURE";
	17 = "IAS_CHANGE_PASSWORD_FAILURE";
	18 = "IAS_UNSUPPORTED_AUTH_TYPE";
	32 = "IAS_LOCAL_USERS_ONLY";
	33 = "IAS_PASSWORD_MUST_CHANGE";
	34 = "IAS_ACCOUNT_DISABLED";
	35 = "IAS_ACCOUNT_EXPIRED";
	36 = "IAS_ACCOUNT_LOCKED_OUT";
	37 = "IAS_INVALID_LOGON_HOURS";
	38 = "IAS_ACCOUNT_RESTRICTION";
	48 = "IAS_NO_POLICY_MATCH";
	64 = "IAS_DIALIN_LOCKED_OUT";
	65 = "IAS_DIALIN_DISABLED";
	66 = "IAS_INVALID_AUTH_TYPE";
	67 = "IAS_INVALID_CALLING_STATION";
	68 = "IAS_INVALID_DIALIN_HOURS";
	69 = "IAS_INVALID_CALLED_STATION";
	70 = "IAS_INVALID_PORT_TYPE";
	71 = "IAS_INVALID_RESTRICTION";
	80 = "IAS_NO_RECORD";
	96 = "IAS_SESSION_TIMEOUT";
	97 = "IAS_UNEXPECTED_REQUEST";
}

$i = 0
foreach ($line in gc $filename) {
    if(!$line.StartsWith("<")){ continue; }
    if($filter -and !($line.Contains($filter))){ continue; }
    $logline = ([xml]$line).Event
    "Timestamp          : "+$logline.Timestamp."#text"
    "ComputerName       : "+$logline."Computer-Name"."#text"
    "NpPolicyName       : "+$logline."NP-Policy-Name"."#text"
    "ProxyPolicyName    : "+$logline."Proxy-Policy-Name"."#text"
    "EventSource        : "+$logline."Event-Source"."#text"
    "UserName           : "+$logline."User-Name"."#text"
    "ClientIpAddress    : "+$logline."Client-IP-Address"."#text"
    "ClientVendor       : "+$logline."Client-Vendor"."#text"
    "ClientFriendlyName : "+$logline."Client-Friendly-Name"."#text"
    "SamAccountName     : "+$logline."SAM-Account-Name"."#text"
    "AuthenticationType : $($logline.'Authentication-Type'.'#text') ($($AUTHENTICATION_TYPE[[int]$logline.'Authentication-Type'.'#text']))"
    if($logline.'Packet-Type'.'#text' -ne "3"){ $color = "white" } else { $color = "red" }
    Write-Host "PacketType         : $($logline.'Packet-Type'.'#text') ($($PACKET_TYPES[[int]$logline.'Packet-Type'.'#text']))" -ForeGroundColor $color
    if($logline.'Reason-Code'.'#text' -eq "0"){ $color = "white" } else { $color = "red" }
    Write-Host "ReasonCode         : $($logline.'Reason-Code'.'#text') ($($REASON_CODES[[int]$logline.'Reason-Code'.'#text']))" -ForeGroundColor $color
    ""
    $i++
}
"Parsed $i packets"
