// YARA ENGINE TO DETECT NETWORK RESOURCE USAGE
import "pe"

rule Detect_HTTP_Network_Activity
{
    meta:
        description = "Detects files attempting to access network resources"
        author = "ChatGPT"

    strings:
        $http_methods = /GET|POST|PUT|DELETE/
        $ip_address = /[0-9]{1,3}(\.[0-9]{1,3}){3}/
        $url_pattern = /(http|https):\/\/[a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,}/
        $WinHttpOpen = "WinHttpOpen" ascii
        $WinHtpOpenRequest = "WinHttpOpenRequest" ascii
        $WinHttpConnect = "WinHttpConnect" ascii
        $WinHttpSendRequest = "WinHttpSendRequest" ascii
        $InternetOpen = "InternetOpen" ascii
        $InternetOpenUrl = "InternetOpenUrl" ascii
        $HttpOpenRequest = "HttpOpenRequest" ascii
        $HttpSendRequest = "HttpSendReqest" ascii
 
    condition:
        any of them
}

rule Detect_Network_Syscalls
{
    meta:
        description = "Detects system calls associated with network usage"
        author = "ChatGPT"

    strings:
        // Basic Network Operations
        $socket = "socket" ascii
        $bind = "bind" ascii
        $listen = "listen" ascii
        $accept = "accept" ascii
        $connect = "connect" ascii

        // Data Transmission
        $send = "send" ascii
        $recv = "recv" ascii
        $sendto = "sendto" ascii
        $recvfrom = "recvfrom" ascii
        $sendmsg = "sendmsg" ascii
        $recvmsg = "recvmsg" ascii

        // Socket Options and Information
        $getsockname = "getsockname" ascii
        $getpeername = "getpeername" ascii
        $getsockopt = "getsockopt" ascii
        $setsockopt = "setsockopt" ascii

        // Advanced Socket Operations
        $shutdown = "shutdown" ascii
        $socketpair = "socketpair" ascii

        // Network Interface Management
        $ioctl = "ioctl" ascii

    condition:
        any of them
}

rule Detect_File_Access
{
    strings:
        $CreateFile = "CreateFile" ascii
        $CopyFile = "CopyFile" ascii
        $MoveFile = "MoveFile" ascii
        $DeleteFile = "DeleteFile" ascii
        $FindFirstFile = "FindFirstFile" ascii
        $FindNextFile = "FindNextFile" ascii

    condition:
        any of them
}

// TEMPORARILY COMMENTED OUT TO TEST OTHER CODE
// FEEL FREE TO UNCOMMENT - MITCH 12/05/24

// rule Detect_Network_DLLs
// {
//     meta:
//         description = "Detect executables importing common network-related DLLs"
//         author = "ChatGPT"

//     strings:
//         $ws2_32 = "ws2_32.dll" nocase
//         $mswsock = "mswsock.dll" nocase
//         $wininet = "wininet.dll" nocase
//         $winhttp = "winhttp.dll" nocase
//         $dnsapi = "dnsapi.dll" nocase
//         $wship6 = "wship6.dll" nocase
//         $rpcrt4 = "rpcrt4.dll" nocase
//         $icm32 = "icm32.dll" nocase
//         $rasapi32 = "rasapi32.dll" nocase
//         $rasman = "rasman.dll" nocase
//         $iphlpapi = "iphlpapi.dll" nocase
//         $netapi32 = "netapi32.dll" nocase
//         $advapi32 = "advapi32.dll" nocase
//         $secur32 = "secur32.dll" nocase
//         $wlanapi = "wlanapi.dll" nocase
//         $mpr = "mpr.dll" nocase

//     condition:
//         any of ($ws2_32, $mswsock, $wininet, $winhttp, $dnsapi, $wship6, 
//                 $rpcrt4, $icm32, $rasapi32, $rasman, $iphlpapi, $netapi32,
//                 $advapi32, $secur32, $wlanapi, $mpr) in (pe.imports_dll_names)
// }

// rule Detect_DNS
// {
//     strings:
//         $GetHostByName = "GetHostByName" ascii
//         $GetHostByAddr = "GetHostByAddr" ascii
//         $DnsQuery = "DnsQuery" ascii
//         $DnsRecordListFree = "DnsRecordListFree" ascii
// }
