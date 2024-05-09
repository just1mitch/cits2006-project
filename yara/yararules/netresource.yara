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

rule Detect_Network_DLLs
{
    meta:
        description = "Detect executables importing common network-related DLLs"
        author = "ChatGPT"

    strings:
        $ws2_32 = "ws2_32.dll" nocase
        $wininet = "wininet.dll" nocase
        $winhttp = "winhttp.dll" nocase
        $mpr = "mpr.dll" nocase
        $netapi = "netapi32.dll" nocase

    condition:
        any of ($ws2_32, $wininet, $winhttp, $mpr, $netapi) in (pe.imports_dll_names)
}

rule Detect_DNS
{
    strings:
        $GetHostByName = "GetHostByName" ascii
        $GetHostByAddr = "GetHostByAddr" ascii
        $DnsQuery = "DnsQuery" ascii
        $DnsRecordListFree = "DnsRecordListFree" ascii
}
