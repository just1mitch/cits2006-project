// YARA ENGINE TO DETECT NETWORK RESOURCE USAGE

rule Detect_HTTP_Network_Activity
{
    meta:
        description = "Detects files attempting to access network resources"
        author = "ChatGPT"

    strings:
        $http_methods = /GET|POST|PUT|DELETE/
        $ip_address = /(\d{1,3}\.){3}\d{1,3}/
        $url_pattern = /(http|https):\/\/[a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,}/

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