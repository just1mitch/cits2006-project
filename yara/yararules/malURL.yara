// YARA ENGINE TO DETECT MALICIOUS URLS
// Based on regex provided by https://www.makeuseof.com/regular-expressions-validate-url/
import "pe"

rule pe_url_detect
{
    meta:
        description = "Uses regex to detect a URL, and the pe module to detect a windows executable"
        author = "23475725"
    strings:
        $url = /(http(s)?:\/\/)[-a-zA-Z0-9@:%._+~#?&\/=]{2,256}.[a-z]{2,6}\b([-a-zA-Z0-9@:%._+~#?&\/=]*)/
    condition:
        $url and pe.is_pe
}
