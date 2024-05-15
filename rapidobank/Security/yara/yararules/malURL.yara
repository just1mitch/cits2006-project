// YARA ENGINE TO DETECT MALICIOUS URLS
// Based on regex provided by https://www.makeuseof.com/regular-expressions-validate-url/
import "pe"

rule pe_url_detect
{
    meta:
        description = "Uses regex to detect a URL, and the pe module to detect a windows executable"
        author = "23475725"
    strings:
        $url_pattern = /https?:\/\/[^\s<>"\[\]\{\}\|\\^`]+/

    condition:
        $url_pattern
}
