// YARA ENGINE TO DETECT MALICIOUS URLS
// Based on regex provided by https://www.makeuseof.com/regular-expressions-validate-url/
import "pe"

rule pe_url_detect
{
    meta:
        description = "Uses regex to detect a URL, and the pe module to detect a windows executable"
        author = "23475725"
    strings:
        $https_url = /https:\/\/[^\s]+/
        $http_url = /http:\/\/[^\s]+/
    condition:
        $https_url or $http_url
}
