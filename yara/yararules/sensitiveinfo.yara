// YARA ENGINE TO DETECT SENSITIVE INFORMATION

rule financial_data
{
    meta:
        description = "Detects financialdata"
        author = "23135002"
    strings:
        $IBAN = /\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b/ // International Bank Number
        $aus_bsb = /\b\d{3}[- ]\d{3}\b/
        $aus_bank_num = /\b\d{6,9}\b/
        $aus_credit_info = /\b\d{15,16}\b/
    condition:
        $IBAN and 1 of ($aus_bsb, $aus_bank_num) or 2 of ($aus_bsb, $aus_bank_num, $aus_credit_info)
}

rule personal_data
{
    strings:
        $first_name = {(46 | 66) 69 72 73 74 ?? (4e | 6e) 61 6d 65} // Matches First Name with anything inbetween case insensitive
        $last_name = {(4c | 6c) 61 73 74 ?? (4e | 6e) 61 6d 65} // Matches Last Name with anything inbetween case insensitive
        $DOB = /\b((0[1-9]|[12][0-9]|3[01])[-\/\ ])((0[1-9]|1[0-2])[-\/\ ])\d{2,4}\b/ // Matches dob's such as 20/11/1990 or 20-11-2099
    condition:
        2 of ($first_name, $last_name, $DOB)
}      