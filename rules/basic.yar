/*
  Antiscan — base YARA ruleset
  Combines the industry-standard EICAR test signature with a handful of
  structural heuristics (macro-enabled Office docs, obfuscated script
  patterns, embedded PE-in-non-PE payloads).
*/

rule EICAR_Test_File
{
    meta:
        description = "Standard antivirus test file (EICAR) - not real malware"
        severity = "test"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Office_Macro_Present
{
    meta:
        description = "Office document contains VBA macro project stream"
        severity = "suspicious"
    strings:
        $vba1 = "VBA_PROJECT" ascii
        $vba2 = "vbaProject.bin" ascii
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }
    condition:
        ($ole_magic at 0) and any of ($vba1, $vba2)
}

rule Obfuscated_Script_Pattern
{
    meta:
        description = "Script contains common obfuscation/dropper patterns"
        severity = "suspicious"
    strings:
        $ps_enc = "-EncodedCommand" nocase
        $ps_hidden = "-WindowStyle Hidden" nocase
        $js_eval_b64 = /eval\s*\(\s*atob\s*\(/
        $downloadstring = "DownloadString" nocase
        $invoke_expr = "IEX" nocase
    condition:
        2 of them
}

rule Embedded_Executable_In_Document
{
    meta:
        description = "MZ/PE header found embedded past the start of a non-exe file"
        severity = "suspicious"
    strings:
        $mz = { 4D 5A }
    condition:
        #mz > 0 and not ($mz at 0)
}

rule Double_Extension_Trick
{
    meta:
        description = "Filename suggests double-extension masquerade"
        severity = "info"
    condition:
        false
}