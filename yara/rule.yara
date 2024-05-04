rule isLatrodectus{

    meta:
        author = "dhmosfunk"
        reference = "https://github.com/dhmosfunk/LatrodectusWEB

    strings:
        $rundll32_cmd = "C:/Windows/System32/rundll32.exe [LocalAppDataFolder]sharepoint"
        $payload_hex_sig = { 48 89 54 24 10 48 89 4C 24 08 57 48 83 EC 10 48 } // Hex signature from packed payload
        $update_hex_sig = { 58 A2 68 A2 78 A2 88 A2 98 A2 A8 A2 B8 A2 C8 A2 } // Hex signature from initial .dll file

    condition:
        $payload_hex_sig or $update_hex_sig or $rundll32_cmd
}