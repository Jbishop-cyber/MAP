rule MAP_Test_Detection
{
    meta:
        description = "Detects a harmless MAP test marker"
        author = "MAP Project"
        purpose = "Testing YARA-X integration"
    
    strings:
        $marker = "MAP_TEST_SIGNATURE"
    
    condition:
        $marker
}