import os
import yara_x


def scan_with_yara(file_path, rule_path):

    if not os.path.isfile(file_path):
        return {"error": "File does not exist"}

    if not os.path.isfile(rule_path):
        return {"error": "YARA rule file does not exist"}

    # Read the YARA rule
    with open(rule_path, "r") as file:
        rule_source = file.read()

    # Compile the rule
    rules = yara_x.compile(rule_source)

    # Create scanner
    scanner = yara_x.Scanner(rules)

    # Scan the file
    results = scanner.scan_file(file_path)

    # Extract matching rule names
    detections = [
        rule.identifier for rule in results.matching_rules
    ]

    return {
        "filename": os.path.basename(file_path),
        "matches_found": len(detections),
        "detections": detections
    }