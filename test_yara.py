from analyzer.yara_analyzer import scan_with_yara

result = scan_with_yara(
    "samples/clean_test.txt",
    "rules/test_rule.yar"
)

print(result)
