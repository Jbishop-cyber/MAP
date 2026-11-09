from analyzer.clamav_analyzer import scan_with_clamav

result = scan_with_clamav("samples/test.txt")

print(result)
