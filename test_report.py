from analyzer.report_builder import analyze_file
from analyzer.report_formatter import format_report

report = analyze_file(
    "samples/yara_test.txt",
    "rules/test_rule.yar"
)

formatted_report = format_report(report)

print(formatted_report)
