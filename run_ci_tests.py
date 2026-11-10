import sys
import pytest

class DiagnosticPlugin:
    def pytest_collectreport(self, report):
        if report.failed:
            err_msg = str(report.longrepr).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
            print(f"::error title=CollectError::{err_msg}")

    def pytest_sessionfinish(self, session, exitstatus):
        items_count = len(getattr(session, 'items', []))
        print(f"::notice title=SessionSummary::ExitStatus={exitstatus}, items_collected={items_count}")

def main():
    print("=== STARTING PYTEST TEST EXECUTION ===")
    plugin = DiagnosticPlugin()
    ret = pytest.main(["tests/unit", "-v", "--tb=short", "-p", "no:warnings"], plugins=[plugin])
    print(f"=== PYTEST FINISHED WITH EXIT CODE: {ret} ===")
    return ret

if __name__ == "__main__":
    code = main()
    sys.exit(int(code))
