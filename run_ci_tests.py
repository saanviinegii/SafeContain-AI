import sys
import io
import pytest

def main():
    print("=== STARTING PYTEST TEST EXECUTION ===")
    # Capture output
    buf = io.StringIO()
    # Run pytest
    ret = pytest.main(["tests", "-v", "--tb=short", "-p", "no:warnings"])
    print(f"=== PYTEST FINISHED WITH EXIT CODE: {ret} ===")
    if ret != 0:
        print(f"::error title=Pytest Failure::Pytest exited with status code {ret}")
    return ret

if __name__ == "__main__":
    code = main()
    sys.exit(int(code))
