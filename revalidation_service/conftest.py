import os
import sys

SERVICE_ROOT = os.path.dirname(os.path.abspath(__file__))
if SERVICE_ROOT not in sys.path:
    sys.path.insert(0, SERVICE_ROOT)

_ARTIFACT = os.path.join(os.getcwd(), "revalidation.db")
_existed_before = os.path.exists(_ARTIFACT)


def pytest_sessionfinish(session, exitstatus):
    # Importing src.main constructs the module-level repository, which
    # creates revalidation.db relative to the invocation directory.
    # Remove that generated artifact unless it existed before the run.
    if not _existed_before and os.path.exists(_ARTIFACT):
        try:
            os.remove(_ARTIFACT)
        except OSError:
            pass
