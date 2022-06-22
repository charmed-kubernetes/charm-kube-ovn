import unittest.mock as mock
from charm import KubeOvnCharm

import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "skip_kubectl_mock: mark tests which do not mock out KubeOvnCharm.kubectl",
    )


@pytest.fixture(autouse=True)
def kubectl(request):
    """Mock out kubectl."""
    if "skip_kubectl_mock" in request.keywords:
        yield KubeOvnCharm.kubectl
        return
    with mock.patch("charm.KubeOvnCharm.kubectl", autospec=True) as mocked:
        yield mocked
