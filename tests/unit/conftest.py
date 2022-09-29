import unittest.mock as mock
from charm import KubeOvnCharm

import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "skip_kubectl_mock: mark tests which do not mock out KubeOvnCharm.kubectl",
    )
    config.addinivalue_line(
        "markers",
        "skip_unlabel_bgp_nodes_mock: mark tests which do not mock out KubeOvnCharm.unlabel_bgp_nodes",
    )


@pytest.fixture(autouse=True)
def kubectl(request):
    """Mock out kubectl."""
    if "skip_kubectl_mock" in request.keywords:
        yield KubeOvnCharm.kubectl
        return
    with mock.patch("charm.KubeOvnCharm.kubectl", autospec=True) as mocked:
        yield mocked


@pytest.fixture(autouse=True)
def unlabel_bgp_nodes(request):
    """Mock out unlabel_bgp_nodes."""
    if "skip_unlabel_bgp_nodes_mock" in request.keywords:
        yield KubeOvnCharm.unlabel_bgp_nodes
        return
    with mock.patch("charm.KubeOvnCharm.unlabel_bgp_nodes", autospec=True) as mocked:
        yield mocked
