from typing import Optional
import shlex
import json


class Prometheus:
    """A class which abstracts access to a running instance of Prometheus."""

    def __init__(
        self,
        ops_test,
        host: Optional[str] = "localhost",
        port: Optional[int] = 9090,
    ):
        """Utility to manage a Prometheus application.
        Args:
            host: Optional host address of Prometheus application, defaults to `localhost`
            port: Optional port on which Prometheus service is exposed, defaults to `9090`
        """
        self.ops_test = ops_test
        self.base_uri = "http://{}:{}".format(host, port)

    async def is_ready(self) -> bool:
        """Send a request to check readiness.
        Returns:
          True if Prometheus is ready (returned 'Prometheus is Ready.'); False otherwise.
        """
        res = await self.health()
        return "Prometheus is Ready." in res

    async def health(self) -> str:
        """A convenience method which queries the API to see whether Prometheus is ready
           to serve traffic (i.e. respond to queries).
        Returns:
            Empty :str: if it is not up, otherwise a str containing "Prometheus is Ready"
        """
        api_path = "-/ready"
        uri = "{}/{}".format(self.base_uri, api_path)

        cmd = f"run --unit ubuntu/0 -- curl {uri}"
        rc, stdout, stderr = await self.ops_test.juju(*shlex.split(cmd))
        assert rc == 0, f"Failed to curl ready endpoint: {(stdout or stderr).strip()}"
        return stdout

    async def metrics_all(self) -> list:
        """Try to get all metrics reported to Prometheus by Kube-OVN components.
        Returns:
          Found metrics, if any
        """
        api_path = "api/v1/label/__name__/values"
        uri = "{}/{}".format(self.base_uri, api_path)
        cmd = (
            f"run --unit ubuntu/0 -- curl -XGET -G '{uri}' "
            '--data-urlencode \'match[]={__name__=~".+", job!="prometheus"}\''
        )
        rc, stdout, stderr = await self.ops_test.juju(*shlex.split(cmd))
        assert (
            rc == 0
        ), f"Failed to curl Prometheus HTTP API: {(stdout or stderr).strip()}"
        return json.loads(stdout)["data"]
