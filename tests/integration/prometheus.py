from typing import Optional
import requests


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
          True if Prometheus is ready (-/ready returns response code 200); False
          otherwise.
        """
        api_path = "-/ready"
        uri = "{}/{}".format(self.base_uri, api_path)
        response = requests.get(uri)
        return response.status_code == 200

    async def metrics_all(self) -> list:
        """Try to get all metrics reported to Prometheus by Kube-OVN components.
        Returns:
          Found metrics, if any
        """
        api_path = "api/v1/label/__name__/values"
        uri = "{}/{}".format(self.base_uri, api_path)
        params = {"match[]": ['{__name__=~".+", job!="prometheus"}']}
        response = requests.get(uri, params=params)
        response.raise_for_status()
        return response.json()["data"]
