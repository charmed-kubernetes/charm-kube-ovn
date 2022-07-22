from typing import Optional
import shlex
import json


class Grafana:
    """A class which abstracts access to a running instance of Grafana."""

    def __init__(
        self,
        ops_test,
        host: Optional[str] = "localhost",
        port: Optional[int] = 3000,
        username: Optional[str] = "admin",
        pw: Optional[str] = "",
    ):
        """Utility to manage a Grafana application.
        Args:
            host: Optional host address of Grafana application, defaults to `localhost`
            port: Optional port on which Grafana service is exposed, defaults to `3000`
            username: Optional username to connect with, defaults to `admin`
            pw: Optional password to connect with, defaults to `""`
        """
        self.ops_test = ops_test
        self.base_uri = "http://{}:{}".format(host, port)
        self.username = username
        self.pw = pw

    async def is_ready(self) -> bool:
        """Send a request to check readiness.
        Returns:
          True if Grafana is ready (returned database information OK); False otherwise.
        """
        res = await self.health()
        return res.get("database", "") == "ok" or False

    async def health(self) -> dict:
        """A convenience method which queries the API to see whether Grafana is really ready.
        Returns:
            Empty :dict: if it is not up, otherwise a dict containing basic API health
        """
        api_path = "api/health"
        uri = "{}/{}".format(self.base_uri, api_path)

        cmd = f"run --unit ubuntu/0 -- curl {uri} -u {self.username}:{self.pw}"
        rc, stdout, stderr = await self.ops_test.juju(*shlex.split(cmd))
        assert rc == 0, f"Failed to curl health endpoint: {(stdout or stderr).strip()}"
        return json.loads(stdout)

    async def dashboards_all(self) -> list:
        """Try to get 'all' dashboards, since relation dashboards are not starred.
        Returns:
          Found dashboards, if any
        """
        api_path = "api/search"
        uri = "{}/{}".format(self.base_uri, api_path)
        cmd = f"run --unit ubuntu/0 -- curl {uri}?starred=false -u {self.username}:{self.pw}"
        rc, stdout, stderr = await self.ops_test.juju(*shlex.split(cmd))
        assert (
            rc == 0
        ), f"Failed to curl dashboards endpoint: {(stdout or stderr).strip()}"
        return json.loads(stdout)
