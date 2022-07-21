import urllib.request
import json
from pathlib import Path

grafana_dir = Path("src/grafana_dashboards")
url = (
    "https://api.github.com/repos/kubeovn/kube-ovn/contents/dist/monitoring?ref=master"
)
opener = urllib.request.build_opener()
response = urllib.request.urlretrieve(url)
with open(response[0], "r") as f:
    data = json.load(f)
    for file in data:
        file_url = file["download_url"]
        file_name = file["name"]

        if file_url is not None and file_name.endswith(".json"):
            filepath = grafana_dir / file_name
            print(f"Downloading dashboard {file_name} ...")
            urllib.request.urlretrieve(file_url, filepath.absolute().as_posix())

# The grafana dashboard lib from the o11y team will automatically replace any datasource
# variables for panels. However, it will not replace datasource variables in templates.
# We must make the appropriate replacement ourselves. The prometheus datasource variable expected by
# the COS grafana charm is named prometheusds.
ds = "${prometheusds}"
grafana_files = [
    p for p in grafana_dir.iterdir() if (p.is_file() and p.name.endswith(".json"))
]
for file in grafana_files:
    json_data = json.loads(file.read_text())
    templating = json_data["templating"]
    templates = templating["list"]
    for template in templates:
        if "datasource" in template:
            name = template["name"]
            print(f"Replacing template {name} datasource in {file}...")
            template["datasource"] = ds

    with open(file, "w") as jsonFile:
        print(f"Saving {file}")
        json.dump(json_data, jsonFile, indent=2)
