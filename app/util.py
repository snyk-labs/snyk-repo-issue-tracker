import json
import requests
import urllib
import logging
from retry.api import retry_call
from os import path, mkdir, scandir

from snyk import SnykClient

from snyk.errors import SnykHTTPError

V3_VERS = "2021-08-20~beta"

logger = logging.getLogger(__name__)


def make_v3_get(endpoint, token, params):
    V3_API = "https://api.snyk.io/v3"
    USER_AGENT = "pysnyk/snyk_services/target_sync"

    client = requests.Session()
    client.headers.update({"Authorization": f"token {token}"})
    client.headers.update({"User-Agent": USER_AGENT})
    client.headers.update({"Content-Type": "application/vnd.api+json"})
    url = f"{V3_API}/{endpoint}"
    return client.get(url)


def v3_get(endpoint, token, delay=1):
    result = retry_call(
        make_v3_get,
        fkwargs={"endpoint": endpoint, "token": token},
        tries=3,
        delay=delay,
    )
    return result


# we need a function to generate the orgs in the cache_path/org/org_id
def gen_org_path(cache, org):
    org_id = org["slug"]
    if path.isdir(f"{cache}/org") is not True:
        mkdir(f"{cache}/org")
    if path.isdir(f"{cache}/org/{org_id}") is not True:
        mkdir(f"{cache}/org/{org_id}")
        mkdir(f"{cache}/org/{org_id}/project")

    return f"{cache}/org/{org_id}/project"


# we need a function to load the map of targets from a data directory

# we need a function to save a new map of targets after being processed

# this is a 'safe' way to get all orgs in a group because not all tokens can use user/me
def get_orgs(snyk_group: str, client: SnykClient) -> list:

    first_resp = client.get(f"group/{snyk_group}/orgs?page=1&perPage=200")
    orgs_resp = first_resp.json()

    all_pages = list()
    all_pages.extend(orgs_resp["orgs"])
    next_page = 2

    while "next" in first_resp.links:
        first_resp = client.get(f"group/{snyk_group}/orgs?page={next_page}&perPage=200")
        all_pages.extend(first_resp.json()["orgs"])
        next_page += 1

    orgs_resp["orgs"] = all_pages

    return orgs_resp["orgs"]


def get_org_targets(org: dict, token: str) -> list:

    print(f"getting {org['id']} / {org['slug']} targets")
    targets_raw = v3_get(f"orgs/{org['id']}/targets?version={V3_VERS}", token)

    targets_resp = targets_raw.json()

    targets = targets_resp["data"]

    return targets


def get_group_targets(orgs: list, token: str) -> dict:
    the_targets = {}

    for org in orgs:
        targets = get_org_targets(org, token)
        for t in targets:
            the_targets[t["id"]] = t

    return the_targets


def get_org_projects(org: dict, token: str) -> dict:

    v3client = SnykV3Client(token)

    print(f"getting {org['id']} / {org['slug']} projects")

    try:
        first_resp = v3_get(f"orgs/{org['id']}/projects?version={V3_VERS}", token)
    except Exception as e:
        print(f"{org['id']} project lookup failed with {e}")
        orgs_resp = {"data": []}
        return orgs_resp

    try:
        orgs_resp = first_resp.json()
    except Exception as e:
        print(f"{org['id']} returned invalid json {e}")
        print(f"headers:{first_resp.headers}")
        print(f"body:{first_resp.text}")
        orgs_resp = {"data": []}
        return orgs_resp

    all_pages = list()
    all_pages.extend(orgs_resp["data"])

    while "next" in page["links"].keys():
        next_url = urllib.parse.urlsplit(page["links"]["next"])
        query = urllib.parse.parse_qs(next_url.query)

        params = {}

        for k, v in query.items():
            params[k] = v

        params["limit"] = 200

        page = self.get(next_url.path, params).json()
        data.extend(page["data"])

    orgs_resp["data"] = all_pages

    return orgs_resp


def build_map(targets, data_dir):
    if path.isfile(f"{data_dir}/targets_metadata.json"):
        has_md = True
        with open(f"{data_dir}/targets_metadata.json") as f:
            metadata = json.load(f)
    else:
        has_md = False

    if path.isfile(f"{data_dir}/bb_repos.json"):
        has_bb = True
        with open(f"{data_dir}/bb_repos.json") as f:
            bb_repos = json.load(f)
    else:
        has_bb = False

    if has_md:
        for t, v in targets.items():
            if t in metadata.keys():
                v["attributes"].update(metadata[t])

        del metadata

    if has_bb:
        for t, v in targets.items():
            if v["attributes"]["origin"] == "bitbucket-server":
                if (
                    v["attributes"]["remoteUrl"] == None
                    and "id" in v["attributes"].keys()
                ):
                    repo_id = v["attributes"]["id"]
                    repo_match = [r for r in bb_repos if r["repo_id"] == repo_id]
                    if len(repo_match) > 0:
                        v["attributes"]["remoteUrl"] = repo_match[0]["self_link"]
                    else:
                        v["attributes"]["remoteUrl"] = "DEAD-REPO"

        del bb_repos

    with open(f"{data_dir}/map.json", mode="w", encoding="utf-8") as f:
        json.dump(targets, f, ensure_ascii=False, indent=4)

    return targets


def load_map(data_dir):
    with open(f"{data_dir}/map.json") as f:
        targets = json.load(f)
    return targets


def map_projects_targets(
    org: dict,
    targets: dict,
    client: SnykClient,
    token: str,
    cache_dir: str = "cache",
):

    projects_path = gen_org_path(cache_dir, org)

    projects = get_org_projects(org, token)

    for project in projects["data"]:

        # we want to bump the attributes to become top level keys
        project.update(project.pop("attributes"))

        project["org_id"] = org["id"]
        project["org_slug"] = org["slug"]

        project[
            "browseUrl"
        ] = f"https://app.snyk.io/org/{org['slug']}/project/{project['id']}"

        target = project["relationships"]["target"]["data"]["id"]
        file_paths = project["name"].split(":")
        if len(file_paths) == 2:
            project["targetObjectPath"] = file_paths[1]
        else:
            project["targetObjectPath"] = ""

        if target in targets.keys():
            project["target"] = targets[target]

        if path.isfile(f"{projects_path}/{project['id']}.json"):
            with open(f"{projects_path}/{project['id']}.json") as f:
                old_project = json.load(f)
        else:
            old_project = {}

        if "issues" in old_project.keys():
            project["issues"] = old_project["issues"]

        p2 = {}
        for i in sorted(project):
            p2[i] = project[i]

        with open(f"{projects_path}/{p2['id']}.json", mode="w", encoding="utf-8") as f:
            json.dump(p2, f, ensure_ascii=False, indent=2)


def load_org_cache(cache_dir):

    file_path = f"{cache_dir}/org/metadata.json"

    with open(file_path) as f:
        orgs = json.load(f)

    return orgs


def load_projects_targets(cache_dir, org):

    org_id = org["slug"]

    projects_path = f"{cache_dir}/org/{org_id}/project"

    projects = []
    for entry in scandir(projects_path):
        if entry.name.endswith("json"):
            with open(f"{projects_path}/{entry.name}") as f:
                projects.append(json.load(f))

    return projects


def load_project_issues(project, client):
    org_id = project["org_id"]
    id = project["id"]

    if "issues" in project.keys():
        old_issues = project["issues"]
    else:
        old_issues = []

    data = {"includeDescription": True}

    try:
        issue_resp = client.post(
            f"org/{org_id}/project/{id}/aggregated-issues", data
        ).json()
    except SnykHTTPError as e:
        print(f"org/{org_id}/project/{id}/aggregated-issues lookup failed with {e}")
        issue_resp = {"issues": []}

    change = compare_issues(issue_resp["issues"], old_issues)

    return change, issue_resp["issues"], old_issues


def compare_issues(new, old):
    change = {"updated": [], "removed": [], "new": []}

    # we need to drop links because their presence alone isn't much (and can lead to erronous 'updates')

    new[:] = [{key: val for key, val in p.items() if key != "links"} for p in new]
    old[:] = [{key: val for key, val in p.items() if key != "links"} for p in old]

    for p in new:
        if p not in old:
            change["new"].append(p["id"])

    for p in old:
        if p not in new:
            change["removed"].append(p["id"])

        # the old id exists as "new" but the dictionaries don't match
        # so it's no new so much as changed one
        if p["id"] in change["new"]:
            change["updated"].append(p["id"])
            change["new"][:] = [np for np in change["new"] if np != p["id"]]
            change["removed"][:] = [np for np in change["removed"] if np != p["id"]]

    return change


def write_project(file_path, project):
    with open(file_path, mode="w", encoding="utf-8") as f:
        json.dump(project, f, ensure_ascii=False, indent=2)


def cache_orgs_metadata(orgs, cache):

    if path.isdir(f"{cache}/org") is not True:
        mkdir(f"{cache}/org")

    file_path = f"{cache}/org/metadata.json"

    with open(file_path, mode="w", encoding="utf-8") as f:
        json.dump(orgs, f, ensure_ascii=False, indent=2)


class SnykV3Client(object):
    API_URL = "https://api.snyk.io/v3"
    V3_VERS = "2021-08-20~beta"
    USER_AGENT = f"pysnyk/snyk_services/sync/{__version__}"

    def __init__(
        self,
        token: str,
        url: str = API_URL,
        version: str = V3_VERS,
        user_agent: str = USER_AGENT,
        debug: bool = False,
        tries: int = 1,
        delay: int = 1,
        backoff: int = 2,
    ):
        self.api_token = token
        self.api_url = url or self.API_URL
        self.api_vers = version or self.V3_VERS
        self.api_headers = {
            "Authorization": "token %s" % self.api_token,
            "User-Agent": user_agent,
        }
        self.api_post_headers = self.api_headers
        self.api_post_headers[
            "Content-Type"
        ] = "Content-Type: application/vnd.api+json; charset=utf-8"
        self.tries = tries
        self.backoff = backoff
        self.delay = delay

    def request(
        self,
        method,
        url: str,
        headers: object,
        params: object = None,
        json: object = None,
    ) -> requests.Response:

        resp: requests.Response

        resp = method(
            url,
            json=json,
            params=params,
            headers=headers,
        )

        if not resp or resp.status_code >= requests.codes.server_error:
            resp.raise_for_status()
        return resp

    def get(self, path: str, params: dict = {}) -> requests.Response:

        # path = ensure_version(path, self.V3_VERS)
        path = cleanup_path(path)

        if "version" not in params.keys():
            params["version"] = self.V3_VERS

        params = {k: v for (k, v) in params.items() if v}

        # because python bool(True) != javascript bool(True) - True vs true
        for k, v in params.items():
            if isinstance(v, bool):
                params[k] = str(v).lower()

        url = self.api_url + path
        logger.debug("GET: %s" % url)
        resp = retry_call(
            self.request,
            fargs=[requests.get, url, self.api_headers, params],
            tries=self.tries,
            delay=self.delay,
            backoff=self.backoff,
            logger=logger,
        )

        if not resp.ok:
            resp.raise_for_status()

        logger.debug("RESP: %s" % resp.headers)

        return resp

    def get_all_pages(self, path: str, params: dict = {}) -> list:
        """
        This is a wrapper of .get() that assumes we're going to get paginated results.
        In that case we really just want concated lists from each pages 'data'
        """

        # this is a raw primative but a higher level module might want something that does an
        # arbitrary path + origin=foo + limit=100 url construction instead before being sent here

        limit = params["limit"]

        data = list()

        page = self.get(path, params).json()

        data.extend(page["data"])

        while "next" in page["links"].keys():
            next_url = urllib.parse.urlsplit(page["links"]["next"])
            query = urllib.parse.parse_qs(next_url.query)

            for k, v in query.items():
                params[k] = v

            params["limit"] = limit

            page = self.get(next_url.path, params).json()
            data.extend(page["data"])

        return data


def cleanup_path(path: str):
    if path[0] != "/":
        return f"/{path}"
    else:
        return path
