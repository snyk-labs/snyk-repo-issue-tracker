## Snyk Repo / Target Tracker

This is a python script / module (soon to be docker container) that allows for generating a changeset of issues between runs against the snyk project issues API.

To facilitate this, this script caches all the org / project information in a folder called cache (set by env SNYK_REPO_CACHE), loads a map.json from a data folder (set env SNYK_REPO_DATA) that contains a map of all the snyk targets to target ids.

This map.json can be augmented by targets_metadata.json and bb_repos.json files, the target metadata file being a source of data that currently isn't in the v3 targets endpoint, but can be provided by your snyk CSM. The bb_repos.json file is specifically for bitbucket-server and allows for linking the snyk target to the repo ID snyk has, with the repo ID that bitbucket has.

### Running this script:

clone this repository
setup this repository (usually poetry works great for this)

```
poetry install
source $(poetry env info -p)/bin/activate
```

or

```
python3 -m venv .venv
source .venv/bin/activate
python pip install
python -m pip install --quiet -U pip
pip install --quiet -r requirements.txt
```

This needs two environment variables:
```
export SNYK_TOKEN=06FEF4A5-DE68-4753-9152-02EC89CE7C1A
export SNYK_GROUP=6D9B14FE-0AB4-4738-9464-62CBC949215E
```

The snyk group is what defines the scope of where to pull issues from

For the first execution of the script, one needs to build the cache of projects and the map of targets:
```
export SNYK_REPO_UPDATE_ORGS=true
export SNYK_REPO_UPDATE_MAP=true
export SNYK_REPO_UPDATE_PROJECTS=true

python app/main.py
```

For future executions of the script, one can skip the map of targets being built (if new repos are not being added) but rebuild the projects (if projects are being removed / changed frequently):
```
export SNYK_REPO_UPDATE_MAP=false
export SNYK_REPO_UPDATE_PROJECTS=true
```

Or if the projects are stable, one can disable that also. Note: both of these tasks generate and populate the cache directory, if that cache directory is reset, then this script will need to be run again with UPDATE_MAP and UPDATE_PROJECTS enabled.

### Formatting

The payload is as minimally modified from a Snyk API response as possible, for convienence the attributes hash has been flatten. Other modifications:

```
org_id = Org's public uuid
org_slug = Org's public 'shortname' - used for URLS
targetObjectPath = path to the file being scanned, this is derived from the project name currently
```

References:
For SCM (bitbucket, github) dependecy checking, `targetReference` is the branch name (this was branch is previous v1 projects api)


Refer to [this example](test/example.json) for a project file with issues present along with target data.

# Snyk-Repo-Issue-Tracker
