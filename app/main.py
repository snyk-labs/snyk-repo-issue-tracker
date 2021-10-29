import json
import time

from os import environ, path
from snyk import SnykClient

from datetime import datetime, timedelta
from util import cache_orgs_metadata, write_project, get_orgs, get_group_targets, map_projects_targets, load_org_cache, build_map, load_map, load_projects_targets, load_project_issues

V3_VERS = "2021-08-20~beta"
USER_AGENT = "pysnyk/snyk_services/target_sync"

# env vars

token = environ['SNYK_TOKEN']
group = environ['SNYK_GROUP']

TRUTHY = ['TRUE','true','True','1']

if 'SNYK_REPO_CACHE' in environ:
    cache_dir = environ['SNYK_REPO_CACHE']
else:
    cache_dir = 'cache'

if 'SNYK_REPO_DATA' in environ:
    data_dir = environ['SNYK_REPO_DATA']
else:
    data_dir = 'data'

if 'SNYK_REPO_OUTPUT' in environ:
    output_dir = environ['SNYK_REPO_OUTPUT']
else:
    output_dir = 'output'

if 'SNYK_REPO_UPDATE_ORGS' in environ:
    update_orgs = environ['SNYK_REPO_UPDATE_ORGS'] in TRUTHY
else:
    update_orgs = False

if 'SNYK_REPO_UPDATE_MAP' in environ:
    update_map = environ['SNYK_REPO_UPDATE_MAP'] in TRUTHY
else:
    update_map = False

if 'SNYK_REPO_UPDATE_PROJECTS' in environ:
    update_projects = environ['SNYK_REPO_UPDATE_PROJECTS'] in TRUTHY
else:
    update_projects = False

v1 = SnykClient(
    token=token,
    user_agent=USER_AGENT,
    delay=3,
    tries=2)


if update_orgs:
    print('Updating Org Metadata')
    orgs = get_orgs(group, v1)
    cache_orgs_metadata(orgs,cache_dir)
elif path.isfile(f"{cache_dir}/org/metadata.json") is not True:
    print('No cache present, retrieving Org Metadata')
    orgs = get_orgs(group, v1)
    cache_orgs_metadata(orgs,cache_dir)
else:
    print('Using cached Org Metadata')
    orgs = load_org_cache(cache_dir)

if update_map:
    print('Generating new map of Target data')
    targets = get_group_targets(orgs, token)
    mapped_targets = build_map(targets,data_dir)
else:
    print('Used cached map of Target data')
    mapped_targets = load_map(data_dir)

if update_projects:
    print('Updating all local projects for all orgs in group')
    for org in orgs:
        map_projects_targets(org,mapped_targets,v1,token,cache_dir)


print('Checking for changes to issues in all cached orgs/projects')

for org in orgs:
    projects = load_projects_targets(cache_dir,org)

    for project in projects:
        id = project['id']
        org_id = project['org_slug']
        projects_cache_file = f"{cache_dir}/org/{org_id}/project/{id}.json"

        changes, new_issues, old_issues = load_project_issues(project,v1)

        project['issues'] = new_issues
        
        # first we write these changes to the cache
        write_project(projects_cache_file,project)

        if len(changes['new']) > 0:
            new_project = project
            new_project['issues'][:] = [i for i in new_issues if i['id'] in changes['new']]
            write_project(f"{output_dir}/new/{id}.json",new_project)
    
        if len(changes['updated']) > 0:
            updated_project = project
            updated_project['issues'][:] = [i for i in new_issues if i['id'] in changes['updated']]
            write_project(f"{output_dir}/updated/{id}.json",updated_project)

        if len(changes['removed']) > 0:
            removed_project = project
            removed_project['issues'][:] = [i for i in old_issues if i['id'] in changes['removed']]
            write_project(f"{output_dir}/removed/{id}.json",removed_project)


