from http import HTTPStatus
from functools import lru_cache
from io import BytesIO
from discord.audit_logs import F
from discord.utils import MISSING
import discord
import fastapi
from fastapi import FastAPI, Depends, Header, Request, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response, JSONResponse, StreamingResponse
from slowapi.errors import RateLimitExceeded
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from fastapi.security import OAuth2PasswordBearer
from typing import Annotated, Optional, List, Dict, Union, Any, Type
from tortoise import Tortoise, fields
from tortoise.models import Model
import aiohttp
import os
from aidenlib.main import dchyperlink, makeembed, getorfetch_channel, makeembed_bot, dctimestamp
import discord
import requests
from io import BytesIO
import datetime
from dateutil import parser
import traceback
from enum import Enum
from dateparser import parse
import discord.utils
import string
import random

if __name__ == "webserver": 
    from events import gl_id, gl_secret, redirect, client_id, client_secret, scopes
    from main import logger_, token, handler

codes = {
    100: "Continue",
    101: "Switching Protocols",
    102: "Processing",
    103: "Early Hints",

    200: "OK",
    201: "Created",
    202: "Accepted",
    203: "Non-Authoritative Information",
    204: "No Content",
    205: "Reset Content",
    206: "Partial Content",
    207: "Multi-Status",
    208: "Already Reported",
    226: "IM Used",

    300: "Multiple Choices",
    301: "Moved Permanently",
    302: "Found",
    303: "See Other",
    304: "Not Modified",
    307: "Temporary Redirect",
    308: "Permanent Redirect",

    314: "Pi Approximation",

    400: "Bad Request",
    401: "Unauthorized",
    402: "Payment Required",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    407: "Proxy Authentication Required",
    408: "Request Timeout",
    409: "Conflict",
    410: "Gone",
    411: "Length Required",
    412: "Precondition Failed",
    413: "Payload Too Large",
    414: "URI Too Long",
    415: "Unsupported Media Type",
    416: "Range Not Satisfiable",
    417: "Expectation Failed",
    418: "I'm a teapot",
    421: "Misdirected Request",
    422: "Unprocessable Content",
    423: "Locked",
    424: "Failed Dependency",
    425: "Too Early",
    426: "Upgrade Required",
    428: "Precondition Required",
    429: "Too Many Requests",
    431: "Request Header Fields Too Large",
    451: "Unavailable For Legal Reasons",

    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
    505: "HTTP Version Not Supported",
    506: "Variant Also Negotiates",
    507: "Insufficient Storage",
    508: "Loop Detected",
    510: "Not Extended",
    511: "Network Authentication Required"
}

emojidict: Dict[Union[str, bool], str] = {
    'gitlab': '<:gitlab:1161419868957048884>',
    True: "<:check:1046808377373769810>",
    "maybe": "\U0001f937",
    False: "<a:X_:1046808381266067547>",
}

def get_random_state(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


HEADER = """<!DOCTYPE html><head>
<title>my website ig</title>
<link rel='icon' href='https://i.ibb.co/QrwTwB9/amogus-impostor.jpg'></head>"""


class Router:
    def db_for_read(self, model: Type[Model]):
        return "slave"

    def db_for_write(self, model: Type[Model]):
        return "master"

class Base(Model):
    dbid = fields.IntField(pk=True,generated=True)
    datelogged = fields.DatetimeField(auto_now_add=True)
    lastupdated = fields.DatetimeField(auto_now=True)

    class Meta:
        abstract = True

class GitlabRepo(Base):
    _links = fields.JSONField()
    allow_merge_on_skipped_pipeline = fields.BooleanField(null=True)
    analytics_access_level = fields.BooleanField()
    archived = fields.BooleanField()
    auto_cancel_pending_pipelines = fields.BooleanField()
    auto_devops_deploy_strategy = fields.TextField()
    auto_devops_enabled = fields.BooleanField()
    autoclose_referenced_issues = fields.BooleanField()
    avatar_url = fields.TextField(null=True)
    build_coverage_regex = fields.TextField(null=True)
    build_timeout = fields.IntField()
    builds_access_level = fields.TextField()
    can_create_merge_request_in = fields.BooleanField()
    ci_config_path = fields.TextField(null=True)
    ci_default_git_depth = fields.IntField()
    ci_forward_deployment_enabled = fields.BooleanField()
    ci_job_token_scope_enabled = fields.BooleanField()
    compliance_frameworks = fields.JSONField(null=True)
    container_expiration_policy = fields.JSONField()
    container_registry_access_level = fields.TextField()
    container_registry_enabled = fields.BooleanField()
    created_at = fields.DatetimeField()
    creator_id = fields.IntField()
    default_branch = fields.TextField()
    description = fields.TextField(null=True)
    emails_disabled = fields.BooleanField(null=True)
    empty_repo = fields.BooleanField()
    forking_access_level = fields.TextField()
    forks_count = fields.IntField()
    http_url_to_repo = fields.TextField()
    import_status = fields.TextField()
    issues_access_level = fields.TextField()
    issues_enabled = fields.BooleanField()
    jobs_enabled = fields.BooleanField()
    keep_latest_artifact = fields.BooleanField()
    last_activity_at = fields.DatetimeField()
    lfs_enabled = fields.BooleanField()
    merge_commit_template = fields.TextField(null=True)
    merge_method = fields.TextField()
    merge_requests_access_level = fields.TextField()
    merge_requests_enabled = fields.BooleanField()
    name = fields.TextField()
    name_with_namespace = fields.TextField()
    namespace_avatar_url = fields.TextField(null=True)
    namespace_full_path = fields.TextField(null=True)
    namespace_id = fields.IntField(null=True)
    namespace_kind = fields.TextField(null=True)
    namespace_name = fields.TextField(null=True)
    namespace_parent_id = fields.IntField(null=True)
    namespace_path = fields.TextField(null=True)
    namespace_web_url = fields.TextField(null=True)
    only_allow_merge_if_all_discussions_are_resolved = fields.BooleanField()
    only_allow_merge_if_pipeline_succeeds = fields.BooleanField()
    open_issues_count = fields.IntField()
    operations_access_level = fields.TextField()
    owner_avatar_url = fields.TextField(null=True)
    owner_id = fields.IntField(null=True)
    owner_name = fields.TextField(null=True)
    owner_state = fields.TextField(null=True)
    owner_username = fields.TextField(null=True)
    owner_web_url = fields.TextField(null=True)
    packages_enabled = fields.BooleanField() 
    pages_access_level = fields.TextField()
    path = fields.TextField()
    path_with_namespace = fields.TextField()
    permissions = fields.JSONField()
    printing_merge_request_link_enabled = fields.BooleanField()
    public_jobs = fields.BooleanField()
    readme_url = fields.TextField(null=True)
    remove_source_branch_after_merge = fields.BooleanField()
    repository_access_level = fields.TextField()
    request_access_enabled = fields.BooleanField()
    requirements_access_level = fields.TextField()
    requirements_enabled = fields.BooleanField()
    resolve_outdated_diff_discussions = fields.BooleanField()
    restrict_user_defined_variables = fields.BooleanField()
    runner_token_expiration_interval = fields.IntField(null=True)
    security_and_compliance_access_level = fields.TextField()
    security_and_compliance_enabled = fields.BooleanField()
    service_desk_enabled = fields.BooleanField()
    shared_runners_enabled = fields.BooleanField()
    shared_with_groups = fields.JSONField()
    snippets_access_level = fields.TextField()
    snippets_enabled = fields.BooleanField()
    squash_commit_template = fields.TextField(null=True)
    squash_option = fields.TextField()
    ssh_url_to_repo = fields.TextField()
    star_count = fields.IntField()
    suggestion_commit_message = fields.TextField(null=True)
    tag_list = fields.JSONField()
    topics = fields.JSONField()
    visibility = fields.TextField()
    web_url = fields.TextField()
    wiki_access_level = fields.TextField()
    wiki_enabled = fields.BooleanField()

    class Meta:
        table = "GitlabRepos"

class GitlabUser(Base):
    username = fields.TextField()
    name = fields.TextField()
    status = fields.TextField()
    avatar_url = fields.TextField()
    web_url = fields.TextField()

    class Meta:
        table = "GitlabUsers"

class GithubEvent(Base):
    object_kind = fields.TextField()
    project_id = fields.IntField()
    project = fields.JSONField()
    repository = fields.JSONField()

    class Meta:
        abstract = True

class PushEvent(Model):
    object_kind = fields.TextField()
    event_name = fields.TextField()
    before = fields.TextField()
    after = fields.TextField()
    ref = fields.TextField()
    ref_protected = fields.BooleanField()
    checkout_sha = fields.TextField()
    user_id = fields.IntField()
    user_name = fields.TextField()
    user_username = fields.TextField()
    user_email = fields.TextField()
    user_avatar = fields.TextField()
    project = fields.JSONField()
    project_id = fields.IntField()
    project_name = fields.TextField()
    project_description = fields.TextField()
    project_web_url = fields.TextField()
    project_avatar_url = fields.TextField()
    project_git_ssh_url = fields.TextField()
    project_git_http_url = fields.TextField()
    project_namespace = fields.TextField()
    project_visibility_level = fields.IntField()
    project_path_with_namespace = fields.TextField()
    project_default_branch = fields.TextField()
    project_homepage = fields.TextField()
    project_url = fields.TextField()
    project_ssh_url = fields.TextField()
    project_http_url = fields.TextField()
    respository = fields.JSONField()
    repository_name = fields.TextField()
    repository_url = fields.TextField()
    repository_description = fields.TextField()
    repository_homepage = fields.TextField()
    repository_git_http_url = fields.TextField()
    repository_git_ssh_url = fields.TextField()
    repository_visibility_level = fields.IntField()
    commits = fields.JSONField()

    class Meta:
        table = "PushEvent"

class TagPushEvent(GithubEvent):
    event_name = fields.TextField(null=False)
    before = fields.TextField()
    after = fields.TextField(null=False)
    ref = fields.TextField(null=False)
    ref_protected = fields.BooleanField()
    checkout_sha = fields.TextField(null=False)
    user_id = fields.IntField(null=False)
    user_name = fields.TextField(null=False)
    user_avatar = fields.TextField(null=True)
    repository = fields.JSONField()
    project = fields.JSONField()
    commits = fields.JSONField()
    total_commits_count = fields.IntField(null=False)

    class Meta:
        table = "TagPushEvent"

class IssueEvent(GithubEvent):
    event_type = fields.TextField()
    user = fields.JSONField()
    user_id = fields.IntField()
    user_name = fields.TextField()
    user_username = fields.TextField()
    user_avatar = fields.TextField()
    user_email = fields.TextField()
    project = fields.JSONField()
    object_attributes = fields.JSONField()
    repository = fields.JSONField()

    class Meta:
        table = "IssueEvent"

class CommentEvent(GithubEvent):
    event_type = fields.TextField()
    user = fields.JSONField()
    user_id = fields.IntField()
    user_name = fields.TextField()
    user_username = fields.TextField()
    user_avatar = fields.TextField()
    user_email = fields.TextField()
    project = fields.JSONField()
    object_attributes = fields.JSONField()
    repository = fields.JSONField()

    class Meta:
        table = "CommentEvent"

class GitlabApiUser(Base):
    discordid = fields.BigIntField(unique=True)
    username = fields.TextField(null=True)
    gitlab_url = fields.TextField()
    state = fields.TextField()
    token = fields.TextField(null=True)
    refresh_token = fields.TextField(null=True)  
    expires_in = fields.BigIntField(null=True) 
    created_at = fields.DatetimeField(null=True)

    class Meta:
        table = "GitlabApiUsers"

class DiscordAuthUser(Base):
    discordid = fields.BigIntField(unique=True)
    botid = fields.BigIntField()
    token_type = fields.TextField(null=True)
    token = fields.TextField(null=True)
    refresh_token = fields.TextField(null=True)  
    expires_in = fields.BigIntField(null=True) 
    created_at = fields.DatetimeField(null=True)
    scope = fields.TextField(null=True)

    class Meta:
        table = "DiscordAuthUsers"

class ArchivedGitlabApiUser(Base):
    olddbid = fields.IntField()
    olddatelogged = fields.DatetimeField()
    oldlastupdated = fields.DatetimeField()
    discordid = fields.BigIntField(unique=False)
    username = fields.TextField(null=True)
    gitlab_url = fields.TextField()
    token = fields.TextField(null=True)
    refresh_token = fields.TextField(null=True)  
    expires_in = fields.BigIntField(null=True) 
    created_at = fields.DatetimeField(null=True)

    class Meta:
        table = "ArchivedGitlabApiUsers"

class ArchivedDiscordAuthUser(Base):
    olddbid = fields.IntField()
    olddatelogged = fields.DatetimeField()
    oldlastupdated = fields.DatetimeField()
    discordid = fields.BigIntField(unique=False)
    token_type = fields.TextField(null=True)
    token = fields.TextField(null=True)
    refresh_token = fields.TextField(null=True)  
    expires_in = fields.BigIntField(null=True) 
    created_at = fields.DatetimeField(null=True)
    scope = fields.TextField(null=True)
    gitlab_url = fields.TextField(null=True)

    class Meta:
        table = "ArchivedDiscordAuthUsers"

class UserSettings(Base):
    discordid = fields.BigIntField(unique=True)
    dm = fields.BooleanField(default=False)
    showgitlab = fields.BooleanField(default=True)
    
    class Meta:
        table = "UserSettings"

class GuildSettings(Base):
    guildid = fields.BigIntField(unique=True)
    changedby = fields.BigIntField(null=True)
    gitlabchannel = fields.BigIntField(null=True)

    class Meta:
        table = "GuildSettings"

class LinkedRoles(Base):
    type = fields.IntField()
    key = fields.TextField()
    name = fields.TextField()
    description = fields.TextField()
    name_localizations = fields.TextField(null=True)
    description_localizations = fields.TextField(null=True)

    class Meta:
        table = 'LinkedRoles'

class UserLinkedRoles(Base):
    discordid = fields.BigIntField()
    value = fields.TextField()
    valuetype = fields.TextField() # bool, int, str

    class Meta:
        table = "UserLinkedRoles"

# settings = [
#     GenericSetting("DM Permissions", "Whether you want to be DMed by the bot or not.", "📩"),
#     GenericSetting("Gitlab Permissions", "Whether you want your Gitlab account to be viewable.", emojidict.get('gitlab')),
# ]

app = FastAPI(title="my goofy api", version=".007")
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

ips = []
admins = []

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def loadips():
    global ips, admins
    with open('ips.txt','r') as f, open('admins.txt','r') as g:
        _ips = f.read().splitlines()
        _admins = g.read().splitlines()
        _ips.extend(g.read().splitlines())
        for ip in _ips:
            if not ip.startswith("#") and ip.strip() != "" and ip not in ips:
                ips.append(ip)
        for ip in _admins:
            if not ip.startswith("#") and ip.strip() != "" and ip not in admins:
                admins.append(ip)
        ips = list(set(ips))
        admins = list(set(admins))

loadips()

allowed_endpoints=["/gitlab/oauth","/gitlab/auth","/discord/oauth","/discord/auth",'/teapot','/discord/oauth/general',
'/discord/oauth/linkedroles/','/discord/oauth/linkedroles']

async def check_auth(request: Request, call_next):
    if request.client.host not in ips and request.client.host not in admins and request.url.path not in allowed_endpoints:
        return JSONResponse(status_code=403, content={'detail': 'Forbidden: get off my website bozo lmao'}, media_type="application/json")
        #return HTTPException(status_code=403, detail="Forbidden")
    return await call_next(request)

webhook_gitlab_url = "https://gitlab.ucls.uchicago.edu"
DISCORD_API = "https://discord.com/api/v10"

MAX_SESSIONS = 2

_sessions: List[aiohttp.ClientSession] = []

async def get_session(session_num: int=0, session_name: Optional[Union[str, int]]=None, **kwargs) -> aiohttp.ClientSession:
    """Get's a session from the current pool of sessions. Will give the first session by default.
    Max amount of sessions can be changed by changing the MAX_SESSIONS variable.
    You can optionally provide a session_name to get a specific session. Depricated dont use this
    Kwargs will be passed into ClientSession constructor."""
    if len(_sessions) < MAX_SESSIONS: _sessions.append(aiohttp.ClientSession(**kwargs))
    return _sessions[session_num]

async def close_session(session: Optional[aiohttp.ClientSession]=None, session_num: int=0) -> None:
    """Closes the specified connection and removes from the connectionn pool."""
    if session is None:
        session = _sessions.pop(session_num)
    elif session in _sessions:
        _sessions.remove(session)
    await session.close()
    return

async def close_sessions(sessions: List[aiohttp.ClientSession]=[], session_nums: List[int]=[], close_all: bool=False) -> None:
    """Closes the specified connections and removes from the connection pool."""
    if close_all:
        sessions = _sessions
    for session in sessions:
        await close_session(session)
    for session_num in session_nums:
        await close_session(session_num=session_num)
    return

@app.middleware("http")
async def middleware(request: Request, call_next):
    return await check_auth(request, call_next)

@app.post('/githubwebhook')
@limiter.limit("5/minute",error_message="bro you need to stop spamming my website")
async def gitlab_webhook_old(request: Request, data: dict):
    # redirect to /gitlab/webhook
    return RedirectResponse(url='/gitlab/webhook',status_code=302)

@app.post('/gitlab/webhook')
@limiter.limit("5/minute",error_message="bro you need to stop spamming my website")
async def gitlab_webhook(request: Request, data: dict):
    session = aiohttp.ClientSession()
    json = data
    #print(json)
    webhook = discord.Webhook.from_url("https://discord.com/api/webhooks/1159745272432304128/plSlbPTZGms0czv3BK9uXWjMBz3KrdjPNry2DRKPldA3ZtOQj_ko9kaljJAbAt-dAKYk",session=session)
    emb = None
    if request.headers.get('X-Gitlab-Event') == "Push Hook":
        emb = await parse_pushhook(json)
    elif request.headers.get('X-Gitlab-Event') == "Tag Push Hook":
        emb = await parse_tagpushhook(json)
    elif request.headers.get('X-Gitlab-Event') in ["Issue Hook","Confidential Issue Hook"]:
        emb = await parse_issueevent(json)
    elif request.headers.get('X-Gitlab-Event') == "Note Hook":
        emb = await parse_comment(json)
    elif request.headers.get('X-Gitlab-Event') == "Merge Request Hook":
        emb = await parse_mergerequest(json)
    elif request.headers.get('X-Gitlab-Event') == "Deployment Hook": # cant test this...
        emb = await parse_deploymentevent(json)
    elif request.headers.get('X-Gitlab-Event') == "Member Hook": # cant test this either...
        emb = await parse_addmember(json)
    else:
        print(request.headers.get('X-Gitlab-Event'))
    
    avatar = await downloadoropen_repoimg(json.get('project').get('id'),json.get('project').get('avatar_url'))
    await webhook.send(embed=emb,username=json.get('project').get('path_with_namespace'),avatar_url=avatar if avatar else MISSING)
    await session.close()

async def parse_pushhook(json: dict) -> discord.Embed:
    branch = json.get('ref').split('/')[-1]
    emb = makeembed_bot(title=f"Branch {branch} was pushed ({json.get('total_commits_count')} commits)",
    url=json.get('project').get('web_url')+'/commits/'+branch,
    author=json.get('user_username')+(f' ({json.get("user_name")})' if json.get('user_name') != json.get('user_username') else ''),
    author_url=f"{webhook_gitlab_url}/{json.get('user_username')}/",
    author_icon_url=json.get('user_avatar'),color=discord.Colour.brand_green())

    desc = f"{json.get('user_username')} pushed to {dchyperlink(json.get('repository').get('homepage')+'/commits/'+branch,branch)} of {dchyperlink(json.get('project').get('web_url'), json.get('project').get('path_with_namespace'))} ({dchyperlink(json.get('project').get('web_url')+'/compare/'+json.get('before')+'...'+json.get('after'),'Compare changes')})\n\n"
    for commit in json.get('commits',[]):
        date = datetime.datetime.fromisoformat(commit.get('timestamp'))
        desc += f"{dchyperlink(commit.get('url'),commit.get('id')[:8])}: {commit.get('message')} \- {commit.get('author').get('name')} {dctimestamp(date,'R')}\n\n"

    emb.description = desc
    return emb

async def parse_tagpushhook(json: dict) -> discord.Embed:
    branch = json.get('ref').split('/')[-1]
    emb = makeembed_bot(title=f"Tag {branch} was updated ({json.get('total_commits_count')} commits)",
    url=json.get('project').get('web_url')+'/commits/'+branch,
    author=json.get('user_username')+(f' ({json.get("user_name")})' if json.get('user_name') != json.get('user_username') else ''),
    author_url=f"{webhook_gitlab_url}/{json.get('user_username')}/",
    author_icon_url=json.get('user_avatar'),color=discord.Colour.yellow())
    return emb

async def parse_issueevent(json: dict) -> discord.Embed:
    emb = makeembed_bot(title=f"Issue #{json.get('object_attributes').get('iid')} {json.get('object_attributes').get('state')}: {json.get('object_attributes').get('title')}",
    url=json.get('object_attributes').get('url'),
    author=json.get('user').get('username')+(f' ({json.get("user").get("name")})' if json.get('user').get('name') != json.get('user').get('username') else ''),
    author_url=f"{webhook_gitlab_url}/{json.get('user').get('username')}/",author_icon_url=json.get('user').get('avatar_url'),color=discord.Colour.brand_red(),
    timestamp=parser.parse(json.get('object_attributes').get('created_at')))

    desc = "Assignees:\n" if len(json.get('assignees',[])) > 0 else ""

    for assignee in json.get('assignees',[]):
        desc += f"{dchyperlink(GITLAB_URL+'/'+assignee.get('username')+'/',assignee.get('username'))} {': '+assignee.get('name')+')' if assignee.get('name') != assignee.get('username') else ''}\n"


    desc += "\nLabels:\n\n" if len(json.get('labels',[])) > 0 else ""

    for label in json.get('labels',[]):
        desc += f"`{label.get('title')}` {': '+label.get('description')+')' if label.get('description') is not None else ''}\n"

    desc += f"\n\nLast Updated {dctimestamp(parser.parse(json.get('object_attributes').get('updated_at')),'R')}"     
    emb.description = desc
    return emb

async def parse_comment(json: dict) -> discord.Embed:
    emb = makeembed_bot(title=f"Comment on {json.get('object_attributes').get('noteable_type')} #{json.get('object_attributes').get('id')}: {json.get('object_attributes').get('note')}",
    url=json.get('object_attributes').get('url'),author=json.get('user').get('username')+(f' ({json.get("user").get("name")})' if json.get('user').get('name') != json.get('user').get('username') else ''),
    author_url=f"{webhook_gitlab_url}/{json.get('user').get('username')}/",author_icon_url=json.get('user').get('avatar_url'),
    timestamp=parser.parse(json.get('object_attributes').get('created_at')),color=discord.Colour.brand_green())
    
    desc = f"{dchyperlink(json.get('repository').get('homepage'),json.get('project').get('path_with_namespace'))}"
    desc += f" {dchyperlink(json.get('object_attributes').get('url'),json.get('object_attributes').get('noteable_type')+' #'+str(json.get('object_attributes').get('id')))} ({json.get('object_attributes').get('note')}):\n"
    desc += f"{json.get('object_attributes').get('note')}"

    emb.description = desc
    return emb

async def parse_mergerequest(json: dict) -> discord.Embed:
    emb = makeembed_bot(title=f"Merge Request #{json.get('object_attributes').get('iid')} {json.get('object_attributes').get('state')}: {json.get('object_attributes').get('title')}",
    url=json.get('object_attributes').get('url'), author=json.get('user').get('username')+(f' ({json.get("user").get("name")})' if json.get('user').get('name') != json.get('user').get('username') else ''),
    author_url=f"{webhook_gitlab_url}/{json.get('user').get('username')}/",author_icon_url=json.get('user').get('avatar_url'),
    timestamp=parser.parse(json.get('object_attributes').get('created_at')),color=discord.Colour.green())

    desc = ""

    desc += f"{dchyperlink(json.get('repository').get('homepage'),json.get('project').get('path_with_namespace'))} {dchyperlink(json.get('object_attributes').get('url'),json.get('object_attributes').get('url').split('/')[-2].replace('_',' ').title().rstrip('s')+' #'+str(json.get('object_attributes').get('iid')))}:\n"
    desc += f"{json.get('object_attributes').get('description')}\n\n"
    desc += f"{dchyperlink(json.get('object_attributes').get('source').get('homepage'),'Source')} (Project {dchyperlink(json.get('object_attributes').get('source').get('web_url'),json.get('object_attributes').get('source').get('path_with_namespace'))})\n"
    emb.description = desc
    return emb

async def parse_deploymentevent(json: dict) -> discord.Embed:
    emb = makeembed_bot(title=f"Deployment #{json.get('deployment_id')} {json.get('status')}: {json.get('commit_title')}",
    url=json.get('commit_url'), author=json.get('user').get('username')+(f' ({json.get("user").get("name")})' if json.get('user').get('name') != json.get('user').get('username') else ''),
    author_url=f"{webhook_gitlab_url}/{json.get('user').get('username')}/",author_icon_url=json.get('user').get('avatar_url'),
    timestamp=parser.parse(json.get('status_changed_at')),color=discord.Colour.green())

    desc = "Deployment of commit "+dchyperlink(json.get('commit_url'),json.get('short_sha'))+" to "+json.get('environment')+" was "+json.get('status')+".\n\n"

    desc += f"{dchyperlink(json.get('project').get('web_url'),json.get('project').get('path_with_namespace'))}\n"

    emb.description = desc
    return emb

async def parse_addmember(json: dict) -> discord.Embed:
    removed = json.get('group_access') is None
    emb = makeembed_bot(title=f"Member {json.get('user_username')} was {'removed from' if removed else 'added/altered in '} group {json.get('group_name')}",
    url=json.get('group_path'), author=json.get('user_username')+(f' ({json.get("user_name")})' if json.get('user_name') != json.get('user_username') else ''),
    author_url=f"{webhook_gitlab_url}/{json.get('user_username')}/",author_icon_url=json.get('user_avatar'),
    timestamp=parser.parse(json.get('created_at')),color=discord.Colour.green())

    desc = f"{dchyperlink(json.get('group_path'),json.get('group_name')+' ('+json.get('group_path'))})\n"
    desc += f"{json.get('user_username')} was added to the group as a {json.get('group_access')}.\n\n"
    emb.description = desc
    return emb

@app.get('/ip/add')
@limiter.limit("5/minute",error_message="bro you need to stop spamming my website")
async def addip(request: Request, ip: str):
    if request.client.host not in admins:
        return JSONResponse(status_code=403, content={'detail': 'Forbidden: get off my website bozo lmao'}, media_type="application/json")
    try:
        with open('ips.txt','a') as f:
            f.write(f"\n{ip}")
        
        loadips()
        return {"status": "ok"}
    except:
        return {"status": "error"}

@app.get('/ip/remove')
@limiter.limit("5/minute",error_message="bro you need to stop spamming my website")
async def removeip(request: Request, ip: str):
    if request.client.host not in admins:
        return JSONResponse(status_code=403, content={'detail': 'Forbidden: get off my website bozo lmao'}, media_type="application/json")
    try:
        with open('ips.txt','r') as f:
            lines = f.read().splitlines()
        with open('ips.txt','w') as f:
            for line in lines:
                if line != ip:
                    f.write(f"\n{line}")
        loadips()
        return {"status": "ok"}
    except:
        return {"status": "error"}

@app.get('/ip/list')
@limiter.limit("5/minute",error_message="bro you need to stop spamming my website")
async def listips(request: Request):
    if request.client.host not in admins:
        return JSONResponse(status_code=403, content={'detail': 'Forbidden: get off my website bozo lmao'}, media_type="application/json")
    return {"ips": ips}

@app.get('/ip/refresh')
@limiter.limit("5/minute",error_message="bro you need to stop spamming my website")
async def refreships(request: Request):
    if request.client.host not in admins:
        return JSONResponse(status_code=403, content={'detail': 'Forbidden: get off my website bozo lmao'}, media_type="application/json")
    try:
        loadips()
        return {"status": "ok"}
    except: return {"status": "error"}

@app.get('/ip/admin/add')
@limiter.limit("5/minute",error_message="bro you need to stop spamming my website")
async def addadmin(request: Request, ip: str):
    if request.client.host not in admins:
        return JSONResponse(status_code=403, content={'detail': 'Forbidden: get off my website bozo lmao'}, media_type="application/json")
    try:
        with open('admins.txt','a') as f:
            f.write(f"\n{ip}")
        
        loadips()
        return {"status": "ok"}
    except:
        return {"status": "error"}

@app.get('/ip/admin/remove')
@limiter.limit("5/minute",error_message="bro you need to stop spamming my website")
async def removeadmin(request: Request, ip: str):
    if request.client.host not in admins:
        return JSONResponse(status_code=403, content={'detail': 'Forbidden: get off my website bozo lmao'}, media_type="application/json")
    try:
        with open('admins.txt','r') as f:
            lines = f.read().splitlines()
        with open('admins.txt','w') as f:
            for line in lines:
                if line != ip:
                    f.write(f"\n{line}")
        loadips()
        return {"status": "ok"}
    except:
        return {"status": "error"}

@app.get('/ip/admin/list')
@limiter.limit("5/minute",error_message="bro you need to stop spamming my website")
async def listadmins(request: Request):
    if request.client.host not in admins:
        return JSONResponse(status_code=403, content={'detail': 'Forbidden: get off my website bozo lmao'}, media_type="application/json")
    return {"admins": admins}

async def downloadoropen_repoimg(projectid,url) -> Optional[BytesIO]:
    file = None
    filename = ""
    r = None
    
    os.chdir("avatars/projects")

    if url is not None:
        filename = f"{projectid}.{url.split('/')[-1].split('.')[-1]}"
    else:
        for f in os.listdir():
            if f.startswith(f"{projectid}."): # so it doesnt return project 25 if looking for project 2
                filename = f
                break
        if filename == "":
            os.chdir("../../")
            return discord.utils.MISSING
            

    if not os.path.exists(filename):
        r = requests.get(url,cookies={
            "remember_user_token": "eyJfcmFpbHMiOnsibWVzc2FnZSI6IlcxczFNRjBzSWlReVlTUXhNQ1JKVTNaeU9WcGFkRlIyUWtsd0wxWndaV3QyWm5oUElpd2lNVFk1TmpRMk9UTTNPQzQwT1RreE1EVWlYUT09IiwiZXhwIjoiMjAyMy0xMC0xOVQwMToyOTozOC40OTlaIiwicHVyIjoiY29va2llLnJlbWVtYmVyX3VzZXJfdG9rZW4ifX0%3D--c492e579765ec6135c165d11d6e1eb532302e16d"
        })

    with open(filename,'wb') as f:
        if r is not None: f.write(r.content)
        f.seek(0)
        if r is not None:
            file = BytesIO(f.read())
        else:
            file = None
    os.chdir('../../')
    return file

@app.get('/')
@limiter.limit("5/minute",error_message="bro you need to stop spamming my website")
async def index(request: Request):
    return JSONResponse({"status": "ok don't care"})

@app.get('/favicon.ico')
@limiter.limit("5/minute",error_message="bro you need to stop spamming my website")
async def favicon(request: Request):
    return FileResponse('https://i.ibb.co/QrwTwB9/amogus-impostor.jpg',302)

@app.get('/gitlab/auth')
@limiter.limit("5/minute",error_message="bro you need to stop spamming my website")
async def gitlab_auth(request: Request,code: str, state: str):
    return RedirectResponse(url=f"{str(request.url).replace('auth','oauth')}",status_code=302)

@app.get('/gitlab/oauth')
@limiter.limit("5/minute",error_message="bro you need to stop spamming my website")
async def gitlab_oauth(request: Request, code: str, state: Optional[str]=None):
    session = aiohttp.ClientSession()

    #gitlab_url = (await get_discord_auth(discordid)).gitlab_url
    gitlab_url = (await GitlabApiUser.get(state=state)).gitlab_url

    r = await session.post(f"{webhook_gitlab_url}/oauth/token",#headers={"Accept": "application/json"},
    data = {'client_id': gl_id,
    'client_secret': gl_secret,
    'code': code,
    'grant_type': 'authorization_code',
    'redirect_uri': redirect})
    r = await r.json()
    rr = await session.get(f'{webhook_gitlab_url}/api/v4/user',headers={"Authorization": "Bearer "+r.get('access_token')})
    rr = await rr.json()
    user = await GitlabApiUser.get(gitlab_url=gitlab_url, username=rr.get('username')) 
    user.token = r.get('access_token')
    user.refresh_token = r.get('refresh_token')
    user.expires_in = r.get('expires_in')
    user.created_at = datetime.datetime.fromtimestamp(int(r.get('created_at'))) if r.get('created_at',None) else datetime.datetime.now()
    await user.save()
    await session.close()
    return {'200': "bro i think it wored"}

@app.get('/discord/auth')
@limiter.limit("5/minute",error_message="bro you need to stop spamming my website")
async def discord_auth(request: Request, code: str, state: str=""):
    return RedirectResponse(url=f"{str(request.url).replace('auth','oauth')}",status_code=302)

@app.get('/discord/oauth/')
@limiter.limit("5/minute",error_message="bro you need to stop spamming my website")
async def discord_oauth(request: Request, code: str, state: str=""):
    return RedirectResponse(url=f"{str(request.url).replace('oauth','oauth/general')}",status_code=302)

async def authorize_discord_token(request: Request, code: str, state: Optional[str]=None, *, session: Optional[aiohttp.ClientSession]=None, close_whendone: bool=False) -> Optional[dict]:
    """close_whendone = close_session when done"""
    if session is None:
        session = await get_session()

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    r = await session.post(f'{DISCORD_API}/oauth2/token',headers=headers,auth=aiohttp.BasicAuth(str(client_id), str(client_secret)),data={
    'grant_type': 'authorization_code',
    'code': code,
    'redirect_uri': f'{request.url.scheme}://{request.url.hostname}{(":"+str(request.url.port) if request.url.port else "")}{request.url.path}',
    })
    r = await r.json()
    if close_whendone: await close_session(session)
    return r

async def push_metadata(token: str, roles: dict[str, Union[bool, str, int]],platform_name: str='Windows 98'):
    """roles = [rolename, rolevalue]"""
    url = f"{DISCORD_API}/users/@me/applications/:id/role-connection"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}'
    }
    session = await get_session()
    r = await session.put(url,headers=headers,json={
        'platform_name': platform_name,
        **roles,
    })
    return await r.json()

async def register_metadata(roles: Union[list[dict[str, Union[str, int]]],dict]):
    """Provide a dictionary or a list of dictionaries similar to the following example:
    Adds the provided roles to the LinkedRoles database table and pushed to discord.
    
    {
        key: 'cookieseaten',
        name: 'Cookies Eaten',
        description: 'Cookies Eaten Greater Than',
        type: 2, (see :class:LinkedRoleType)
    },
    {
        key: 'allergictonuts',
        name: 'Allergic To Nuts',
        description: 'Is Allergic To Nuts',
        type: 7,
    },"""
    url = f"{DISCORD_API}/applications/{client_id}/role-connections/metadata"
    if isinstance(roles,dict): roles: list[dict[str, Union[str, int]]] = [roles]
    else: roles: list[dict[str, Union[str, int]]] = roles

    for role in roles:
        if await LinkedRoles.filter(key=role.get('key')).exists():
            return Exception(f'{role} already exists')
        if role.get('using_db',False): role.pop('using_db')
        await LinkedRoles.create(**role) # type: ignore
    session = await get_session()
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bot {token}'
    }
    r = await session.put(url, headers=headers, json=roles)
    print(r)
    print(await r.json())
    return await r.json()

async def get_metadata() -> dict:
    """Get's all the metadata from discord."""
    url = f"{DISCORD_API}/applications/{client_id}/role-connections/metadata"
    headers = {
        'Authorization': f'Bot {token}'
    }
    session = await get_session()
    r = await session.get(url,headers=headers)
    return await r.json()

class LinkedRoleType(Enum):
    """All the types of linked roles."""
    number_lt = 1
    """Number is less than.
    Ex: Number of cookies is less than"""
    number_gt = 2
    """Number is greater than.
    Ex: Number of cookies is greater than"""
    number_eq = 3
    """Number.
    Ex: Number of bitches is 0"""
    number_neq = 4
    """Not a number.
    Ex: Number of bitches is not 0"""
    datetime_lt = 5
    """Datetime (less than.)
    Ex: Days ago since baking their first cookie"""
    datetime_gt = 6
    """Datetime (greater than.)
    Ex: Days since baking their first cookie"""
    boolean_eq = 7
    """Regular Boolean.
    Ex: Is Allergic To Nuts"""
    boolean_neq = 8
    """Not a boolean.
    Ex: Is Not Allergic To Nuts"""

    @staticmethod
    def all():
        return [LinkedRoleType.number_lt, LinkedRoleType.number_gt, LinkedRoleType.number_eq, LinkedRoleType.number_neq, LinkedRoleType.datetime_lt, LinkedRoleType.datetime_gt, LinkedRoleType.boolean_eq, LinkedRoleType.boolean_neq]

    def __int__(self):
        return self.value
    
    def __str__(self):
        return self.name

@app.get('/discord/oauth/general/')
@limiter.limit("5/minute",error_message="bro you need to stop spamming my website")
async def discord_oauth_general(request: Request, code: str, state: Optional[str]=None):
    #print(r)
    session = await get_session()
    r = await authorize_discord_token(request, code, state, session=session)

    rr = await session.get(f'{DISCORD_API}/oauth2/@me',headers={"Authorization": f"Bearer {r.get('access_token')}"})

    rr = await rr.json()
    await session.close()

    #print(rr)
    #'user': {'id': '458657458995462154', 'username': 'aidenpearce3066', 'avatar': '3acfe15b991e017b80f0430797927156', 'discriminator': '0', 'public_flags': 4194368, 'flags': 4194368, 'banner': None, 'accent_color': None, 'global_name': 'Aiden Pearce', 'avatar_decoration_data': None, 'banner_color': None}}
    discordid = rr.get('user').get('id')

    try:
        await DiscordAuthUser.create(discordid=discordid,botid=client_id,token_type=r.get('token_type'),token=r.get('access_token'),refresh_token=r.get('refresh_token'),expires_in=r.get('expires_in'),scope=r.get('scope'))
        return {'200': "bro i think it worked, ok go back to discord link your gitlab"}
    except:
        traceback.print_exc()

@app.get('/discord/oauth/linkedroles/')
async def oauth_linkedroles(request: Request):
    """Get the linked roles page."""
    return RedirectResponse(
        discord.utils.oauth_url(client_id, scopes=['identify','role_connections.write'],
        redirect_uri='https://aidenpearce.space/discord/oauth/general/',state=get_random_state(16)),
    )

@app.post('/discord/oauth/linkedroles/user/update/')
@limiter.limit("5/minute",error_message="bro you need to stop spamming my website")
async def linked_role_update(request: Request, data: dict):
    # data = {'userid': 123, rolename: rolevalue, rolename2: rolevalue2}
    try:
        token = (await DiscordAuthUser.get(discordid=data.get('userid'))).token
        data.pop('userid')
        await push_metadata(token, data)
    except:
        traceback.print_exc()
        return {'500': 'error'}

@app.post('/discord/oauth/linkedroles/push/')
async def linked_role_register(request: Request, data: list[dict[str, Union[str, int]]]):
    """Push linked roles to discord.
    Take a list of dictionaries.
    {
        'key': 'basicallyid',
        'name': "Shown name",
        "description": 'desc',
        type: 2 (see LinkedRoleType)
    }"""
    # data = [{'key': 'basicallyid', 'name': "Shown name", "description": 'desc', type: 2 -> LinkedRoleType}]
    try:
        for role in data:
            if await LinkedRoles.filter(key=role.get('key')).exists():
                return Response(f'{role} already exists',422)
        await register_metadata(data)
        return Response(status_code=204)
    except Exception as e:
        return Response(e, 500)

@app.get('/discord/oauth/linkedroles/get')
async def linked_role_get(request: Request):
    """Get all linked roles."""
    return JSONResponse(await get_metadata())

@app.get('/teapot')
async def teapot(request: Request):
    return Response("hahaha im so funny i made a teapot\nNO SCREW YOU 418 ERROR FOR YOU",418)

@app.get('/images/')
async def get_image(request: Request):
    for image in os.listdir('/images'):
        if (os.path.isdir(f'/images/{image}') 
        or image.startswith('_') 
        or image.startswith('.')): 
            continue


async def check_user_auth(id: int):
    try:
        return await check_gitlab_auth(id) or await check_discord_auth(id)
    except:
        traceback.print_exc()
        return False

async def check_gitlab_auth(id: int):
    try:
        return await GitlabApiUser.filter(discordid=id).exists()
    except:
        traceback.print_exc()
        return False

async def get_gitlab_auth(id: int):
    try:
        return await GitlabApiUser.get(discordid=id)
    except:
        #traceback.print_exc()
        return None

async def check_discord_auth(id: int):
    try:
        return await DiscordAuthUser.filter(discordid=id).exists()
        #return (await DiscordAuthUser.get(discordid=id))
    except:
        traceback.print_exc()
        return False

async def get_discord_auth(id: int):
    try:
        return await DiscordAuthUser.get(discordid=id)
    except:
        traceback.print_exc()
        return None

async def create_gitlab(id: int, gitlab_url: str,username: str,state: str):
    await GitlabApiUser.create(discordid=id,gitlab_url=gitlab_url,username=username,state=state)

async def delete_user(id: int):
    return await delete_discord_user(id) and await delete_gitlab_user(id)

async def delete_discord_user(id: int):
    user = (await DiscordAuthUser.get(discordid=id))
    user = dict(user)
    for k in ('dbid','datelogged','lastupdated'):
        user['old'+k] = user.pop(k)
    await ArchivedDiscordAuthUser.create(**user)
    await DiscordAuthUser.filter(discordid=id).delete()
    return True

async def delete_gitlab_user(id: int):
    user = (await GitlabApiUser.get(discordid=id))
    user = dict(user)
    for k in ('dbid','datelogged','lastupdated'):
        user['old'+k] = user.pop(k)
    await ArchivedGitlabApiUser.create(**user)
    await GitlabApiUser.filter(discordid=id).delete()
    return True

async def update_user_settings(id: int, **kwargs):
    """Current settings:
    dm: bool (Default False)
    showgitlab: bool (Default True)
    """
    user = await UserSettings.get(discordid=id)

    if user is None: raise Exception("no user")
    await user.update_from_dict(kwargs)

async def get_user_settings(id: int):
    try:
        user = await UserSettings.get(discordid=id)
        return user
    except:
        return None

async def create_user_settings(id: int, dm: bool=False, **kwargs):
    """Current settings:
    dm: bool (Default False)
    showgitlab: bool (Default True)
    """
    await UserSettings.create(discordid=id,dm=dm,**kwargs)

# @asynccontextmanager
# async def lifecycle(app: fastapi.FastAPI):
#     await startup(app)
#     yield
#     await shutdown(app)

# async def startup(app: fastapi.FastAPI):
#     await Tortoise.init(config_file='config.yml')
#     await Tortoise.generate_schemas()
#     print('ch')

# async def shutdown(app: fastapi.FastAPI):
#     await Tortoise.close_connections()

@app.on_event('startup')
async def startup_event():
    await Tortoise.init(config_file='config.yml')
    await Tortoise.generate_schemas()
    # LinkedRole(LinkedRoleType.number_eq, key='bitches',name='Number of Bitches',description='The amount of bitches you pull')
    # print(await register_linked_roles(LinkedRole(LinkedRoleType.number_eq, key='bitches',name='Number of Bitches',description='The amount of bitches you pull')))
    # return

@app.on_event('shutdown')
async def shutdown_event():
    await close_sessions()

# if __name__ == '__main__':
#     uvicorn.run(app, host="127.0.0.1", port=3066,log_config='log.ini')


class LinkedRole:
    type: LinkedRoleType
    key: str
    name: str
    description: str
    name_localizations: Optional[str]
    description_localizations: Optional[str]
    __dict: dict

    def __init__(self, type: Union[int, LinkedRoleType], *, key: str, name: str, description: str, name_localizations: Optional[str]=None, description_localizations: Optional[str]=None):
        self.type = LinkedRoleType(int(type))
        self.key = key
        self.name = name
        self.description = description
        self.name_localizations = name_localizations
        self.description_localizations = description_localizations
        self.__dict = {
            "type": int(type),
            "key": key,
            "name": name,
            "description": description,
            "name_localizations": name_localizations,
            "description_localizations": description_localizations
        }
    
    @staticmethod
    def from_json(json: dict):
        return LinkedRole(**json)
    
    def to_json(self):
        self.__dict = {
            "type": int(self.type),
            "key": self.key,
            "name": self.name,
            "description": self.description,
            "name_localizations": self.name_localizations,
            "description_localizations": self.description_localizations
        }
        print(self.__dict)
        return self.__dict
    
    def __str__(self):
        return f"LinkedRole(type={int(self.type)},key={self.key},name={self.name},description={self.description},name_localizations={self.name_localizations},description_localizations={self.description_localizations})"

    def __dict__(self):
        return self.to_json()
