import tortoise
from tortoise import Tortoise, fields
from tortoise.exceptions import IntegrityError
from tortoise.models import Model
import asyncio

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
    token = fields.TextField(null=True)
    refresh_token = fields.TextField(null=True)  
    expires_in = fields.BigIntField(null=True) 
    created_at = fields.DatetimeField(null=True)

    class Meta:
        table = "GitlabApiUsers"

class DiscordAuthUser(Base):
    discordid = fields.BigIntField(unique=True)
    token_type = fields.TextField(null=True)
    token = fields.TextField(null=True)
    refresh_token = fields.TextField(null=True)  
    expires_in = fields.BigIntField(null=True) 
    created_at = fields.DatetimeField(null=True)
    scope = fields.TextField(null=True)
    gitlab_url = fields.TextField(null=True)

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
    token = fields.TextField(null=True)
    refresh_token = fields.TextField(null=True)  
    expires_in = fields.BigIntField(null=True) 
    created_at = fields.DatetimeField(null=True)
    scope = fields.TextField(null=True)
    gitlab_url = fields.TextField(null=True)

    class Meta:
        table = "ArchivedDiscordAuthUsers"
