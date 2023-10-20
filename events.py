import asyncio
import datetime
from functools import lru_cache
from http import HTTPStatus
from io import BytesIO
import io
import logging
from logging import FileHandler, handlers
import os
from pprint import pprint
import re
import time
from typing import TYPE_CHECKING, Annotated
from typing import Optional
import requests
from PIL import Image
from aidenlib.main import (
    dchyperlink,
    dctimestamp,
    getorfetch_channel,
    makeembed,
    makeembed_bot,
)
import aiohttp
from asyncpg import UniqueViolationError
from asyncpg.connection import traceback
from dateutil import parser
import discord
from discord import TextChannel, app_commands, guild
from discord.ext import commands, tasks
from discord.utils import _URL_REGEX
import fastapi
from fastapi import Depends, FastAPI, HTTPException, Header, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.security import OAuth2PasswordBearer
import gitlab
from gitlab.v4.objects import Project, User, UserManager
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
import tortoise
from tortoise import Tortoise, fields
from tortoise.exceptions import IntegrityError
from tortoise.models import Model
import uvicorn
import yaml
import json as Json
import string
import random

if TYPE_CHECKING:
    from webserver import GitlabApiUser, DiscordAuthUser, ArchivedDiscordAuthUser, ArchivedGitlabApiUser, GitlabRepo


URL_REGEX = re.compile(_URL_REGEX)

with open('apikeys.yml','r') as f: 
    keys = dict(yaml.safe_load(f))
    token = keys.get('me')
    gl_id = keys.get('gitlab_appid')
    gl_secret = keys.get('gitlab_appsecret')
    redirect = keys.get('redirect')
    scopes = "api+read_api+read_user+read_repository+write_repository+sudo"

with open('client.yml') as f:
    keys = dict(yaml.safe_load(f))
    client_id = keys.get('client_id')
    client_secret = keys.get('client_secret')

def get_random_state(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

class EventCog(commands.Cog):
    bot: commands.Bot

    def __init__(self, bot: commands.Bot):
        self.bot = bot
    
    @tasks.loop(minutes=1)
    async def checkrepos():
        for user in await GitlabApiUser.all():

            gl = gitlab.Gitlab(user.gitlab_url, user.token)
            
            for p in gl.projects.list():
                print(p.attributes)
                return
                try:
                    attrs = {}
                    for attr, value in p.attributes.items():
                        if attr in GitlabRepo._meta.fields:
                            attrs[attr] = value
                    r = await GitlabRepo.get(**attrs)
                    if r is None:
                        print('created')
                        await GitlabRepo.create(**attrs)
                except (IntegrityError,UniqueViolationError):
                    r = gl.http_get(f"/projects/{p.get_id()}/hooks")
                    for wb in r:
                        if wb.get("url") == "https://aidenpearce.space/githubwebhook":
                            #'merge_requests_events': True, 'repository_update_events': False, 'enable_ssl_verification': True, 'project_id': 266, 'issues_events': True, 'confidential_issues_events': True, 'note_events': True, 'confidential_note_events': True, 'pipeline_events': True, 'wiki_page_events': True, 'deployment_events': True, 'job_events': True, 'releases_events': True, 'push_events_branch_filter': None},
                            if wb.get("push_events") and wb.get('tag_push_event') and wb.get('merge_requests_events') and not wb.get('repository_update_events') \
                                and wb.get('enable_ssl_verification') and wb.get('issues_events') and wb.get('confidential_issues_events') and wb.get('note_events') \
                                    and wb.get('confidential_note_events') and wb.get('pipeline_events') and wb.get('wiki_page_events') and wb.get('deployment_events') \
                                        and wb.get('job_events') and wb.get('releases_events'):
                                            continue 
                        else:
                            try:
                                r = gl.http_post(f"/projects/{p.get_id()}/hooks",query_data={
                                    "id": p.get_id(),
                                    "url": "https://aidenpearce.space/githubwebhook",
                                    "push_events": True,
                                    "enable_ssl_verification": True,
                                    "issues_events": True,
                                    "merge_requests_events": True,
                                    "tag_push_events": True,
                                    "note_events": True,
                                    "job_events": True,
                                    "pipeline_events": True,
                                    "wiki_page_events": True,
                                    "confidential_issues_events": True,
                                    "confidential_note_events": True,
                                    "deployment_events": True,
                                    "releases_events": True,
                                    })
                                if r.status_code == 403: raise Exception()
                            except:
                                continue

    @commands.hybrid_group(name='link',description='Authenticate your Discord to allow authentication of your Gitlab.',fallback='discord')
    async def authenticate(self, interaction: commands.Context):
        # ensure gitlaburl is a valid gitlab url
        await interaction.defer(ephemeral=True)
        if t := await webserver.check_discord_auth(interaction.author.id):
            return await interaction.reply("You've already authenticated your Discord account. If this was an accident, run `/unlink discord` to unlink your Discord account.") 
        print(t)
        await interaction.reply(f"Go {dchyperlink('https://discord.com/api/oauth2/authorize?client_id=1159299331061461032&redirect_uri=https%3A%2F%2Faidenpearce.space%2Fdiscord%2Foauth&response_type=code&scope=identify','here')}"
        " to authorize your Discord.")

    @authenticate.command(name='gitlab',description='Link your Gitlab.')
    @app_commands.describe(gitlab_url="Your gitlab URL. Should be something like https://gitlab.[yoururl].com.")
    async def authenticate_gitlab(self, ctx: commands.Context, gitlab_url: str, gitlab_username: str):
        try:
            await ctx.defer(ephemeral=True)
            if not await webserver.check_discord_auth(ctx.author.id):
                return await ctx.reply("You need to authenticate your Discord account first. Run `/link discord` first then run this.")
            if await webserver.check_gitlab_auth(ctx.author.id):
                return await ctx.reply("You've already authenticated your Gitlab account. If this was an accident run `/unlink gitlab` to unlink your Gitlab account.")
            if not URL_REGEX.match(gitlab_url):
                return await ctx.reply("That's not a valid URL.")
            gitlab_url = gitlab_url.rstrip('/')
            state = f"{ctx.author.id}.{int(datetime.datetime.now().timestamp())}.{get_random_state(16)}"
            await webserver.create_gitlab(ctx.author.id,gitlab_url,gitlab_username,state)
            await ctx.reply(f"Go {dchyperlink(f'{gitlab_url}/oauth/authorize?client_id={gl_id}&redirect_uri={redirect}&response_type=code&scope={scopes}&state={state}','here')} to authorize.")
        except:
            traceback.print_exc()

    @commands.hybrid_group(name='unlink',description='Disconnect your discord from your Gitlab.',fallback='discord')
    async def unauthenticate(self, ctx: commands.Context):
        await ctx.defer(ephemeral=True)
        if not await webserver.check_discord_auth(ctx.author.id):
            return await ctx.reply("You haven't authenticated your Discord account yet.")
        await webserver.delete_discord_user(ctx.author.id)
        await ctx.reply("Successfully unlinked your Discord account.")
    
    @unauthenticate.command(name='gitlab',description='Disconnect your Gitlab from your Discord.')
    async def unauthenticate_gitlab(self, ctx: commands.Context):
        try:
            await ctx.defer(ephemeral=True)
            if not await webserver.check_gitlab_auth(ctx.author.id):
                return await ctx.reply("You haven't authenticated your Gitlab account yet.")
            await webserver.delete_gitlab_user(ctx.author.id)
            await ctx.reply("Successfully unlinked your Gitlab account.")
        except Exception as e:
            await ctx.reply(f"Something went wrong: {e} {__name__}")


async def setup(bot: commands.Bot):
    cog = EventCog(bot)
    await tortoise.Tortoise.init(config_file='config2.yml')
    #cog.checkrepos.start()
    await bot.add_cog(cog)
