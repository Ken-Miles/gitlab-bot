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
from aidenlib.main import dchyperlink, dctimestamp, getorfetch_channel, makeembed
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
import gitlab
from gitlab import Gitlab
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
from urllib.parse import urlparse 
from main import logger_

if TYPE_CHECKING:
    from webserver import check_gitlab_auth, get_gitlab_auth 
    from webserver import GitlabApiUser, DiscordAuthUser, ArchivedDiscordAuthUser, ArchivedGitlabApiUser, GitlabRepo


def has_gitlab_auth():
    async def predicate(ctx):
        return await check_gitlab_auth(ctx.author.id) is not None
    return commands.check(predicate)

class GitlabCog(commands.Cog):
    bot: commands.Bot
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    async def get_gitlab(self, id: int) -> Gitlab:
        """Get a Gitlab object from a discord user id."""
        user = await get_gitlab_auth(id)
        return Gitlab(user.gitlab_url, private_token=user.token)
    
    @commands.hybrid_command(name='issue',description='Show an issue from a gitlab repo',aliases=['i'])
    @has_gitlab_auth()
    @app_commands.describe(issue='The issue you want to view.',repo='The repo you want to view the issue from.')
    async def get_issue(self, ctx: commands.Context, issue: app_commands.Range[int, 0,100_000], repo: str):
        await ctx.defer()
        gl = await self.get_gitlab(ctx.author.id)
        issues = gl.projects.get(urlparse(repo).path[1:]).issues.get(issue)
        await ctx.send(embed=makeembed_bot(
            title=f"#{issues.iid} {issues.title}",
            description=issues.description,
            color=discord.Color.orange(),
            timestamp=datetime.datetime.now()
        ))

    @commands.hybrid_command(name='projects',description='Show repositories you have access to.',aliases=['repos','r'])
    @has_gitlab_auth()
    async def get_projects(self, ctx: commands.Context):
        try:
            await ctx.defer()
            gl = await self.get_gitlab(ctx.author.id)
            projects = gl.projects.list()
            embed = makeembed(
                title=f"Projects for {gl.user.username}",
                description='\n'.join([f"[{p.name}]({p.web_url})" for p in projects]),
                color=discord.Color.blurple(),
                timestamp=datetime.datetime.now()
            )
            await ctx.send(embed=embed)
        except Exception as e:
            await ctx.send(f"You don't have any projects. {e}")


    @commands.hybrid_command(name='gitlab',description='Show your gitlab profile.',aliases=['gl'])
    @has_gitlab_auth()
    async def show_gitlab(self, ctx: commands.Context):
        try:
            await ctx.defer()
            gl = await self.get_gitlab(ctx.author.id)
            user = gl.user
            gl.user
            print(user)
            print()
            embed = makeembed(
                title=f"Gitlab profile for {user}",
                color=discord.Color.blurple(),
                timestamp=datetime.datetime.now()
            )
            embed.set_thumbnail(url=user.avatar_url)
            embed.add_field(name="Username",value=user.username)
            embed.add_field(name="Name",value=user.name)
            embed.add_field(name="Location",value=user.location)
            embed.add_field(name="Bio",value=user.bio)
            embed.add_field(name="Website",value=user.website_url)
            await ctx.send(embed=embed)
        except Exception as e:
            await ctx.send(f"You don't have any projects. {e}")
    
    @commands.Cog.listener()
    async def on_comand_error(self, ctx: commands.Context, error: commands.CommandError):
        ignored = (commands.CommandNotFound, commands.UserInputError)
        delete_after = (10.0 if not ctx.interaction else None)
        if isinstance(error, commands.CommandInvokeError):
            logger_.error(f'In {ctx.command}: {error}', exc_info=error.original)
            try:
                console_webhook = "https://discord.com/api/webhooks/1162835268550791280/SpzMGWcHyC7hNeh4KCPsoKmE-WK0JRP9B3-NsY_dpDm2hTzHwfh2kOL_XvpHp87DWeP2"
                await discord.Webhook.from_url(console_webhook).send(f"{error}")
            except: pass
        elif isinstance(error, ignored): return
        elif isinstance(error, commands.NotOwner):
            await ctx.reply("You're not my father (well creator...)",ephemeral=True, delete_after=delete_after)
        #    send(youre not my daddy!)
        else:
            await ctx.reply(str(error),ephemeral=True,delete_after=delete_after)

async def setup(bot: commands.Bot):
    await bot.add_cog(GitlabCog(bot))