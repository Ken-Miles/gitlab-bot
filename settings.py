from typing import Any, Union, List, Dict, Optional, Tuple, Literal
import discord
from discord import AppCommandType, TextChannel, app_commands, guild
from discord.ext import commands, tasks
from discord.utils import _URL_REGEX
from aidenlib.main import makeembed, makeembed_bot
import inspect
from webserver import GenericSetting, create_user_settings, settings, get_user_settings, update_user_settings, get_gitlab_auth

class SettingsCog(commands.Cog):
    bot: commands.Bot
    def __init__(self, bot: commands.Bot):
        self.bot = bot

        self.gitlab_context_menu = app_commands.ContextMenu(name="Gitlab",
            callback=self.gitlab,type=AppCommandType.user)
    
    @commands.hybrid_group(name="settings")
    async def settings(self, ctx: commands.Context):
        """Change your settings."""
        pass
    
    @settings.command(name='dms')
    @app_commands.describe(value="Whether to DM you or not. (True = Allow)")
    async def settings_dms(self, ctx: commands.Context, value: bool):
        """Whether the bot should DM you or not."""
        if (user := await get_user_settings(ctx.author.id)) is None:
            await create_user_settings(ctx.author.id,dm=value)
        elif user.dm != value:
            await update_user_settings(ctx.author.id,dm=value)
        else:
            return await ctx.reply("You already have that setting set.")
        await ctx.reply("Successfully updated your settings.")

    @settings.command(name='showgitlab')
    @app_commands.describe(value="Whether to show your gitlab username in your profile. (True = Show)")
    async def settings_showgitlab(self, ctx: commands.Context, value: bool):
        """Whether to show your gitlab username in your profile."""
        if (user := await get_user_settings(ctx.author.id)) is None:
            await create_user_settings(ctx.author.id,showgitlab=value)
        elif user.showgitlab != value:
            await update_user_settings(ctx.author.id,showgitlab=value)
        else:
            return await ctx.reply("You already have that setting set.")
        await ctx.reply("Successfully updated your settings.")

    async def gitlab(self, interaction: discord.Interaction, user: discord.User):
        await interaction.response.defer(thinking=True,ephemeral=True)
        try:
            user_ = await get_gitlab_auth(interaction.user.id)
            if user_ is None and not self.bot.is_owner(interaction.user):
                await interaction.followup.send("This person ain't authenticated their Gitlab yet.")
                return
            user_ = await get_gitlab_auth(interaction.user.id)
            if user_ is None: raise Exception()
            if (await get_user_settings(user.id)).showgitlab is False:
                return await interaction.followup.send("This person has disabled showing their Gitlab username in their profile.")
        except:
            return await interaction.followup.send("This person ain't authenticated their Gitlab yet.")

# async def setup(bot: commands.Bot):
#     await bot.add_cog(SettingsCog(bot))