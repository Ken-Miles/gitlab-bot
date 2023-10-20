import discord
from discord import app_commands, guild, TextChannel
from discord.ext import commands
import os
import asyncio
import datetime
import time
import yaml
import logging
from logging import FileHandler, handlers
import requests
import aiohttp
from aidenlib.main import makeembed, getorfetch_channel
import tortoise

with open('client.yml', 'r') as f: token = dict(yaml.safe_load(f)).get('token')

currentdate_epoch = int(datetime.datetime.timestamp(datetime.datetime.now()))
currentdate = datetime.datetime.fromtimestamp(currentdate_epoch)

me = 458657458995462154

guilds = [1029151630215618600,1149513568069365831]


emojidict: dict[str | int, str] = {
'discord': '<:discord:1080925531580682360>',
# global
"x": '<a:X_:1046808381266067547>',
'x2': "\U0000274c",
"check": '<a:check_:1046808377373769810>',
"check2": '\U00002705',
'L': "\U0001f1f1",
'l': "\U0001f1f1",
"salute": "\U0001fae1",

"calendar": "\U0001f4c6",
"notepad": "\U0001f5d2",
"alarmclock": "\U000023f0",
"timer": "\U000023f2",
True: "<:check:1046808377373769810>",
"maybe": "\U0001f937",
False: "<a:X_:1046808381266067547>",
"pong": "\U0001f3d3",

'red': "\U0001f534",
"yellow": "\U0001f7e1",
"green": "\U0001f7e2",
"blue": "\U0001f535",
'purple': "\U0001f7e3",

"headphones": "\U0001f3a7",

"hamburger": '🍔',
"building": '🏛️',
"click": '🖱️',
"newspaper": '📰',
"pick": '⛏️',
"restart": '🔄',

"skull": "\U0001f480",
"laughing": "\U0001f923",
"notfunny": "\U0001f610",

1: "\U00000031"+"\U0000fe0f"+"\U000020e3",
2: "\U00000032"+"\U0000fe0f"+"\U000020e3",
3: "\U00000033"+"\U0000fe0f"+"\U000020e3",
4: "\U00000034"+"\U0000fe0f"+"\U000020e3",
5: "\U00000035"+"\U0000fe0f"+"\U000020e3",

"stop": "\U000023f9",
"playpause": "\U000023ef",
"eject": "\U000023cf",
"play": "\U000025b6",
"pause": "\U000023f8",
"record": "\U000023fa",
"next": "\U000023ed",
"prev": "\U000023ee",
"fastforward": "\U000023e9",
"rewind": "\U000023ea",
"repeat": "\U0001f501",
"back": "\U000025c0",
"forward": "\U000025b6", # same as play
"shuffle": "\U0001f500",
}

if __name__ == "__main__": 
    print(f"""Started running:
{currentdate}
{currentdate_epoch}""")

intents = discord.Intents.all()
bot = commands.Bot(command_prefix=commands.when_mentioned,intents=intents,activity=discord.Activity(type=discord.ActivityType.playing,name='with the API'), status=discord.Status.online)
tree = bot.tree


logger = logging.getLogger('discord')
logger.setLevel(logging.ERROR)
logging.getLogger('discord.http').setLevel(logging.INFO)

handler = logging.FileHandler(filename='bot.log', encoding='utf-8', mode='w')
dt_fmt = '%Y-%m-%d %H:%M:%S'
formatter = logging.Formatter('[{asctime}] [{levelname:<8}] {name}: {message}', dt_fmt, style='{')
handler.setFormatter(formatter)
logger.addHandler(handler)

logger_ = logging.getLogger("commands")
logger_.addHandler(handler)
logger_.setLevel(logging.INFO)

@bot.event
async def on_ready():
    date = datetime.datetime.fromtimestamp(int(datetime.datetime.now().timestamp()))
    print(f"{date}: Ready!")

async def main():
    async with aiohttp.ClientSession() as session:
        async with aiohttp.ClientSession() as session2:
            async with aiohttp.ClientSession() as session3:
                bot.session = session
                bot.session2 = session2
                bot.session3 = session3
                discord.utils.setup_logging(handler=handler)
                for file in os.listdir('./'):
                    if not file.startswith('_') and file not in ["main.py",'db.py','webserver.py','run.py','settings.py'] and file.endswith('.py'):
                        await bot.load_extension(f'{file[:-3]}')
                await bot.load_extension("jishaku")
                #await bot.load_extension("aidenlib.main.helpercog")
                await bot.start(token)

if __name__ == '__main__': asyncio.run(main())