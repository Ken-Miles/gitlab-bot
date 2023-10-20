import asyncio
from webserver import app
from main import bot
from uvicorn import Config, Server
import os
import discord
from main import handler, token
import contextlib
import threading
import time

class Server(Server):
    def install_signal_handlers(self):
        pass

    @contextlib.contextmanager
    def run_in_thread(self, loop):
        thread = threading.Thread(target=loop.create_task(self.serve()))
        thread.start()
        try:
            while not self.started:
                time.sleep(1e-3)
            yield
        finally:
            self.should_exit = True
            thread.join()



async def bootstrap():
    async with bot:
        discord.utils.setup_logging(handler=handler)
        for file in os.listdir('./'):
            if not file.startswith('_') and file not in ["main.py",'db.py','webserver.py','settings.py'] and file.endswith('.py'):
                await bot.load_extension(f'{file[:-3]}')
        await bot.load_extension("jishaku")
        await bot.start(token)

def bot_task_callback(future: asyncio.Future):
    exc = future.exception()
    if exc is not None:
        raise exc


loop = asyncio.new_event_loop()
bot_task = loop.create_task(bootstrap())
uvicorn_config = Config(app=app, host="127.0.0.1", port=3066,log_config='log.ini',loop=loop)
uvicorn_server = Server(uvicorn_config)
with uvicorn_server.run_in_thread(loop):
    try:
        bot_task = loop.create_task(bootstrap())
        bot_task.add_done_callback(bot_task_callback)
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()