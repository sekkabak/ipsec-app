import asyncio

async def countdown(n, m):  # <- coroutine function
    print("timer start")
    await asyncio.sleep(n)
    print("timer stop")
    await coro1()

async def coro1():
    print("coroutine called")

async def coromain():
    print("first")
    asyncio.ensure_future(countdown(5, 0))  # create a new Task
    print("second")

loop = asyncio.get_event_loop()
loop.run_until_complete(coromain())  # run coromain() from sync code
loop.run_until_complete(asyncio.gather())