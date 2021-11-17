import aiohttp
from sirius_sdk.encryption import P2PConnection

from python.agent_backchannel import DEFAULT_EXTERNAL_HOST


async def http_get(url: str):
    async with aiohttp.ClientSession() as session:
        headers = {
            'content-type': 'application/json'
        }
        try:
            async with session.get(url, headers=headers) as resp:
                if resp.status in [200]:
                    content = await resp.json()
                    return True, content
                else:
                    err_message = await resp.text()
                    return False, err_message
        except aiohttp.ClientError:
            return False, None


async def get_agent_params(agent_name: str):
    ok, meta = await http_get("http://172.17.0.1/test_suite")
    print(meta)
    agent = meta.get(agent_name, None)
    if not agent:
        raise RuntimeError('TestSuite does not have agent with name "%s"' % agent_name)
    p2p = agent['p2p']
    return {
        'server_uri': 'http://172.17.0.1',
        'credentials': agent['credentials'].encode('ascii'),
        'p2p': P2PConnection(
            my_keys=(
                p2p['smart_contract']['verkey'],
                p2p['smart_contract']['secret_key']
            ),
            their_verkey=p2p['agent']['verkey']
        )
    }, list(agent['entities'].items())[0][1]
