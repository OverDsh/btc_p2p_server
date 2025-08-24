import server
import messages

import os
from dotenv import load_dotenv
load_dotenv()

server = server.Server(os.getenv("RemoteIP"), timeout=3600)

@server.on("inv")
def inv(inv_payload):
    getDataMessage = messages.GetData(inv_payload, server.magic)
    server.send(getDataMessage.build_message())



server.connect()