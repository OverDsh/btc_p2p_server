import server
from dotenv import load_dotenv
import os
load_dotenv()

server = server.Server(os.getenv("RemoteIP"))
server.connect()