from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
uri = "mongodb+srv://reaprofile:reaprofile@cluster0.izlg80j.mongodb.net/?retryWrites=true&w=majority"
# Create a new client and connect to the server
db_client = MongoClient(uri, server_api=ServerApi('1')).reaprofile
# db_client = MongoClient().local
# Send a ping to confirm a successful connection
try:
    db_client.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)