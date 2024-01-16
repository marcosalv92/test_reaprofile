from fastapi.testclient import TestClient
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '../'))
from main import app

client = TestClient(app)

def test_create_user():
    user = {
        "username": "christian2@reaprofile.es",
        "full_name": "christian",
        "password": "Christian2023"
    }
    response = client.post('/user/register', json=user)
    assert response.status_code == 400
    
