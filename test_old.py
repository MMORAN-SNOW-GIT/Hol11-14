import os
import json
import requests
from dotenv import load_dotenv
import generate_jwt
from generate_jwt import JWTGenerator

# Load environment variables from .env
load_dotenv()

# Instantiate JWT generator and get token
jwt = JWTGenerator(os.getenv("ACCOUNT"),os.getenv("DEMO_USER"),os.getenv("RSA_PRIVATE_KEY_PATH"))
jwt_token = jwt.get_token()

# Build the payload
payload = {
    "model": "claude-3-5-sonnet",
    "messages": [
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": "Can you show me a breakdown of customer support tickets by service type cellular vs business internet?"
                }
            ]
        }
    ],
    "tools": [
        {
            "tool_spec": {
                "type": "cortex_search",
                "name": "vehicles_info_search"
            }
        },
        {
            "tool_spec": {
                "type": "cortex_analyst_text_to_sql",
                "name": "supply_chain"
            }
        }
    ],
    "tool_resources": {
        "vehicles_info_search": {
            "name": os.getenv("SEARCH_SERVICE"),
            "max_results": 1,
            "title_column": "title",
            "id_column": "relative_path"
        },
        "supply_chain": {
            "semantic_model_file": os.getenv("SEMANTIC_MODEL")
        }
    }
}

# Send the POST request
headers = {
    "X-Snowflake-Authorization-Token-Type": "KEYPAIR_JWT",
    "Authorization": f"Bearer {jwt_token}",
    "Content-Type": "application/json",
    "Accept": "application/json"
}

try:
    response = requests.post(
        os.getenv("AGENT_ENDPOINT"),
        headers=headers,
        data=json.dumps(payload)
    )
    response.raise_for_status()
    print("✅ Cortex Agents response:\n\n", response.text)

except requests.exceptions.RequestException as e:
    print("❌ curl error:", str(e))
