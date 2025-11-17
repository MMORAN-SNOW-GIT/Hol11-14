import os
import json
import requests
import pandas as pd
import matplotlib.pyplot as plt
import snowflake.connector
from dotenv import load_dotenv
from cortex_chat import CortexChat

DEBUG = False

# Set up matplotlib for better display
plt.style.use('default')

# Load environment variables from .env
load_dotenv()

# Instantiate JWT generator and get token
pat = os.getenv("PAT")

if DEBUG:
    print(f"Using PAT for authentication: {pat}")

def get_snowflake_connection():
    """Create Snowflake connection for executing queries."""
    try:
        # Debug environment variables
        if DEBUG:
            print(f"   DEMO_USER: {os.getenv('DEMO_USER')}")
            print(f"   HOST: {os.getenv('HOST')}")
            print(f"   WAREHOUSE: {os.getenv('WAREHOUSE')}")
            print(f"   PAT available: {'Yes' if os.getenv('PAT') else 'No'}")

        # Get account from host if not set in ACCOUNT env var
        account = os.getenv("ACCOUNT")
        if not account:
            host = os.getenv("HOST")
            if host:
                # Extract account from host URL
                account = host.split('.')[0]
                print(f"   Extracted account from host: {account}")
        
        print(f"   Attempting PAT authentication...")
        conn = snowflake.connector.connect(
            user=os.getenv("DEMO_USER"),
            password=os.getenv("PAT"),
            account=account,
            warehouse=os.getenv("WAREHOUSE"),
            role=os.getenv("DEMO_USER_ROLE")
        )

        # Test connection
        cursor = conn.cursor()
        cursor.execute("SELECT CURRENT_VERSION()")
        result = cursor.fetchone()
        cursor.close()
        print(f"   ✅ PAT authentication successful! Snowflake version: {result[0]}")
        return conn
            
    except Exception as e:
        print(f"   Failed to connect to Snowflake: {e}")
        return None

questions = [
    "Can you show me a breakdown of customer support tickets by service type cellular vs business internet?",
]

def test_raw_api_response(question, question_num):
    """Test API directly and show raw response format."""
    print(f"\n{'='*70}")
    print(f"RAW API TEST {question_num}: {question}")
    print('='*70)
    
    import requests
    import json
    
    agent_url = os.getenv("AGENT_ENDPOINT")
    
    payload = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": question
                    }
                ]
            }
        ],
        "tool_choice": {
            "type": "auto"
        },
        "stream": True
    }
    
    headers = {
        "X-Snowflake-Authorization-Token-Type": "PROGRAMMATIC_ACCESS_TOKEN",
        "Authorization": f"Bearer {pat}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    print(f"\n🔗 Making request to: {agent_url}")
    print(f"🔑 Headers: {headers}")
    print(f"📋 Payload: {json.dumps(payload, indent=2)}")
    print("\n" + "="*70)
    print("📡 RAW SSE RESPONSE STREAM:")
    print("="*70)
    
    try:
        response = requests.post(
            agent_url,
            headers=headers,
            data=json.dumps(payload),
            timeout=120,
            stream=True
        )
        response.raise_for_status()
        
        line_count = 0
        for line in response.iter_lines():
            line_count += 1
            if line:
                line_decoded = line.decode('utf-8')
                print(f"[{line_count:03d}] {line_decoded}")
                
                # Stop after reasonable number of lines to avoid spam
                if line_count > 200:
                    print("... [truncated for readability] ...")
                    break
        
        print("\n" + "="*70)
        print("✅ RAW RESPONSE COMPLETE")
        print("="*70)
        
    except requests.exceptions.RequestException as e:
        print(f"❌ API Error: {e}")
        if hasattr(e, 'response') and e.response is not None:
            try:
                print(f"Status Code: {e.response.status_code}")
                print(f"Response Headers: {dict(e.response.headers)}")
                print(f"Response Body: {e.response.text}")
            except:
                print("Could not get detailed error info")

def test_question(question, question_num):
    """Test a single question with the Cortex Agent and show raw response with data execution."""
    print(f"\n{'='*70}")
    print(f"QUERY {question_num}: {question}")
    print('='*70)
    
    # Create CortexChat instance with simplified parameters
    cortex_chat = CortexChat(
        agent_url=os.getenv("AGENT_ENDPOINT"),
        pat=pat
    )

    try:
        # Use CortexChat for simplified API interaction
        print("\n🤖 AGENT PLANNING & EXECUTION:")
        print("="*50)
        
        # Get response using CortexChat (includes real-time streaming)
        summary = cortex_chat.chat(question)
        
        # Check for verification information in summary
        print(f"\n🔍 CHECKING FOR VERIFICATION DATA:")
        print("="*50)
        
        # Show what summary contains
        print(f"📊 Summary keys available: {list(summary.keys()) if isinstance(summary, dict) else 'Not a dict'}")
        
        verification_found = False
        if isinstance(summary, dict):
            for key, value in summary.items():
                if 'verif' in key.lower() or 'valid' in key.lower():
                    print(f"🔍 Verification in summary - {key}: {value}")
                    verification_found = True
        
        if not verification_found:
            print("❓ No explicit verification information found in response")
        
        # Display detailed thinking steps from official API response
        if isinstance(summary, dict) and summary.get('planning_updates'):
            print(f"\n🧠 DETAILED THINKING PROCESS FROM CORTEX API:")
            print("="*70)
            planning_steps = summary['planning_updates']
            for i, step in enumerate(planning_steps, 1):
                print(f"   {i:2d}. {step}")
            print(f"\n✅ Thinking completed with {len(planning_steps)} steps")
            print("="*70)
        
        # Display final response
        if isinstance(summary, dict) and summary.get('text'):
            print("\n" + "="*70)
            print("🎯 FINAL API RESPONSE:")
            print("="*70)
            print(summary['text'])
            print("="*70)
        
        # Show extracted SQL queries
        if isinstance(summary, dict) and summary.get('sql_queries'):
            print(f"\n💾 EXTRACTED {len(summary['sql_queries'])} SQL QUERIES:")
            print("="*70)
            
            for i, sql_query in enumerate(summary['sql_queries'], 1):
                print(f"\n📋 Query {i}:")
                print("-" * 40)
                print(sql_query)
                print("-" * 40)
            
            print(f"\n✅ CORTEX EXECUTION COMPLETE")
            print("="*50)
        else:
            print("\n❓ No SQL queries found in response")
        
        return True
        
    except Exception as e:
        print(f"\nError: {e}")
        return False

# Test RAW API Response Format
print("\n🔬 Testing RAW Cortex Agent API Response Format")
print("="*70)

for i, question in enumerate(questions, 1):
    test_raw_api_response(question, i)
    if i < len(questions):
        import time
        time.sleep(2)
    break  # Only test first question for raw analysis

print("\n" + "="*70)

# Test Cortex API with real-time planning display, SQL execution and visualization  
print("\n🚀 Testing Cortex Agent API with real-time planning/thinking display")
print("="*70)

for i, question in enumerate(questions, 1):
    success = test_question(question, i)
    if i < len(questions):
        import time
        time.sleep(2)

print("\nTest completed.")
