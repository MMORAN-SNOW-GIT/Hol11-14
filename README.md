# Hol11-14


Slack Application Creation: Create a Slack application here.
Alternate Bolt App Initialization: Alternatively, use the following Slack commands to initialize a Bolt application:
slack create first-bolt-app --template slack-samples/bolt-python-getting-started-app
cd first-bolt-app
Manifest File: Utilize this manifest.json for application setup: Manifest File
Main Repository: The primary code repository is available here: Main GitHub Repo
Setup File: The required setup.sql file is located at: Setup SQL
Semantic Model Specification: Review the semantic model spec file: YAML Spec
Data Folder: The necessary data folder is available here: Data Folder
Cortex Search Service SQL: The SQL for the Cortex Search Service is: Cortex SQL
Environment Variable (.ENV) Configuration
Snowsight Details: The following variables require your specific Snowsight account information:
ACCOUNT
HOST
DEMO_USER
Required Tokens and Endpoint: The following tokens and endpoint details are also required:
PAT (Personal Access Token)
AGENT_ENDPOINT (The Snowflake agent endpoint URL)
SLACK_APP_TOKEN
SLACK_BOT_TOKEN
Non-Modifiable Variables: Do not modify the following variables:
WAREHOUSE='dash_agent_wh'
DEMO_USER_ROLE='snowflake_intelligence_admin'
Application Execution Commands
Navigate to Project Directory: Cd “path/sfguide-integrate-snowflake-cortex-agents-with-slack/”
Set Up and Activate Python Virtual Environment:
python3 -m venv .venv
source .venv/bin/activate
Install Required Python Packages: pip install -r requirements.txt
Key Package Dependencies: The required Python packages include:
slack_bolt
snowflake-snowpark-python
requests
pandas
numpy
python-dotenv
Matplotlib
Execute the Application:
Test Run: python3 test.py
Main Application Run: Python3 app.py

