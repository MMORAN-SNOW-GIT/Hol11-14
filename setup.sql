-- Run the following statements to create a database, schema, and a table with data loaded from AWS S3.

use role accountadmin;

create role if not exists snowflake_intelligence_admin;
grant create database on account to role snowflake_intelligence_admin;
grant create warehouse on account to role snowflake_intelligence_admin;

set current_user = (SELECT CURRENT_USER());   
grant role snowflake_intelligence_admin to user IDENTIFIER($current_user);
alter user set default_role = snowflake_intelligence_admin;

use role snowflake_intelligence_admin;

create database if not exists snowflake_intelligence;
grant all privileges on database snowflake_intelligence to role snowflake_intelligence_admin;

create warehouse if not exists dash_agent_wh warehouse_size=large auto_suspend=300 auto_resume=true initially_suspended=false;
use warehouse dash_agent_wh;

CREATE SCHEMA IF NOT EXISTS snowflake_intelligence.agents;
grant create agent on schema snowflake_intelligence.agents to role snowflake_intelligence_admin;

create database if not exists dash_agent_slack;

create schema if not exists dash_agent_slack.data;

use database dash_agent_slack;
use schema data;

create or replace file format csvformat  
  skip_header = 1  
  field_optionally_enclosed_by = '"'  
  type = 'csv';  
  
create or replace stage support_tickets_data_stage  
  file_format = csvformat  
  url = 's3://sfquickstarts/sfguide_integrate_snowflake_cortex_agents_with_slack/';  
  
create or replace table support_tickets (  
  ticket_id varchar(60),  
  customer_name varchar(60),  
  customer_email varchar(60),  
  service_type varchar(60),  
  request varchar,  
  contact_preference varchar(60)  
);  
  
copy into support_tickets  
  from @support_tickets_data_stage;

-- run the following statement to create a snowflake managed internal stage to store the semantic model specification file.
create or replace stage semantic_models encryption = (type = 'snowflake_sse') directory = ( enable = true );

-- run the following statement to create a snowflake managed internal stage to store the pdf documents.
create or replace stage pdfs encryption = (type = 'snowflake_sse') directory = ( enable = true );

alter account set cortex_enabled_cross_region = 'AWS_US';
CREATE AUTHENTICATION POLICY IF NOT EXISTS pat_authentication_policy2
  pat_policy=(
    network_policy_evaluation = ENFORCED_NOT_REQUIRED
);
-- run this if policy not working:alter user IDENTIFIER($current_user) set authentication policy pat_authentication_policy2;


select 'Congratulations! Setup has completed successfully!' as status;
