use role snowflake_intelligence_admin;

use dash_agent_slack.data;
use warehouse dash_agent_wh;

create or replace table parse_pdfs as 
select relative_path, snowflake.cortex.parse_document(@dash_agent_slack.data.pdfs,relative_path,{'mode':'layout'}) as data
    from directory(@dash_agent_slack.data.pdfs);

create or replace table parsed_pdfs as (
    with tmp_parsed as (select
        relative_path,
        snowflake.cortex.split_text_recursive_character(to_variant(data):content, 'markdown', 1800, 300) as chunks
    from parse_pdfs where to_variant(data):content is not null)
    select
        to_varchar(c.value) as page_content,
        regexp_replace(relative_path, '\\.pdf$', '') as title,
        'dash_agent_slack.data.pdfs' as input_stage,
        relative_path as relative_path
    from tmp_parsed p, lateral flatten(input => p.chunks) c
);

create or replace cortex search service dash_agent_slack.data.vehicles_info
on page_content
warehouse = dash_agent_wh
target_lag = '1 hour'
as (
    select '' as page_url, page_content, title, relative_path
    from parsed_pdfs
);

select 'Congratulations! Cortex Search Service has been created successfully!' as status;
