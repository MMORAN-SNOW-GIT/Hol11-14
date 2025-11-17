"""
Snowflake Cortex Response Parser

This module provides comprehensive parsing functionality for Snowflake Cortex Agent responses.
It handles both streaming SSE (Server-Sent Events) responses and non-streaming JSON responses.

Based on the REST API documentation:
https://docs.snowflake.com/en/user-guide/snowflake-cortex/cortex-agents-rest-api#id42
"""

import json
import re
from typing import Dict, List, Any, Optional, Union, Iterator
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ToolUse:
    """Represents a tool use in a Cortex response."""
    id: str
    name: str
    type: str
    arguments: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolResult:
    """Represents a tool result in a Cortex response."""
    tool_use_id: str
    content: List[Dict[str, Any]] = field(default_factory=list)
    
    @property
    def sql_query(self) -> Optional[str]:
        """
        Extract SQL query from tool results.
        
        Note: These SQL queries were already executed by Cortex during analysis.
        The results are included in the final text response (response.text.delta).
        This method extracts queries for transparency/logging purposes only.
        """
        for item in self.content:
            if isinstance(item, dict) and 'json' in item:
                if 'sql' in item['json']:
                    return item['json']['sql']
        return None
    
    @property
    def search_results(self) -> List[Dict[str, Any]]:
        """Extract search results from tool results."""
        results = []
        for item in self.content:
            if isinstance(item, dict) and 'json' in item:
                if 'searchResults' in item['json']:
                    results.extend(item['json']['searchResults'])
        return results
    
    @property
    def verification_info(self) -> Dict[str, Any]:
        """Extract verification information from tool results."""
        verification = {}
        for item in self.content:
            if isinstance(item, dict) and 'json' in item:
                json_data = item['json']
                # Check for various verification fields
                if 'verification' in json_data:
                    verification['verification'] = json_data['verification']
                if 'validated' in json_data:
                    verification['validated'] = json_data['validated']
                if 'query_verified' in json_data:
                    verification['query_verified'] = json_data['query_verified']
                if 'verified_query_used' in json_data:
                    verification['verified_query_used'] = json_data['verified_query_used']
                if 'query_validation' in json_data:
                    verification['query_validation'] = json_data['query_validation']
        return verification
    
    @property
    def is_verified_query(self) -> bool:
        """Check if a verified query was used."""
        verification = self.verification_info
        # Check multiple possible boolean fields for verification
        return (
            verification.get('verified_query_used', False) or
            verification.get('query_verified', False) or
            verification.get('validated', False) or
            verification.get('verification', False)
        )


@dataclass
class ParsedMessage:
    """Represents a parsed message from Cortex response."""
    role: str
    content: List[Dict[str, Any]] = field(default_factory=list)
    
    @property
    def text_content(self) -> str:
        """Extract text content from the message."""
        text_parts = []
        for item in self.content:
            if item.get('type') == 'text':
                text_parts.append(item.get('text', ''))
        return ''.join(text_parts)
    
    @property
    def tool_uses(self) -> List[ToolUse]:
        """Extract tool uses from the message."""
        tools = []
        for item in self.content:
            if item.get('type') == 'tool_use':
                tool_data = item.get('tool_use', {})
                tools.append(ToolUse(
                    id=tool_data.get('id', ''),
                    name=tool_data.get('name', ''),
                    type=tool_data.get('type', ''),
                    arguments=tool_data.get('arguments', {})
                ))
        return tools
    
    @property
    def tool_results(self) -> List[ToolResult]:
        """Extract tool results from the message."""
        results = []
        for item in self.content:
            # Handle both old format ('tool_results') and new format ('tool_result')
            if item.get('type') == 'tool_results':
                tool_results_data = item.get('tool_results', {})
                results.append(ToolResult(
                    tool_use_id=tool_results_data.get('tool_use_id', ''),
                    content=tool_results_data.get('content', [])
                ))
            elif item.get('type') == 'tool_result':
                tool_result_data = item.get('tool_result', {})
                results.append(ToolResult(
                    tool_use_id=tool_result_data.get('tool_use_id', ''),
                    content=tool_result_data.get('content', [])
                ))
        return results


@dataclass 
class Suggestion:
    """Represents a suggestion in a Cortex response."""
    text: str


@dataclass
class CortexResponse:
    """Represents a complete parsed Cortex response."""
    messages: List[ParsedMessage] = field(default_factory=list)
    suggestions: List[Suggestion] = field(default_factory=list)
    status_messages: List[str] = field(default_factory=list)  # Add status messages for planning steps
    request_id: Optional[str] = None
    
    @property
    def final_text(self) -> str:
        """Get the final text response from the assistant."""
        for message in reversed(self.messages):
            if message.role == 'assistant':
                return message.text_content
        return ""
    
    @property
    def sql_queries(self) -> List[str]:
        """Extract all SQL queries from tool results."""
        queries = []
        for message in self.messages:
            for tool_result in message.tool_results:
                sql = tool_result.sql_query
                if sql:
                    queries.append(sql)
        return queries
    
    @property
    def search_results(self) -> List[Dict[str, Any]]:
        """Extract all search results from tool results."""
        all_results = []
        for message in self.messages:
            for tool_result in message.tool_results:
                all_results.extend(tool_result.search_results)
        return all_results
    
    @property
    def citations(self) -> List[str]:
        """Extract citations from search results."""
        citations = []
        for result in self.search_results:
            if 'doc_title' in result and 'text' in result:
                citation = f"{result['doc_title']}: {result['text']}"
                if 'doc_id' in result:
                    citation += f" [Source: {result['doc_id']}]"
                citations.append(citation)
        return citations


class CortexResponseParser:
    """Parser for Snowflake Cortex Agent responses."""
    
    def __init__(self, debug: bool = False):
        self.debug = debug
    
    def parse_sse_response(self, sse_lines: List[str]) -> CortexResponse:
        """
        Parse Server-Sent Events (SSE) streaming response.
        
        Args:
            sse_lines: List of SSE lines from the response
            
        Returns:
            CortexResponse object with parsed data
        """
        response = CortexResponse()
        accumulated_content = {'text': '', 'tool_use': [], 'tool_results': []}
        accumulated_thinking = []  # Store thinking content
        current_event = None
        
        for line in sse_lines:
            # Track event types
            if line.startswith('event: '):
                current_event = line[7:].strip()
                continue
            
            # Process data lines based on current event
            if line.startswith('data: '):
                data_content = line[6:].strip()
                
                if data_content == '[DONE]':
                    break
                
                try:
                    json_data = json.loads(data_content)
                    
                    # Handle thinking events
                    if current_event == 'response.thinking.delta' or current_event == 'response.thinking':
                        if 'text' in json_data:
                            thinking_text = json_data['text']
                            # Extract content from <thinking> tags
                            import re
                            thinking_match = re.search(r'<thinking>(.*?)</thinking>', thinking_text, re.DOTALL)
                            if thinking_match:
                                clean_thinking = thinking_match.group(1).strip()
                                if clean_thinking:
                                    accumulated_thinking.append(clean_thinking)
                    
                    # Handle status events (planning steps)
                    elif current_event == 'response.status':
                        if 'message' in json_data:
                            status_msg = json_data['message']
                            response.status_messages.append(status_msg)
                    
                    # Handle response text events (final answer content)
                    elif current_event == 'response.text.delta':
                        if 'text' in json_data:
                            text_content = json_data['text']
                            # Add text content as accumulated content (only from delta events to avoid duplication)
                            accumulated_content['text'] += text_content
                    
                    elif current_event == 'response.text':
                        # Skip complete text events since we're building from deltas
                        # This prevents duplication from both delta and complete events
                        pass
                    
                    # Handle tool result events (contains SQL queries and verification info)
                    elif current_event == 'response.tool_result':
                        if 'content' in json_data and 'tool_use_id' in json_data:
                            tool_result = {
                                'tool_use_id': json_data['tool_use_id'],
                                'content': json_data['content']
                            }
                            accumulated_content['tool_results'].append(tool_result)
                    
                except json.JSONDecodeError:
                    pass
            
            # Also process using original logic for other content (but skip events we already handled)
            # Skip text events that we already processed above to prevent duplication
            parsed_line = self._process_sse_line(line)
            
            if current_event not in ['response.text.delta', 'response.text', 'response.thinking.delta', 'response.thinking', 'response.status']:
                if parsed_line.get('type') == 'message':
                    content = parsed_line['content']
                    accumulated_content['text'] += content.get('text', '')
                    accumulated_content['tool_use'].extend(content.get('tool_use', []))
                    accumulated_content['tool_results'].extend(content.get('tool_results', []))
            
            if parsed_line.get('type') == 'final_message':
                # Skip final message content processing since we're already accumulating from delta events
                # This prevents duplicate content in the final response
                # Note: The final message contains the complete assembled content that we've already 
                # built up from individual response.text.delta events
                pass
            
            elif parsed_line.get('type') == 'done':
                break
        
        # Add thinking content as separate messages FIRST
        for thinking_text in accumulated_thinking:
            if thinking_text.strip():
                response.messages.append(ParsedMessage(
                    role='assistant',
                    content=[{'type': 'thinking', 'text': thinking_text}]
                ))
        
        # Convert accumulated content to message (this should be LAST so final_text picks it up)
        if accumulated_content['text'] or accumulated_content['tool_use'] or accumulated_content['tool_results']:
            message_content = []
            
            if accumulated_content['text']:
                message_content.append({
                    'type': 'text',
                    'text': accumulated_content['text']
                })
            
            for tool_use in accumulated_content['tool_use']:
                message_content.append({
                    'type': 'tool_use',
                    'tool_use': tool_use
                })
            
            for tool_result in accumulated_content['tool_results']:
                message_content.append({
                    'type': 'tool_results',
                    'tool_results': tool_result
                })
            
            response.messages.append(ParsedMessage(
                role='assistant',
                content=message_content
            ))
        
        return response
    
    def parse_json_response(self, json_data: Union[str, Dict[str, Any]]) -> CortexResponse:
        """
        Parse non-streaming JSON response.
        
        Args:
            json_data: JSON string or dictionary
            
        Returns:
            CortexResponse object with parsed data
        """
        if isinstance(json_data, str):
            data = json.loads(json_data)
        else:
            data = json_data
        
        response = CortexResponse()
        response.request_id = data.get('request_id')
        
        # Parse message
        if 'message' in data:
            message_data = data['message']
            response.messages.append(ParsedMessage(
                role=message_data.get('role', 'assistant'),
                content=message_data.get('content', [])
            ))
        
        # Parse suggestions
        if 'suggestions' in data:
            for suggestion_text in data['suggestions']:
                response.suggestions.append(Suggestion(text=suggestion_text))
        
        return response
    
    def parse_file_response(self, file_path: str) -> List[CortexResponse]:
        """
        Parse responses from a file containing multiple sample responses.
        
        Args:
            file_path: Path to the file containing responses
            
        Returns:
            List of CortexResponse objects
        """
        responses = []
        current_response_lines = []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        in_response = False
        for line in lines:
            line = line.strip()
            
            if line.startswith('Sample response'):
                # Start of new response
                if current_response_lines:
                    # Parse previous response
                    response = self.parse_sse_response(current_response_lines)
                    responses.append(response)
                    current_response_lines = []
                in_response = True
                continue
            
            if in_response and line:
                current_response_lines.append(line)
        
        # Parse last response
        if current_response_lines:
            response = self._parse_trace_response(current_response_lines)
            responses.append(response)
        
        return responses
    
    def _parse_trace_response(self, lines: List[str]) -> CortexResponse:
        """
        Parse trace data from sample responses to extract meaningful content.
        
        Args:
            lines: List of lines containing trace data
            
        Returns:
            CortexResponse object with extracted data
        """
        response = CortexResponse()
        
        for line in lines:
            if not line.startswith('data: '):
                continue
                
            try:
                json_str = line[6:].strip()  # Remove 'data: ' prefix
                if json_str.startswith('['):
                    # Parse array of trace JSON objects
                    trace_array = json.loads(json_str)
                    
                    for trace_str in trace_array:
                        trace_data = json.loads(trace_str)
                        self._extract_from_trace(trace_data, response)
            except (json.JSONDecodeError, TypeError):
                continue
        
        return response
    
    def _extract_from_trace(self, trace_data: Dict[str, Any], response: CortexResponse):
        """Extract meaningful information from a single trace object."""
        attributes = trace_data.get('attributes', [])
        
        for attr in attributes:
            key = attr.get('key', '')
            value = attr.get('value', {})
            
            # Extract final response text (main response from agent)
            if key == 'ai.observability.agent.response':
                text = value.get('stringValue', '').strip()
                if text and not any(msg.text_content == text for msg in response.messages):
                    response.messages.append(ParsedMessage(
                        role='assistant',
                        content=[{'type': 'text', 'text': text}]
                    ))
            
            # Extract SQL queries from Cortex Analyst
            elif key == 'ai.observability.agent.tool.cortex_analyst.sql_query':
                sql = value.get('stringValue', '').strip()
                if sql:
                    # Check if we already have this SQL
                    existing_sqls = [tr.sql_query for msg in response.messages for tr in msg.tool_results if tr.sql_query]
                    if sql not in existing_sqls:
                        # Add to existing message or create new one
                        if response.messages:
                            response.messages[-1].content.append({
                                'type': 'tool_results',
                                'tool_results': {
                                    'tool_use_id': 'cortex_analyst',
                                    'content': [{'json': {'sql': sql}}]
                                }
                            })
                        else:
                            response.messages.append(ParsedMessage(
                                role='assistant',
                                content=[{
                                    'type': 'tool_results',
                                    'tool_results': {
                                        'tool_use_id': 'cortex_analyst',
                                        'content': [{'json': {'sql': sql}}]
                                    }
                                }]
                            ))
            
            # Extract search results from Cortex Search
            elif key == 'ai.observability.agent.tool.cortex_search.results':
                search_results = value.get('arrayValue', {}).get('values', [])
                if search_results:
                    for i, result in enumerate(search_results):
                        search_text = result.get('stringValue', '')
                        if search_text:
                            # Create a search result
                            search_result = {
                                'text': search_text[:1000] + '...' if len(search_text) > 1000 else search_text,
                                'doc_title': 'Support Cases',
                                'doc_id': f'search_result_{i+1}'
                            }
                            
                            # Add to existing message or create new one
                            if response.messages:
                                response.messages[-1].content.append({
                                    'type': 'tool_results',
                                    'tool_results': {
                                        'tool_use_id': 'cortex_search',
                                        'content': [{'json': {'searchResults': [search_result]}}]
                                    }
                                })
                            else:
                                response.messages.append(ParsedMessage(
                                    role='assistant',
                                    content=[{
                                        'type': 'tool_results',
                                        'tool_results': {
                                            'tool_use_id': 'cortex_search',
                                            'content': [{'json': {'searchResults': [search_result]}}]
                                        }
                                    }]
                                ))
            
            # Extract request ID
            elif key == 'ai.observability.agent.request_id':
                if not response.request_id:  # Only set if not already set
                    response.request_id = value.get('stringValue', '')
    
    def _process_sse_line(self, line: str) -> Dict[str, Any]:
        """Process a single SSE line and return parsed content."""
        if not line.startswith('data: '):
            return {}
        
        try:
            json_str = line[6:].strip()  # Remove 'data: ' prefix
            if json_str == '[DONE]':
                return {'type': 'done'}
            
            # Handle array of JSON strings (trace data)
            if json_str.startswith('['):
                # This is trace data, not message data
                return {'type': 'trace', 'data': json_str}
            
            data = json.loads(json_str)
            
            # Handle new format: final response with content array
            if 'content' in data and 'role' in data and data.get('role') == 'assistant':
                return {
                    'type': 'final_message',
                    'role': data['role'],
                    'content': data['content']
                }
            
            # Handle old format: message deltas
            if data.get('object') == 'message.delta':
                delta = data.get('delta', {})
                if 'content' in delta:
                    return {
                        'type': 'message',
                        'content': self._parse_delta_content(delta['content'])
                    }
            return {'type': 'other', 'data': data}
        except json.JSONDecodeError:
            return {'type': 'error', 'message': f'Failed to parse: {line}'}
    
    def _parse_delta_content(self, content: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Parse different types of content from the delta."""
        result = {
            'text': '',
            'tool_use': [],
            'tool_results': []
        }
        
        for entry in content:
            entry_type = entry.get('type')
            if entry_type == 'text':
                result['text'] += entry.get('text', '')
            elif entry_type == 'tool_use':
                result['tool_use'].append(entry.get('tool_use', {}))
            elif entry_type == 'tool_results':
                result['tool_results'].append(entry.get('tool_results', {}))
        
        return result
    
    def extract_summary(self, response: CortexResponse) -> Dict[str, Any]:
        """
        Extract a summary of key information from the response.
        
        Args:
            response: Parsed CortexResponse
            
        Returns:
            Dictionary with summary information
        """
        # Collect verification information from all tool results
        verification_info = {}
        verified_query_used = False
        
        # Collect thinking responses from messages
        planning_updates = []
        
        for message in response.messages:
            # Extract thinking content
            for content in message.content:
                if content.get('type') == 'thinking':
                    thinking_text = content.get('text', '').strip()
                    if thinking_text:
                        planning_updates.append(thinking_text)
            
            # Extract verification info from tool results
            for tool_result in message.tool_results:
                tool_verification = tool_result.verification_info
                if tool_verification:
                    verification_info.update(tool_verification)
                if tool_result.is_verified_query:
                    verified_query_used = True
        
        return {
            'text': response.final_text,
            'sql_queries': response.sql_queries,
            'citations': response.citations,
            'suggestions': [s.text for s in response.suggestions],
            'tool_uses': len([tool for msg in response.messages for tool in msg.tool_uses]),
            'search_results_count': len(response.search_results),
            'verification_info': verification_info,
            'verified_query_used': verified_query_used,
            'planning_updates': planning_updates  # Add thinking responses
        }
    
    def debug_print(self, message: str):
        """Print debug message if debug mode is enabled."""
        if self.debug:
            print(f"[DEBUG] {message}")


def main():
    """Example usage of the parser."""
    parser = CortexResponseParser(debug=True)
    
    # Example: Parse responses from sample file
    try:
        responses = parser.parse_file_response('sample_responses')
        
        print(f"Parsed {len(responses)} sample responses:")
        for i, response in enumerate(responses, 1):
            print(f"\n--- Sample Response {i} ---")
            summary = parser.extract_summary(response)
            
            print(f"Text: {summary['text'][:200]}..." if len(summary['text']) > 200 else f"Text: {summary['text']}")
            print(f"SQL Queries: {len(summary['sql_queries'])}")
            print(f"Citations: {len(summary['citations'])}")
            print(f"Tool Uses: {summary['tool_uses']}")
            print(f"Search Results: {summary['search_results_count']}")
            
            if summary['sql_queries']:
                print("SQL Query:")
                print(summary['sql_queries'][0][:300] + "..." if len(summary['sql_queries'][0]) > 300 else summary['sql_queries'][0])
    
    except FileNotFoundError:
        print("Sample responses file not found. Please provide the path to your sample responses file.")
    except Exception as e:
        print(f"Error parsing responses: {e}")


if __name__ == "__main__":
    main()
