import requests
import json

from cortex_response_parser import CortexResponseParser

DEBUG = False  # Set to True for detailed logging

class CortexChat:
    def __init__(self, 
            agent_url: str, 
            pat: str,
            slack_say_function=None,
            slack_app=None
        ):
        self.agent_url = agent_url
        self.pat = pat
        self.parser = CortexResponseParser(debug=DEBUG)
        self.slack_say = slack_say_function  # For real-time Slack updates
        self.slack_app = slack_app  # For updating messages

    def _retrieve_response(self, query: str, limit=1) -> dict[str, any]:
        """Enhanced response retrieval with real-time streaming and planning display."""

        payload = {
            "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": query
                    }
                ]
            }
            ],
            "tool_choice": {
                "type": "auto"
            },
            "stream": True  # Enable streaming as expected by the API
        }

        headers = {
            "X-Snowflake-Authorization-Token-Type": "PROGRAMMATIC_ACCESS_TOKEN",
            "Authorization": f"Bearer {self.pat}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        # Debug: Print the request details
        if DEBUG:
            print(f"🔍 Making request to: {self.agent_url}")
            print(f"🔍 Headers: {headers}")
            print(f"🔍 Payload: {json.dumps(payload, indent=2)}")

        try:
            # Make streaming request
            response = requests.post(
                self.agent_url,
                headers=headers,
                data=json.dumps(payload),
                timeout=120,
                stream=True
            )
            response.raise_for_status()
            
            # Send initial planning status to Slack with collapsible button interface
            self.planning_message_ts = None
            self.planning_channel = getattr(self.slack_app, '_channel_id', None) if self.slack_app else None
            planning_expanded = False  # Track whether details are shown
            if self.slack_say:
                result = self.slack_say(
                    text="🤔 Thinking...",
                    blocks=[
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": "*🤔 Thinking...*"
                            }
                        }
                    ]
                )
                # Store message timestamp for updates if available
                if hasattr(result, 'get') and result.get('ts'):
                    self.planning_message_ts = result['ts']
            
            # Collect streaming response with real-time display
            response_lines = []
            tools_used = []
            current_thinking = ""
            planning_updates = []
            thinking_updates = []  # Track thinking content for Slack updates
            timeline = []  # Chronological timeline of status and thinking events
            
            if DEBUG:
                print("\n🤖 AGENT PLANNING & EXECUTION:")
                print("="*50)

            line_count = 0
            current_event = None
            for line in response.iter_lines():
                line_count += 1
                if line:
                    line_decoded = line.decode('utf-8')
                    response_lines.append(line_decoded)
                    
                    # Check for event type first
                    if line_decoded.startswith('event: '):
                        current_event = line_decoded[7:].strip()
                        continue
                        
                    if line_decoded.startswith('data: '):
                        data_content = line_decoded[6:].strip()
                        
                        if data_content == '[DONE]':
                            if DEBUG:
                                print("\n✅ AGENT PROCESSING COMPLETE")
                            break
                        elif not data_content.startswith('['):
                            try:
                                json_data = json.loads(data_content)
                                
                                # Handle status events (planning steps)
                                if current_event == 'response.status':
                                    if 'message' in json_data:
                                        status_msg = json_data['message']
                                        print(f"🔹 STATUS: {status_msg}")
                                        
                                        # Add all planning steps to the details (now that header is "Thinking")
                                        planning_updates.append(status_msg)
                                        timeline.append({'type': 'status', 'content': status_msg})
                                        
                                        # Update Slack in real-time for planning steps (keep collapsed by default)
                                        if self.slack_app and self.planning_message_ts and self.planning_channel:
                                            try:
                                                step_count = len(planning_updates)
                                                latest_step = planning_updates[-1] if planning_updates else "Processing..."
                                                
                                                # Show summary with step count and latest step (no button while thinking)
                                                summary_text = f"*🤔 Thinking...*\n\n_Latest: {latest_step}_"
                                                
                                                blocks = [
                                                    {
                                                        "type": "section",
                                                        "text": {
                                                            "type": "mrkdwn",
                                                            "text": summary_text
                                                        }
                                                    }
                                                ]
                                                
                                                self.slack_app.client.chat_update(
                                                    channel=self.planning_channel,
                                                    ts=self.planning_message_ts,
                                                    blocks=blocks
                                                )
                                                print(f"⚡ Updated planning: {step_count} steps")
                                            except Exception as e:
                                                print(f"❌ Error updating planning message: {e}")
                                                if DEBUG:
                                                    import traceback
                                                    print(f"❌ Full error: {traceback.format_exc()}")
                                    continue
                                
                                # Handle thinking events (real-time thinking content)
                                elif current_event == 'response.thinking.delta':
                                    if 'text' in json_data:
                                        thinking_text = json_data['text']
                                        # Extract content from <thinking> tags and print without tags
                                        import re
                                        thinking_match = re.search(r'<thinking>(.*?)</thinking>', thinking_text, re.DOTALL)
                                        if thinking_match:
                                            clean_thinking = thinking_match.group(1).strip()
                                            if clean_thinking:
                                                print(f"THINKING COMPLETE: {clean_thinking}")
                                                # Replace the last thinking update with complete version
                                                if thinking_updates:
                                                    thinking_updates[-1] = clean_thinking
                                                    # Update timeline entry if it exists
                                                    for i in range(len(timeline) - 1, -1, -1):
                                                        if timeline[i]['type'] == 'thinking':
                                                            timeline[i]['content'] = clean_thinking.strip()
                                                            break
                                                else:
                                                    thinking_updates.append(clean_thinking)
                                                    timeline.append({'type': 'thinking', 'content': clean_thinking.strip()})
                                                self._update_slack_with_thinking(planning_updates, thinking_updates)
                                        else:
                                            # Handle streaming text fragments (preserve spacing from API)
                                            clean_text = thinking_text.replace('<thinking>', '').replace('</thinking>', '')
                                            if clean_text:
                                                # Check content_index to handle multiple thinking streams
                                                content_index = json_data.get('content_index', 0)
                                                
                                                # Ensure we have enough thinking slots
                                                while len(thinking_updates) <= content_index:
                                                    thinking_updates.append("")
                                                
                                                # For streaming, print text directly
                                                if not thinking_updates[content_index]:
                                                    print(f"\nTHINKING: {clean_text}", end='', flush=True)
                                                    # Add new thinking entry to timeline (strip leading/trailing whitespace)
                                                    timeline.append({'type': 'thinking', 'content': clean_text.strip(), 'content_index': content_index})
                                                else:
                                                    print(f"{clean_text}", end='', flush=True)
                                                
                                                # Accumulate text exactly as provided by the API (spacing is correct)
                                                thinking_updates[content_index] += clean_text
                                                
                                                # Update the timeline entry for this content_index
                                                for i in range(len(timeline) - 1, -1, -1):
                                                    if (timeline[i]['type'] == 'thinking' and 
                                                        timeline[i].get('content_index') == content_index):
                                                        timeline[i]['content'] = thinking_updates[content_index].strip()
                                                        break
                                                
                                                self._update_slack_with_thinking(planning_updates, thinking_updates)
                                    continue
                                
                                elif current_event == 'response.thinking':
                                    if 'text' in json_data:
                                        thinking_text = json_data['text']
                                        # Extract content from <thinking> tags
                                        import re
                                        thinking_match = re.search(r'<thinking>(.*?)</thinking>', thinking_text, re.DOTALL)
                                        if thinking_match:
                                            clean_thinking = thinking_match.group(1).strip()
                                            if clean_thinking:
                                                print(f"\n\nTHINKING COMPLETE: {clean_thinking}")
                                                print("=" * 50)
                                                # Use content_index to place in correct slot
                                                content_index = json_data.get('content_index', 0)
                                                
                                                # Ensure we have enough thinking slots
                                                while len(thinking_updates) <= content_index:
                                                    thinking_updates.append("")
                                                
                                                # Replace the content at the correct index
                                                thinking_updates[content_index] = clean_thinking
                                                
                                                # Update or add to timeline
                                                timeline_updated = False
                                                for i in range(len(timeline) - 1, -1, -1):
                                                    if (timeline[i]['type'] == 'thinking' and 
                                                        timeline[i].get('content_index') == content_index):
                                                        timeline[i]['content'] = clean_thinking.strip()
                                                        timeline_updated = True
                                                        break
                                                
                                                if not timeline_updated:
                                                    timeline.append({'type': 'thinking', 'content': clean_thinking.strip(), 'content_index': content_index})
                                                
                                                self._update_slack_with_thinking(planning_updates, thinking_updates)
                                    continue
                                
                                # Handle final response event (new format)
                                if current_event == 'response':
                                    print(f"🎯 FINAL RESPONSE EVENT: Found final response data")
                                    continue
                                
                                # Handle message deltas (streaming content)
                                if json_data.get('object') == 'message.delta':
                                    delta = json_data.get('delta', {})
                                    
                                    # Display thinking/planning text as it streams
                                    # Note: response.text.delta contains the final answer delta with SQL results already included
                                    if 'content' in delta:
                                        for content_item in delta['content']:
                                            if content_item.get('type') == 'text':
                                                text_delta = content_item.get('text', '')
                                                if text_delta:
                                                    current_thinking += text_delta
                                                    # Only show first part as thinking
                                                    if len(current_thinking) < 200:
                                                        if DEBUG:
                                                            print(f"🧠 {text_delta}", end='', flush=True)
                                            
                                            elif content_item.get('type') == 'tool_use':
                                                tool_data = content_item.get('tool_use', {})
                                                tool_name = tool_data.get('name', 'unknown')
                                                if tool_name not in tools_used:
                                                    tools_used.append(tool_name)
                                                    if DEBUG:
                                                        print(f"\n🔧 USING TOOL: {tool_name}")
                                                    planning_updates.append(f"Using {tool_name}")
                                                    timeline.append({'type': 'status', 'content': f"Using {tool_name}"})
                                                    
                                                    # Show tool parameters if available
                                                    if 'input' in tool_data:
                                                        tool_input = tool_data['input']
                                                        if isinstance(tool_input, dict):
                                                            for key, value in tool_input.items():
                                                                if isinstance(value, str) and len(value) < 100:
                                                                    if DEBUG:
                                                                        print(f"   📝 {key}: {value}")
                                            
                                            elif content_item.get('type') == 'tool_result':
                                                if DEBUG:
                                                    print(f"✅ Tool execution completed")
                                                
                                                # Check for verification information in tool result
                                                tool_result = content_item.get('tool_result', {})
                                                if tool_result:
                                                    # Check for verification fields (debug only)
                                                    if DEBUG and 'verification' in tool_result:
                                                        print(f"   🔍 Verification: {tool_result['verification']}")
                                                    if DEBUG and 'validated' in tool_result:
                                                        print(f"   ✅ Validated: {tool_result['validated']}")
                                                    if DEBUG and 'query_verified' in tool_result:
                                                        print(f"   🎯 Query Verified: {tool_result['query_verified']}")
                                                    if DEBUG and 'verified_query_used' in tool_result:
                                                        print(f"   ✅ Verified Query Used: {tool_result['verified_query_used']}")
                                                    if DEBUG and 'query_validation' in tool_result:
                                                        print(f"   📋 Query Validation: {tool_result['query_validation']}")
                                                    
                                                    # Also check nested JSON content (debug only)
                                                    if DEBUG and isinstance(tool_result, dict) and 'json' in tool_result:
                                                        json_data = tool_result['json']
                                                        if 'verification' in json_data:
                                                            print(f"   🔍 JSON Verification: {json_data['verification']}")
                                                        if 'validated' in json_data:
                                                            print(f"   ✅ JSON Validated: {json_data['validated']}")
                                                        if 'query_verified' in json_data:
                                                            print(f"   🎯 JSON Query Verified: {json_data['query_verified']}")
                                                        if 'verified_query_used' in json_data:
                                                            print(f"   ✅ JSON Verified Query Used: {json_data['verified_query_used']}")
                                
                                # Handle objects without explicit type (status updates, tool metadata)
                                elif json_data.get('object') is None:
                                    if 'status' in json_data:
                                        status = json_data.get('status', '')
                                        status_msg = json_data.get('status_message', '')
                                        if status and status not in ['REASONING_AGENT_STOP']:  # Filter noise
                                            if DEBUG:
                                                print(f"\n🔹 STATUS: {status.replace('_', ' ').title()}")
                                                if status_msg:
                                                    print(f"   📝 {status_msg}")
                                            
                                            # Always append status messages for Slack updates (regardless of DEBUG)
                                            if status_msg:
                                                planning_updates.append(status_msg)
                                                timeline.append({'type': 'status', 'content': status_msg})
                                                
                                                # Update planning message with new steps (keep collapsed by default)
                                                if self.slack_app and self.planning_message_ts and len(planning_updates) % 2 == 0:  # Every 2nd update
                                                    try:
                                                        # Update the existing planning message with current step count
                                                        step_count = len(planning_updates)
                                                        latest_step = planning_updates[-1] if planning_updates else "Processing..."
                                                        
                                                        channel = getattr(self.slack_app, '_channel_id', None)
                                                        if channel:
                                                            self.slack_app.client.chat_update(
                                                                channel=channel,
                                                                ts=self.planning_message_ts,
                                                                text="🤔 Planning the next steps...",
                                                                blocks=[
                                                                    {
                                                                        "type": "section",
                                                                        "text": {
                                                                            "type": "mrkdwn",
                                                                            "text": f"*🤔 Planning the next steps...* ({step_count} steps)\n\n_Latest: {latest_step}_"
                                                                        }
                                                                    },
                                                                    {
                                                                        "type": "actions",
                                                                        "elements": [
                                                                            {
                                                                                "type": "button",
                                                                                "text": {
                                                                                    "type": "plain_text",
                                                                                    "text": "📋 Show Details"
                                                                                },
                                                                                "action_id": "show_planning_details",
                                                                                "value": "show"
                                                                            }
                                                                        ]
                                                                    }
                                                                ]
                                                            )
                                                    except Exception as e:
                                                        if DEBUG:
                                                            print(f"Failed to update planning message: {e}")
                                                        # Fallback to new message
                                                        if self.slack_say:
                                                            latest_updates = planning_updates[-3:]
                                                            update_text = "\n".join(f"• {update}" for update in latest_updates)
                                                            self.slack_say(
                                                                text="🔄 Agent working...",
                                                                blocks=[
                                                                    {
                                                                        "type": "section",
                                                                        "text": {
                                                                            "type": "mrkdwn",
                                                                            "text": f"*🔄 Progress Update:*\n{update_text}"
                                                                        }
                                                                    }
                                                                ]
                                                            )
                                    
                                    # Display tool metadata if present
                                    if 'tool_metadata' in json_data:
                                        tool_meta = json_data['tool_metadata']
                                        if DEBUG:
                                            print(f"\n🔧 TOOL METADATA:")
                                            if isinstance(tool_meta, dict):
                                                for key, value in tool_meta.items():
                                                    print(f"   📋 {key}: {value}")
                                            
                            except json.JSONDecodeError:
                                pass
            
            # Parse response with CortexResponseParser
            has_sse_data = any(line.startswith('data: ') for line in response_lines)
            
            if has_sse_data:
                parsed_response = self.parser.parse_sse_response(response_lines)
            else:
                parsed_response = self.parser.parse_json_response('\n'.join(response_lines))
            
            # Extract summary for business display
            summary = self.parser.extract_summary(parsed_response)
            
            # Display the complete final response
            final_text = summary.get('text', '')
            if final_text:
                print(f"\n\n{'='*80}")
                print("FINAL RESPONSE:")
                print(f"{'='*80}")
                print(final_text)
                print(f"{'='*80}")
            
            # Store data for collapsible planning details
            self.planning_steps = planning_updates
            # Filter out empty thinking content for details display
            self.thinking_steps = [content.strip() for content in thinking_updates if content and content.strip()]
            # Store chronological timeline for proper ordering
            self.timeline = timeline
            self.sql_queries = summary.get('sql_queries', [])
            self.verification_info = summary.get('verification_info', {})
            self.verified_query_used = summary.get('verified_query_used', False)
            
            # Update planning message to show completion (now that summary data is available)
            if planning_updates:
                # Try to update the existing planning message first
                if self.slack_app and self.planning_message_ts:
                    try:
                        step_count = len(planning_updates)
                        
                        # Build summary with additional info using the summary data
                        additional_info = []
                        try:
                            has_verification = summary.get('verification_info') or summary.get('verified_query_used')
                            sql_queries = summary.get('sql_queries', [])
                            
                            if has_verification:                                
                                additional_info.append(":verified: answer accuracy verified by agent owner")
                            elif sql_queries:
                                # Only SQL queries
                                query_count = len(sql_queries)
                                additional_info.append(f"{query_count} SQL {'query' if query_count == 1 else 'queries'}")
                        except:
                            pass
                        
                        summary_text = f"_Finished {step_count} steps"
                        if additional_info:
                            summary_text += f" • Includes {' and '.join(additional_info)}"
                        summary_text += "_"
                        
                        if self.planning_channel:
                            self.slack_app.client.chat_update(
                                channel=self.planning_channel,
                                ts=self.planning_message_ts,
                                text="✅ Thinking completed!",
                                blocks=[
                                    {
                                        "type": "section",
                                        "text": {
                                            "type": "mrkdwn",
                                            "text": f"*🤔 Thinking...* ✅ *Completed!*\n\n{summary_text}"
                                        }
                                    },
                                    {
                                        "type": "actions",
                                        "elements": [
                                            {
                                                "type": "button",
                                                "text": {
                                                    "type": "plain_text",
                                                    "text": "📋 Show Details"
                                                },
                                                "action_id": "show_planning_details",
                                                "value": "show"
                                            }
                                        ]
                                    }
                                ]
                            )
                            print(f"✅ Updated completion message with summary info")
                        else:
                            raise Exception("No channel available")
                    except Exception as e:
                        if DEBUG:
                            print(f"Failed to update completion message: {e}")
                        # Fallback to new message
                        if self.slack_say:
                            all_updates = "\n".join(f"• {update}" for update in planning_updates)
                            self.slack_say(
                                text="✅ Thinking completed!",
                                blocks=[
                                    {
                                        "type": "section",
                                        "text": {
                                            "type": "mrkdwn",
                                            "text": f"*🤔 Thinking...* ✅ *Completed!*\n\n{all_updates}"
                                        }
                                    }
                                ]
                            )
                # Fallback to new message if no app available
                elif self.slack_say:
                    all_updates = "\n".join(f"• {update}" for update in planning_updates)
                    self.slack_say(
                        text="✅ Thinking completed!",
                        blocks=[
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": f"*🤔 Thinking...* ✅ *Completed!*\n\nFinished {len(planning_updates)} steps"
                                }
                            }
                        ]
                    )
            
            # Log verification information (debug only)
            if DEBUG and (summary.get('verification_info') or summary.get('verified_query_used')):
                print(f"\n🔍 VERIFICATION SUMMARY:")
                print(f"   🔹 Verified Query Used: {'✅ YES' if summary.get('verified_query_used') else '❌ NO'}")
                
                verification_info = summary.get('verification_info', {})
                if verification_info:
                    print(f"   📋 Verification Details:")
                    for key, value in verification_info.items():
                        print(f"      • {key}: {value}")
                else:
                    print(f"   📋 No detailed verification info available")
            elif DEBUG:
                print(f"\n🔍 VERIFICATION SUMMARY: No verification information found")
            
            return summary
            
        except requests.exceptions.Timeout:
            print(f"🔍 Timeout error caught")
            return self._handle_error("Request took longer than 120 seconds", "Request timeout")
        except requests.exceptions.RequestException as e:
            print(f"🔍 RequestException error caught: {e}")
            # Get more detailed error information
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_details = e.response.text
                    print(f"🔍 Response status code: {e.response.status_code}")
                    print(f"🔍 Response headers: {dict(e.response.headers)}")
                    print(f"🔍 Response body: {error_details}")
                except:
                    print(f"🔍 Could not get response details")
            return self._handle_error(f"Request error: {e}", "Request failed")
        except Exception as e:
            print(f"🔍 General exception caught: {type(e).__name__}: {e}")
            return self._handle_error(f"Unexpected error: {e}", "Unexpected error")

    def _handle_error(self, error_msg: str, slack_title: str) -> dict:
        """Helper method to handle errors consistently."""
        if DEBUG:
            print(f"\n{error_msg}")
        if self.slack_say:
            self.slack_say(
                text=f"❌ {slack_title}",
                blocks=[{
                    "type": "section",
                    "text": {"type": "plain_text", "text": f"❌ {error_msg}"}
                }]
            )
        return {"text": f"Error: {error_msg}", "sql_queries": [], "citations": []}

    def set_slack_say_function(self, slack_say_function):
        """Set the Slack say function for real-time updates."""
        self.slack_say = slack_say_function
    
    def set_slack_app(self, slack_app, channel_id=None):
        """Set the Slack app and channel for message updates."""
        self.slack_app = slack_app
        if channel_id:
            # Handle both channel ID string and channel object
            if isinstance(channel_id, dict):
                channel_id = channel_id.get('id', channel_id)
            setattr(slack_app, '_channel_id', channel_id)
    
    def _smart_truncate(self, text, max_length=200, suffix="..."):
        """Smart truncation that preserves word and sentence boundaries."""
        if len(text) <= max_length:
            return text
        
        # Try sentence boundary first
        sentences = text.split('. ')
        if len(sentences) > 1:
            result = ""
            for sentence in sentences:
                test = result + sentence + ". "
                if len(test) + len(suffix) <= max_length:
                    result = test
                else:
                    break
            if result.strip():
                return result.strip() + suffix
        
        # Try word boundary
        words = text.split()
        result = ""
        for word in words:
            test = result + word + " "
            if len(test) + len(suffix) <= max_length:
                result = test
            else:
                break
        
        return result.strip() + suffix if result.strip() else text[:max_length-len(suffix)] + suffix

    def _update_slack_with_thinking(self, planning_updates, thinking_updates):
        """Update Slack with combined planning and thinking updates in real-time."""
        if not (self.slack_app and self.planning_message_ts and self.planning_channel):
            return
            
        try:
            # Build appended status list (show recent status updates)
            status_lines = []
            
            # Show last 8 status updates to keep it manageable
            recent_statuses = planning_updates[-8:] if planning_updates else []
            for status in recent_statuses:
                status_lines.append(f"• {status}")
            
            # Add thinking content from all content indices
            if thinking_updates:
                # Combine all non-empty thinking content
                all_thinking = []
                for thinking_content in thinking_updates:
                    if thinking_content and thinking_content.strip():
                        all_thinking.append(thinking_content.strip())
                
                if all_thinking:
                    # Use the most recent thinking content
                    latest_thinking = all_thinking[-1]
                    # Truncate thinking for real-time display to keep message manageable
                    if len(latest_thinking) > 300:
                        truncated_thinking = self._smart_truncate(latest_thinking, max_length=300)
                        thinking_line = f"• {truncated_thinking}"
                    else:
                        thinking_line = f"• {latest_thinking}"
                    status_lines.append(thinking_line)
            
            # Create the status progression text
            if status_lines:
                progress_text = "\n".join(status_lines)
                summary_text = f"*🤔 Thinking...*\n\n{progress_text}"
                
                # Ensure we don't exceed Slack message limits (3000 chars is Slack's limit)
                if len(summary_text) > 2900:
                    # If too long, show fewer status updates
                    recent_statuses = planning_updates[-4:] if planning_updates else []
                    status_lines = [f"• {status}" for status in recent_statuses]
                    
                    # Add thinking if available
                    if thinking_updates:
                        latest_thinking = thinking_updates[-1]
                        truncated_thinking = self._smart_truncate(latest_thinking, max_length=200)
                        status_lines.append(f"• {truncated_thinking}")
                    
                    progress_text = "\n".join(status_lines)
                    summary_text = f"*🤔 Thinking...*\n\n{progress_text}"
            else:
                summary_text = "*🤔 Thinking...* Processing..."
            
            blocks = [
                {
                    "type": "section", 
                    "text": {
                        "type": "mrkdwn",
                        "text": summary_text
                    }
                }
            ]
            
            self.slack_app.client.chat_update(
                channel=self.planning_channel,
                ts=self.planning_message_ts,
                blocks=blocks
            )
            
        except Exception as e:
            print(f"❌ Error updating Slack with thinking: {e}")
        if DEBUG:
                import traceback
                print(f"❌ Full error: {traceback.format_exc()}")

    def chat(self, query: str) -> dict[str, any]:
        """
        Enhanced chat method with real-time streaming and planning display.
        Returns: dict with keys: 'text', 'sql_queries', 'citations', 'suggestions', etc.
        """
        result = self._retrieve_response(query)
        return result
