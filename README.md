<div align="center">
  <a href="https://fctr.io">
    <img src="https://fctr.io/images/logo.svg" alt="fctr.io" width="110" height="auto">
  </a>
</div>

<div align="center">
  <h2>Okta MCP Server (v0.2.0-ALPHA)</h2>
</div>

The Okta MCP Server is a groundbreaking tool that enables AI models to interact directly with your Okta environment using the Model Context Protocol (MCP). Built specifically for IAM engineers, security teams, and Okta administrators, it implements the MCP specification to transform how AI assistants can help manage and analyze Okta resources.

<div style="align: center" >
<p ><a href="https://github.com/fctr-id/okta-mcp-server">View on GitHub</a> | <a href="https://modelcontextprotocol.io/introduction">Learn about MCP</a> | <a href="https://github.com/fctr-id/okta-ai-agent">Okta AI Agent</a></p>
</div>

<div >
<h3>Quick Demo</h3>
</div>
<p >
  <img src="images/mcp-server.gif" alt="Okta MCP Server Demo" width="1024px" height="auto">
</p>

## 📋 Table of Contents

- [📋 Table of Contents](#-table-of-contents)
- [🔍 What is the Model Context Protocol?](#-what-is-the-model-context-protocol)
- [⚠️ IMPORTANT: Security \& Limitations](#️-important-security--limitations)
  - [🔄 Data Flow \& Privacy](#-data-flow--privacy)
  - [📊 Context Window Limitations](#-context-window-limitations)
  - [🚨 SSE Transport Security Warning](#-sse-transport-security-warning)
- [🛠️ Available Tools](#️-available-tools)
- [�️ Available Tools](#️-available-tools-1)
- [🚀 Quick Start](#-quick-start)
  - [Prerequisites](#prerequisites)
- [🧠 Supported AI Providers](#-supported-ai-providers)
  - [Currently Supported Providers:](#currently-supported-providers)
  - [Installation](#installation)
  - [Configuration \& Usage](#configuration--usage)
  - [Supported Transports and Launching](#supported-transports-and-launching)
    - [1. Standard I/O (STDIO) - Recommended](#1-standard-io-stdio---recommended)
    - [2. Server-Sent Events (SSE) - Advanced Use Only](#2-server-sent-events-sse---advanced-use-only)
- [⚠️ Good to Know](#️-good-to-know)
  - [Alpha Release 🧪](#alpha-release-)
  - [Security First 🛡️](#security-first-️)
  - [Current Limitations 🔍](#current-limitations-)
- [🗺️ Roadmap](#️-roadmap)
- [🆘 Need Help?](#-need-help)
- [💡 Feature Requests \& Ideas](#-feature-requests--ideas)
- [👥 Contributors](#-contributors)
- [⚖️ Legal Stuff](#️-legal-stuff)

&nbsp;

## 🔍 What is the Model Context Protocol?

<div align="left">
<p>The Model Context Protocol (MCP) is an open standard that enables AI models to interact with external tools and services in a structured, secure way. It provides a consistent interface for AI systems to discover and use capabilities exposed by servers, allowing AI assistants to extend their functionality beyond their training data.</p>

<p>Think of MCP as the "USB-C of AI integration" - just as USB-C provides a universal standard that allows various devices to connect and communicate regardless of manufacturer, MCP creates a standardized way for AI models to discover and interact with different services without custom integration for each one. This "plug-and-play" approach means developers can build tools once and have them work across multiple AI assistants, while users benefit from seamless integration without worrying about compatibility issues.</p>

<p><strong>Example:</strong> "Find all locked users in our Okta tenant, and create a spreadsheet in our IT Operations folder on Google Drive with their names, email addresses, and last login dates." <em>The AI uses Okta MCP Server to query locked users, then passes this data to Google Drive MCP Server to create the spreadsheet - all without custom coding.</em></p>

<div align="left">
      <a href="https://modelcontextprotocol.io/introduction">
         <img src="images/MCP-Example.png" style="width:700px">
      </a>
</div>
</div>

## ⚠️ IMPORTANT: Security & Limitations

Please read this section carefully before using Okta MCP Server.

### 🔄 Data Flow & Privacy

When you make a request, the interaction happens directly between the LLM and the Okta MCP tools - the client application is no longer in the middle. All data returned by these tools (including complete user profiles, group memberships, etc.) is sent to and stored in the LLM's context during the entire transaction for that conversation.

**Key Privacy Considerations:**
- The LLM (Claude, GPT, etc.) receives and processes all Okta data retrieved by the tools
- This data remains in the LLM's context for the duration of the conversation
- You must be comfortable with your Okta user data being processed by the LLM provider's systems
- Before using these tools, ensure you're comfortable with Okta data being sent to the AI model's servers

### 📊 Context Window Limitations

MCP is designed for lightweight workflows similar to Zapier, not bulk data operations.

**Recommendation:** Limit requests to fewer than 100 entities per transaction. Avoid operations that require fetching large datasets or multiple API calls.

**Examples:**

❌ **Avoid these types of requests:**
- "Fetch all 10,000 users from our Okta tenant and analyze their login patterns"
- "Find users who do not have Okta Verify enrolled as a factor"

✅ **Better approaches:**
- "Get the most recently created 20 users" 
- "Find users who haven't logged in for 90+ days, limit to first 50 results"

> 💡 **For larger data sets and complex queries:** Consider using the [Okta AI Agent](https://github.com/fctr-id/okta-ai-agent) for larger queries and data sets, The agent  is being enhanced with similar "actionable" features to handle larger datasets and more complex scenarios in the very near future.

### 🚨 SSE Transport Security Warning

The SSE over HTTP transport mode has significant security risks:
- It opens an unauthenticated HTTP server with full access to your Okta tenant
- No authentication or authorization is provided
- Anyone who can reach the network port can issue commands to your Okta environment

**Best Practice:** Only use the STDIO transport method (default mode) unless you have specific security controls in place.

## 🛠️ Available Tools

The Okta MCP Server currently provides the following tools:

## 🛠️ Available Tools

The Okta MCP Server currently provides the following tools:

**User Management**
- `list_okta_users` - Retrieve users with filtering, search, and pagination options
- `get_okta_user` - Get detailed information about a specific user by ID or login
- `list_okta_user_groups` - List all groups that a specific user belongs to
- `list_okta_user_applications` - List all application links (assigned applications) for a specific user
- `list_okta_user_factors` - List all authentication factors enrolled for a specific user

**Group Operations**
- `list_okta_groups` - Retrieve groups with filtering, search, and pagination options
- `get_okta_group` - Get detailed information about a specific group
- `list_okta_group_members` - List all members of a specific group
- `list_okta_assigned_applications_for_group` - List all applications assigned to a specific group

**Application Management**
- `list_okta_applications` - Retrieve applications with filtering, search, and pagination options
- `list_okta_application_users` - List all users assigned to a specific application
- `list_okta_application_group_assignments` - List all groups assigned to a specific application

**Policy & Network Management**
- `list_okta_policy_rules` - List all rules for a specific policy with detailed conditions and actions
- `get_okta_policy_rule` - Get detailed information about a specific policy rule
- `list_okta_network_zones` - List all network zones with IP ranges and configuration details

**System Log Events**
- `get_okta_event_logs` - Retrieve Okta system log events with time-based filtering and search options

**Date & Time Utilities**
- `get_current_time` - Get current UTC time in ISO 8601 format
- `parse_relative_time` - Convert natural language time expressions to ISO 8601 format


> Additional tools for applications, factors, policies, and more advanced operations are on the roadmap and will be added in future releases.

## 🚀 Quick Start

### Prerequisites

✅ Python 3.8+ installed on your machine  
✅ Okta tenant with appropriate API access  
✅ An MCP-compatible AI client (Claude Desktop, Microsoft Copilot Studio, etc.)  

> **⚠️ Important Model Compatibility Note:**  
> Not all AI models work with this MCP server. Testing has only been performed with:
> - GPT-4.0
> - Claude 3.7 Sonnet
>
> You must use latest model versions that explicitly support tool calling/function calling capabilities. Older models or models without tool calling support will not be able to interact with the Okta MCP Server.

## 🧠 Supported AI Providers

The Okta MCP Server supports multiple AI providers through its flexible configuration system. This allows you to connect to various large language models based on your specific needs and existing access.

### Currently Supported Providers:

| Provider | Environment Variable | Description |
|----------|---------------------|-------------|
| **OpenAI** | `AI_PROVIDER=openai` | Connect to OpenAI API with models like GPT-4o. Requires an OpenAI API key. |
| **Azure OpenAI** | `AI_PROVIDER=azure_openai` | Use Azure-hosted OpenAI models with enhanced security and compliance features. |
| **Anthropic** | `AI_PROVIDER=anthropic` | Connect to Anthropic's Claude models (primarily tested with Claude 3.7 Sonnet). |
| **Google Vertex AI** | `AI_PROVIDER=vertex_ai` | Use Google's Gemini models via Vertex AI. Requires Google Cloud service account. |
| **OpenAI Compatible** | `AI_PROVIDER=openai_compatible` | Connect to any OpenAI API-compatible endpoint, such as Fireworks.ai, Ollama, or other providers that implement the OpenAI API specification. |

### Installation

```bash
# Clone the repository
git clone https://github.com/fctr-id/okta-mcp-server.git
cd okta-mcp-server

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration & Usage

Create a config file with your Okta settings:

To use the command line client (no memory), use the instructions below

```bash
# Copy the sample config
cp .env.sample .env

# Edit the env with your settings
# Required: Okta domain and API token and LLM settings

cd clients
python mcp-cli-stdio-client.py
```

To use MCP hosts like Claude Code, vsCode ...etc find the json config below


### Supported Transports and Launching

The Okta MCP Server supports two transport protocols:

#### 1. Standard I/O (STDIO) - Recommended

- **Security**: Direct communication through standard input/output streams
- **Use case**: Ideal for desktop AI assistants like Claude Desktop
- **Configuration**: For Claude Desktop, add to `claude_desktop_config.json`:
  ```json
  {
    "mcpServers": {
      "okta-mcp-server": {
        "command": "DIR/okta-mcp-server/venv/Scripts/python",
        "args": [
          "DIR/okta-mcp-server/main.py"
        ],
        "env": {
          "OKTA_CLIENT_ORGURL": "https://dev-1606.okta.com",
          "OKTA_API_TOKEN": "OKTA_API_TOKEN"
        }
      }
    }
  }
  ```
  *Replace `DIR` with your absolute directory path and `OKTA_API_TOKEN` with your actual token*

#### 2. Server-Sent Events (SSE) - Advanced Use Only

```bash
# Run in SSE mode (requires explicit risk acknowledgment)
python main.py --sse --iunderstandtherisks
```

⚠️ **WARNING**: SSE transport exposes your server via a web endpoint accessible to anyone who can reach your network. Use only in secure environments with proper network protections.

- **For other MCP clients**: Configure according to their documentation for either STDIO or SSE transport.

## ⚠️ Good to Know

### Alpha Release 🧪
* Early development phase - expect frequent updates
* API surface coverage is still expanding
* Currently focusing on read-only operations for users and groups
* More tools and capabilities being added rapidly
* Not yet suitable for production environments

### Security First 🛡️
* Designed for least-privilege operation
* Default read-only access to Okta resources
* Future write operations will require explicit approval flows

### Current Limitations 🔍
* Starting with a limited set of read-only tools for users and groups
* Planning to expand API coverage rapidly in upcoming releases
* Some complex Okta relationships not yet exposed
* Performance with very large Okta instances not yet optimized
* Requires direct network access to Okta API endpoints

## 🗺️ Roadmap

Current progress:
- [x] MCP protocol compliance
- [x] Basic Okta API integration
- [x] Read-only operations support

Future plans include:
- [ ] Comprehensive documentation
- [ ] Complete user lifecycle operations
- [ ] Application assignment management
- [ ] Group membership operations
- [ ] Factor enrollment and verification
- [ ] Policy and rule management
- [ ] Approval workflows for sensitive operations
- [ ] Multi-channel approval options (web, email, Slack)
- [ ] Audit logging and compliance reporting
- [ ] System log integration
- [ ] Security insights generation
- [ ] Multi-tenant support
- [ ] Role-based access control

## 🆘 Need Help?

Before raising an issue, check:
1. 📝 Server configuration
2. 🔑 Okta API permissions
3. 🔌 MCP client compatibility
4. 📊 Server logs

Still having problems? Open an issue on GitHub or email support@fctr.io (response times may vary)

## 💡 Feature Requests & Ideas

Have an idea or suggestion? [Open a feature request](https://github.com/fctr-id/okta-mcp-server/issues/new?labels=enhancement) on GitHub!

## 👥 Contributors

Interested in contributing? We'd love to have you! Contact info@fctr.io for collaboration opportunities.

## ⚖️ Legal Stuff

Check out [`License.md`](LICENSE) for the fine print.

---

🌟 © 2025 Fctr Identity. All rights reserved. Made with ❤️ for the Okta and AI communities.