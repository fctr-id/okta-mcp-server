<div align="center">
  <a href="https://fctr.io">
    <img src="https://fctr.io/images/logo.svg" alt="fctr.io" width="110" height="auto">
  </a>
</div>

<h2 style="margin-left: 10px" align="center">Okta MCP Server (v0.1.0-ALPHA)</h2>

The Okta MCP Server is a groundbreaking tool that enables AI models to interact directly with your Okta environment using the Model Context Protocol (MCP). Built specifically for IAM engineers, security teams, and Okta administrators, it implements the MCP specification to transform how AI assistants can help manage and analyze Okta resources. Our vision is to create a secure bridge between AI models and Okta's powerful API ecosystem, maintaining enterprise-grade security while unlocking unprecedented integration capabilities.

<div align="center">
<p><a href="https://github.com/fctr-id/okta-mcp-server">View on GitHub</a> | <a href="https://modelcontextprotocol.io/introduction">Learn about MCP</a></p>
</div>

<div align="center">
<h3>MCP Integration with AI Assistants</h3>
</div>
<p align="center">
  <img src="docs/okta-mcp-demo.gif" alt="Okta MCP Server Demo" width="1024px" height="auto">
</p>

<div align="center">
<h3>What is the Model Context Protocol?</h3>
<p>Learn how MCP enables secure, structured AI-to-tool interactions:</p>
<div align="center">
      <a href="https://modelcontextprotocol.io/introduction">
         <img src="docs/mcp-overview.png" style="width:500px">
      </a>
</div>
</div>

## 📋 Table of Contents

- [📋 Table of Contents](#-table-of-contents)
- [✨ What's Special?](#-whats-special)
- [🚀 Quick Start](#-quick-start)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Supported Transports and Launching](#supported-transports-and-launching)
    - [1. Standard I/O (STDIO) - Recommended](#1-standard-io-stdio---recommended)
    - [2. Server-Sent Events (SSE) - Advanced Use Only](#2-server-sent-events-sse---advanced-use-only)
- [🔍 Overview](#-overview)
- [🛡️ Security \& Privacy](#️-security--privacy)
  - [Data Control](#data-control)
    - [Technical Safeguards](#technical-safeguards)
    - [Access Management](#access-management)
  - [Data Privacy](#data-privacy)
  - [Available Tools Overview](#available-tools-overview)
- [⚠️ Good to Know](#️-good-to-know)
  - [Alpha Release 🧪](#alpha-release-)
  - [Security First 🛡️](#security-first-️)
  - [Current Limitations 🔍](#current-limitations-)
- [🗺️ Roadmap](#️-roadmap)
  - [Phase 1: Core MCP Implementation](#phase-1-core-mcp-implementation)
  - [Phase 2: Expanded Okta API Coverage](#phase-2-expanded-okta-api-coverage)
  - [Phase 3: Human-in-the-Loop Workflows](#phase-3-human-in-the-loop-workflows)
  - [Phase 4: Enhanced Analytics](#phase-4-enhanced-analytics)
  - [Phase 5: Enterprise Integration](#phase-5-enterprise-integration)
- [🆘 Need Help?Still having problems? Open an issue on GitHub or email support@fctr.io (response times may vary)](#-need-helpstill-having-problems-open-an-issue-on-github-or-email-supportfctrio-response-times-may-vary)
- [💡 Feature Requests \& Ideas## ⚖️ Legal Stuff](#-feature-requests--ideas-️-legal-stuff)
- [👥 Contributors---](#-contributors---)
- [⚖️ Legal Stuff](#️-legal-stuff)

&nbsp;

## ✨ What's Special?

* 🔄 **MCP Standard Implementation** - Fully compliant with the Model Context Protocol specification
* 🔌 **Wide Client Compatibility** - Works with Claude Desktop, Microsoft Copilot Studio, Fast-agent, Cline, Continue and many other MCP clients
* 🔍 **Natural Language Okta Exploration** - Query your Okta environment through conversational AI interfaces
* 🧩 **Modular Architecture** - Extensible design for easy addition of new Okta API capabilities
* 🛡️ **Security-First Design** - Built with IAM best practices at its core

## 🚀 Quick Start

### Prerequisites

✅ Python 3.8+ installed on your machine  
✅ Okta tenant with appropriate API access  
✅ An MCP-compatible AI client (Claude Desktop, Microsoft Copilot Studio, etc.)  

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

### Configuration

Create a config file with your Okta settings:

```bash
# Copy the sample config
cp config.example.json config.json

# Edit with your settings
# Required: Okta domain and API token
```

### Supported Transports and Launching

The Okta MCP Server supports two transport protocols:

#### 1. Standard I/O (STDIO) - Recommended

```bash
# Run the server in STDIO mode (default)
python main.py
```

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
          "OKTA_ORG_URL": "https://dev-1606.okta.com",
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

## 🔍 Overview

The Okta MCP Server implements the Model Context Protocol to expose Okta's APIs as standardized tools that can be discovered and used by AI assistants. Key capabilities include:

- **Discovering resources** - Browse users, groups, applications and other Okta entities
- **Executing Okta operations** - Perform read operations and eventually write operations with approval
- **Contextual data exchange** - Provide relevant Okta information to AI models for decision making
- **Secure permissions model** - Granular control over what operations are available

## 🛡️ Security & Privacy 

<p align="center">
  <img src="docs/okta_mcp_architecture.png" alt="Okta MCP Server Architecture" width="800" height="auto">
</p>

### Data Control

#### Technical Safeguards
- **Controlled Information Flow**: The server mediates all interactions between AI models and your Okta environment
- **On-Premise Deployment**: Deploy in your own infrastructure with full control over network boundaries
- **No External Dependencies**: Self-contained architecture requires no third-party services

#### Access Management
- **API Token Management**: You create and control the Okta API token, including network access and permissions
- **Tool Authorization**: Fine-grained control over which Okta operations are exposed as tools

### Data Privacy 

- ✅ **What's Sent to AI Clients**:
  - Tool descriptions and schemas
  - Operation parameters and results
  - Error messages without sensitive details
  
- ❌ **What's Not Sent Without Explicit Actions**:
  - Bulk user data
  - Security configurations
  - Credentials or secrets

### Available Tools Overview 

| Category | Available Tools |
|----------|----------------|
| User Management | `list_users`, `get_user`, `search_users` |
| Group Operations | `list_groups`, `get_group_members`, `get_user_groups` |
| Application Management | `list_applications`, `get_application`, `get_application_users` |
| Factor Management | `list_user_factors`, `get_factor` |
| Policy Inspection | `list_policies`, `get_policy` |

Each tool includes rich metadata to help AI models understand:
- Required parameters
- Expected data formats
- Potential errors and handling strategies

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

### Phase 1: Core MCP Implementation
- [x] MCP protocol compliance
- [x] Basic Okta API integration
- [x] Read-only operations support
- [ ] Comprehensive documentation

### Phase 2: Expanded Okta API Coverage
- [ ] Complete user lifecycle operations
- [ ] Application assignment management
- [ ] Group membership operations
- [ ] Factor enrollment and verification
- [ ] Policy and rule management

### Phase 3: Human-in-the-Loop Workflows
- [ ] Approval workflows for sensitive operations
- [ ] Multi-channel approval options (web, email, Slack)
- [ ] Audit logging and compliance reporting
- [ ] Session-based operation context

### Phase 4: Enhanced Analytics
- [ ] System log integration
- [ ] Event analysis and correlation
- [ ] Security insights generation
- [ ] Configuration recommendations

### Phase 5: Enterprise Integration
- [ ] Multi-tenant support
- [ ] Role-based access control
- [ ] High availability deployment options
3. 🔌 MCP client compatibility
- [ ] Enterprise authentication flows

## 🆘 Need Help?Still having problems? Open an issue on GitHub or email support@fctr.io (response times may vary)

Before raising an issue, check:## 💡 Feature Requests & Ideas
1. 📝 Server configuration
2. 🔑 Okta API permissionsHave an idea or suggestion? [Open a feature request](https://github.com/fctr-id/okta-mcp-server/issues/new?labels=enhancement) on GitHub!
3. 🔌 MCP client compatibility
4. 📊 Server logs## 👥 Contributors

Still having problems? Open an issue on GitHub or email support@fctr.io (response times may vary)Interested in contributing? We'd love to have you! Contact info@fctr.io for collaboration opportunities.

## 💡 Feature Requests & Ideas## ⚖️ Legal Stuff

Have an idea or suggestion? [Open a feature request](https://github.com/fctr-id/okta-mcp-server/issues/new?labels=enhancement) on GitHub!Check out [`License.md`](LICENSE) for the fine print.

## 👥 Contributors---

Interested in contributing? We'd love to have you! Contact info@fctr.io for collaboration opportunities.🌟 © 2024 Fctr. All rights reserved. Made with ❤️ for the Okta and AI communities.
## ⚖️ Legal Stuff

Check out [`License.md`](LICENSE) for the fine print.

---

🌟 © 2024 Fctr. All rights reserved. Made with ❤️ for the Okta and AI communities.