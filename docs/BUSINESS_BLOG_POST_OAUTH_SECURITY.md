# Secure MCP + Okta: Protect SOAR Workflows with OAuth 2.1 Security & RBAC (Part 1)

*If you have been following the model context protocl closely , the running joke is: "The S in MCP stands for Security"*

**FCTR's  MCP Server for Okta delivers OAuth 2.1-protected MCP access with role-based tool filtering.** The server's tools are protectd by Oauth and can aslo be filtered by roles so all users don;t get the same level of tool access.

Our implementation uses the combined Authorization Server/Resource Server pattern, where the MCP server acts as both an OAuth authorization server and resource server. The approach is detailed in the [MCP Authorization specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization), with [Aaron Parecki's analysis of the trade-offs](https://aaronparecki.com/2025/04/03/15/oauth-for-model-context-protocol) providing additional context. 

It's particularly valuable for organizations that don't have dedicated OAuth infrastructure or where Dynamic Client Registration (DCR) may not be practical. The POC and reference implementation explores how OAuth proxy patterns work in practice, helping organizations that prefer static client registration or need tighter control over client registration processes. For security issues or vulnerabilities, please contact dan@fctr.io. We welcome feedback and contributions from the security community.

---

## Most MCP Implementations Today Have No Security At All

The Model Context Protocol (MCP) has exploded in popularity, but here's the uncomfortable truth: most examples in the wild have no security whatsoever. This is why we're seeing MCP remote server exposures making headlines.

While Dynamic Client Registration (DCR) is indeed more secure for many scenarios and reduces the operational burden on MCP servers by enabling automatic client registration, the reality is that most implementations skip security entirely. When security is attempted, many production environments prefer static client registration for better audit trails and predictable security boundaries.

DCR excels in scenarios with many diverse clients, while the combined pattern works well for controlled enterprise environments where you want explicit oversight of client registration and unified access control policies.

## The Challenge: 

As AI agents become increasingly sophisticated, they're demanding access to more sensitive enterprise data than ever before. Different teams across the organization want AI to analyze various data sources - from customer information to code repositories to financial reports.

This creates a fundamental tension: **How do you give AI the data it needs to be useful while maintaining the security controls your business depends on?**

The Model Context Protocol (MCP) was designed to solve this challenge by creating a standardized way for AI systems to access enterprise data sources. But early implementations suffered from a critical flaw: they treated security as an afterthought, not a foundational requirement.

## The Combined vs. Separated Pattern Approach

Before we dive into solutions, let's acknowledge what most MCP implementations actually look like: no security whatsoever. Everyone gets all access to everything. This "trust everyone with everything" approach might work for toy examples and demos, but it creates obvious problems when you're dealing with real enterprise data.

Our Okta MCP Server takes a different approach using what the [MCP Authorization specification describes as the combined Authorization Server/Resource Server pattern](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization). In this pattern, the MCP server handles both OAuth authorization and resource serving, which provides several advantages:

- **Simplified deployment**: Single server to deploy and maintain
- **Tighter integration**: Direct control over both authentication and authorization 
- **Enterprise compatibility**: Works with existing OAuth infrastructure without requiring DCR support
- **Audit simplicity**: Single point for all access control decisions

While Dynamic Client Registration (DCR) offers benefits like reduced server burden and per-client token management, the combined pattern is often more practical for enterprise deployments where you need predictable client registration processes and comprehensive audit trails.

Our implementation acts as a secure proxy between AI clients and Okta, implementing OAuth 2.1 security requirements and following the security guidelines outlined in the [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices).

For detailed information about our security fixes and implementation details, see our [Security Best Practices documentation](https://github.com/fctr-id/okta-mcp-server/blob/feature/oauth-proxy-implementation/docs/Security-Best-Practices.md).

## How It Actually Works: Step by Step

Here's the complete workflow when an AI client wants to access your Okta data:

![OAuth Flow Diagram](https://raw.githubusercontent.com/fctr-id/okta-mcp-server/refs/heads/feature/oauth-proxy-implementation/images/mcp-oauth-proxy.png)

*The complete OAuth 2.1 flow showing the interaction between MCP Client, MCP Proxy Server, and Third-Party Authorization Server*

**Step 1: Initial Connection**  
An AI client (like VS Code or Claude Desktop) attempts to connect to our MCP server endpoint at `/mcp`. No authentication required at this stage.

**Step 2: Security Challenge**  
Our server responds with OAuth 2.1 discovery metadata, essentially saying "you need to authenticate first." The client gets redirected to start the OAuth flow.

**Step 3: User Authentication**  
The user is redirected to Okta for authentication. They log in with their corporate credentials, potentially including multi-factor authentication.

**Step 4: Consent Screen**  
The user sees a clear consent screen explaining exactly what data the AI will access and for what purpose. This consent expires after 24 hours in our implementation, providing additional security layers and ensuring users maintain control over AI access to their data.

**Step 5: Token Exchange**  
Once the user consents, Okta issues scoped access tokens specifically for our MCP server. These tokens are temporary and can be refreshed by the client.

**Step 6: RBAC Filtering**  
Our server checks the user's Okta group memberships and dynamically filters which tools and data they can access. A viewer role gets different capabilities than an admin role.

**Step 7: Secure Operations**  
The AI can now perform operations, but only within the user's authorized scope. Every request is validated, and all activities are logged for audit purposes.

**Step 8: Session Management**  
Sessions automatically expire after 2 hours. Consent expires after 24 hours. Tokens refresh automatically to maintain seamless operation while preserving security.

## Getting Started and What's Next

The [implementation is available on GitHub](https://github.com/fctr-id/okta-mcp-server/tree/feature/oauth-proxy-implementation). Setup involves configuring your Okta environment and running the server with your organization's configuration. Once configured, AI clients like VS Code can connect using a simple URL.

This is a reference implementation demonstrating security best practices. It provides enterprise-grade OAuth 2.1 authentication, role-based access controls, comprehensive audit logging, and secure session management. For production use, you'll want persistent session storage, comprehensive token revocation processes, proper SSL certificates, and integration with existing monitoring systems.

## Conclusion: Security as a Business Enabler

The transition from no security to OAuth 2.1-secured MCP servers isn't just about reducing risk - it's about enabling broader AI adoption within your organization. When security teams trust the access controls, when compliance teams can generate audit reports, and when users can safely connect AI to their data, innovation accelerates.

The choice isn't between security and functionality. It's between implementations that will never pass an enterprise security review and ones that will.

**The S in MCP really does stand for Security** - when implemented correctly.

We encourage security professionals to test our implementation. For security issues, contact our security team directly. For general feedback, standard support channels are available.

**Coming in Part 2**: We'll explore the separated Authorization Server/Resource Server pattern with Dynamic Client Registration, showing how to evolve from this foundation to the distributed architecture defined in the [2025-06-18 MCP specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) for more complex enterprise scenarios.

---


## Related Security Resources

- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
- [MCP Specification Changelog](https://modelcontextprotocol.io/specification/2025-06-18/changelog)
- [Aaron Parecki's OAuth for MCP Article](https://aaronparecki.com/2025/04/03/15/oauth-for-model-context-protocol)
- [OAuth 2.1 Security Best Practices](https://datatracker.ietf.org/doc/html/rfc9700)


---

**Tags**: [OAuth 2.1](https://iamse.blog/tag/oauth/), [MCP Security](https://iamse.blog/tag/mcp-security/), [AI Security](https://iamse.blog/tag/ai-security/), [Okta MCP](https://iamse.blog/tag/okta-mcp/), [RBAC](https://iamse.blog/tag/rbac/), [FastMCP](https://iamse.blog/tag/fastmcp/), [Static Client Registration](https://iamse.blog/tag/static-client/)
