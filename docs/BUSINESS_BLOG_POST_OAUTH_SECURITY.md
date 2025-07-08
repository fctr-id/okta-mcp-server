# Secure MCP + Okta: Protect SOAR Workflows with OAuth 2.1 Security & RBAC (Part 1)

*If you have been following the model context protocl closely , the running joke is: "The S in MCP stands for Security"*

This article is about FCTR's implementation based on the older (legacy) MCP protocol spec (03-26) standard which uses the MCP server as the authorization server (or proxy), which is now replaced by Dynamic Client Registration in the 06-18 spec revision.

This was created as a POC and reference implementation to see how this works and may help with use cases where the organization does not have Okta SKUs to create custom auth servers, and DCR also needs a way or portal for clients to register which is not available yet.

 Feel free to browse and deploy. Leave a comment below if you see anything wrong or find vulnerabilities, please email dan@fctr.io. Happy to learn!

---

## Most MCP Implementations Today Have No Security At All

The Model Context Protocol (MCP) has exploded in popularity, but here's the uncomfortable truth: most examples in the wild have no security whatsoever. This is why we're seeing MCP remote server exposures making headlines.

While Dynamic Client Registration (DCR) is indeed more secure and reduces the burden on MCP servers by enabling automatic client registration, the reality is that most implementations skip security entirely. When security is attempted, most commercial MCP servers do not provide a secure way to initiate or register DCR clients. DCR creates practical challenges for enterprise deployments like application sprawl and complex audit trails, with each MCP client creating its own application registration.

DCR has many advantages: no load on the MCP server to act as a proxy, each client has its own token, revocation is possible for individual clients, and it removes the middleman role between clients and authorization servers.

## The Challenge: 

As AI agents become increasingly sophisticated, they're demanding access to more sensitive enterprise data than ever before. Different teams across the organization want AI to analyze various data sources - from customer information to code repositories to financial reports.

This creates a fundamental tension: **How do you give AI the data it needs to be useful while maintaining the security controls your business depends on?**

The Model Context Protocol (MCP) was designed to solve this challenge by creating a standardized way for AI systems to access enterprise data sources. But early implementations suffered from a critical flaw: they treated security as an afterthought, not a foundational requirement.

## The Old MCP Way vs. Our Secure Approach

Before we dive into solutions, let's acknowledge what most MCP implementations actually look like: no security whatsoever. Everyone gets all access to everything. This "trust everyone with everything" approach might work for toy examples and demos, but it creates obvious problems when you're dealing with real enterprise data.

Our Okta MCP Server takes a different approach. We're following what [Aaron Parecki calls the "legacy" pattern](https://aaronparecki.com/2025/04/03/15/oauth-for-model-context-protocol), but with good reason. Not every organization has Okta SKUs for creating custom OAuth servers, and currently most providers do not support initial registration or make it easy to implement DCR securely.

Our implementation acts as a secure proxy between AI clients and Okta, implementing every security best practice outlined in the [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices).

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
The user sees a clear consent screen explaining exactly what data the AI will access and for what purpose. This consent expires every hour per MCP best practices, providing a workaround for the Confused Deputy vulnerability.

**Step 5: Token Exchange**  
Once the user consents, Okta issues scoped access tokens specifically for our MCP server. These tokens are temporary and can be refreshed by the client.

**Step 6: RBAC Filtering**  
Our server checks the user's Okta group memberships and dynamically filters which tools and data they can access. A viewer role gets different capabilities than an admin role.

**Step 7: Secure Operations**  
The AI can now perform operations, but only within the user's authorized scope. Every request is validated, and all activities are logged for audit purposes.

**Step 8: Session Management**  
Sessions automatically expire after 2 hours. Consent expires every hour. Tokens refresh automatically to maintain seamless operation while preserving security.

## Getting Started and What's Next

The [implementation is available on GitHub](https://github.com/fctr-id/okta-mcp-server/tree/feature/oauth-proxy-implementation). Setup involves configuring your Okta environment and running the server with your organization's configuration. Once configured, AI clients like VS Code can connect using a simple URL.

This is a reference implementation demonstrating security best practices. It provides enterprise-grade OAuth 2.1 authentication, role-based access controls, comprehensive audit logging, and secure session management. For production use, you'll want persistent session storage, comprehensive token revocation processes, proper SSL certificates, and integration with existing monitoring systems.

## Conclusion: Security as a Business Enabler

The transition from no security to OAuth 2.1-secured MCP servers isn't just about reducing risk - it's about enabling broader AI adoption within your organization. When security teams trust the access controls, when compliance teams can generate audit reports, and when users can safely connect AI to their data, innovation accelerates.

The choice isn't between security and functionality. It's between implementations that will never pass an enterprise security review and ones that will.

**The S in MCP really does stand for Security** - when implemented correctly.

We encourage security professionals to test our implementation. For security issues, contact our security team directly. For general feedback, standard support channels are available.

**Coming in Part 2**: We'll explore the separated Authorization Server pattern with Dynamic Client Registration, showing how to evolve from this foundation to the architecture Aaron Parecki and the OAuth community are championing.

---


## Related Security Resources

- [Aaron Parecki's OAuth for MCP Article](https://aaronparecki.com/2025/04/03/15/oauth-for-model-context-protocol)
- [OAuth 2.1 Security Best Practices](https://tools.ietf.org/html/draft-ietf-oauth-security-topics)
- [MCP Security Considerations](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)


---

**Tags**: [OAuth 2.1](https://iamse.blog/tag/oauth/), [MCP Security](https://iamse.blog/tag/mcp-security/), [AI Security](https://iamse.blog/tag/ai-security/), [Okta MCP](https://iamse.blog/tag/okta-mcp/), [RBAC](https://iamse.blog/tag/rbac/), [FastMCP](https://iamse.blog/tag/fastmcp/), [Static Client Registration](https://iamse.blog/tag/static-client/)
