Write-Host "Building STDIO image..." -ForegroundColor Yellow
docker build --target stdio -t okta-mcp-server-stdio .

Write-Host "Building SSE image..." -ForegroundColor Yellow
docker build --target sse -t okta-mcp-server-sse .

Write-Host "✅ Both images built successfully!" -ForegroundColor Green
docker images | Select-String "okta-mcp-server"