# compuute-scan — Isolated scan environment
# No network, no root, read-only filesystem, resource-limited
FROM node:22-alpine

# Non-root user
RUN addgroup -S scanner && adduser -S scanner -G scanner

# Install git (for cloning repos inside container)
RUN apk add --no-cache git

# Copy scanner
WORKDIR /home/scanner/tool
COPY compuute-scan.js .
RUN chmod +x compuute-scan.js && chown -R scanner:scanner /home/scanner

# Working directory for client repos
RUN mkdir -p /home/scanner/repos /home/scanner/reports && \
    chown -R scanner:scanner /home/scanner/repos /home/scanner/reports

USER scanner
WORKDIR /home/scanner/repos

ENTRYPOINT ["node", "/home/scanner/tool/compuute-scan.js"]
