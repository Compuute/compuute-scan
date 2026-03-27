#!/bin/bash
# compuute-scan secure workflow
# Usage:
#   ./scan.sh clone <git-url>              — Clone repo into isolated volume
#   ./scan.sh run <repo-name> [options]    — Scan repo (no network)
#   ./scan.sh list                         — List cloned repos
#   ./scan.sh clean                        — Remove all cloned repos
#   ./scan.sh clean <repo-name>            — Remove specific repo

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Ensure reports dir exists
mkdir -p reports

case "${1:-help}" in
  clone)
    if [ -z "$2" ]; then
      echo -e "${RED}Usage: ./scan.sh clone <git-url>${NC}"
      exit 1
    fi
    REPO_URL="$2"
    REPO_NAME="${3:-$(basename "$REPO_URL" .git)}"

    echo -e "${CYAN}Cloning ${REPO_URL} → ${REPO_NAME}${NC}"
    echo -e "${YELLOW}Network: enabled (clone-net)${NC}"

    docker compose run --rm clone clone --depth 1 "$REPO_URL" "/home/scanner/repos/$REPO_NAME"

    echo -e "${GREEN}✓ Cloned to isolated volume: ${REPO_NAME}${NC}"
    echo -e "  Run: ${CYAN}./scan.sh run ${REPO_NAME}${NC}"
    ;;

  run|scan)
    if [ -z "$2" ]; then
      echo -e "${RED}Usage: ./scan.sh run <repo-name> [--output filename.md] [options]${NC}"
      exit 1
    fi
    REPO_NAME="$2"
    shift 2

    # Auto-prefix --output with container report path
    ARGS=()
    while [ $# -gt 0 ]; do
      if [ "$1" = "--output" ] || [ "$1" = "-o" ]; then
        ARGS+=("--output")
        shift
        FILENAME="$1"
        # If user gives just a filename, map to /home/scanner/reports/
        if [[ "$FILENAME" != /* ]]; then
          FILENAME="/home/scanner/reports/$FILENAME"
        fi
        ARGS+=("$FILENAME")
      else
        ARGS+=("$1")
      fi
      shift
    done

    echo -e "${CYAN}Scanning: ${REPO_NAME}${NC}"
    echo -e "${GREEN}Network: NONE (--network none, zero stack)${NC}"
    echo -e "${GREEN}Filesystem: READ-ONLY${NC}"
    echo -e "${GREEN}Capabilities: ALL DROPPED${NC}"
    echo -e "${GREEN}Privileges: no-new-privileges${NC}"
    echo ""

    docker compose run --rm scan "./$REPO_NAME" "${ARGS[@]}"

    # Show host path if report was written
    for i in "${!ARGS[@]}"; do
      if [ "${ARGS[$i]}" = "--output" ]; then
        HOST_FILE="$SCRIPT_DIR/reports/$(basename "${ARGS[$((i+1))]}")"
        if [ -f "$HOST_FILE" ]; then
          echo -e "\n${GREEN}Report saved: ${HOST_FILE}${NC}"
        fi
      fi
    done
    ;;

  list)
    echo -e "${CYAN}Cloned repositories:${NC}"
    docker compose run --rm --entrypoint ls scan -la /home/scanner/repos/ 2>/dev/null || echo "  (none)"
    ;;

  clean)
    if [ -n "$2" ]; then
      echo -e "${YELLOW}Removing repo: $2${NC}"
      # Use clone service (not read-only) for deletion
      docker run --rm \
        --network none \
        --cap-drop ALL \
        --security-opt no-new-privileges:true \
        -v compuute-scan-repos:/home/scanner/repos \
        --entrypoint rm \
        compuute-scan-clone -rf "/home/scanner/repos/$2"
      echo -e "${GREEN}✓ Removed${NC}"
    else
      echo -e "${YELLOW}Removing ALL cloned repos...${NC}"
      docker volume rm compuute-scan-repos 2>/dev/null || true
      echo -e "${GREEN}✓ Volume removed${NC}"
    fi
    ;;

  local)
    # Scan a local directory (mounted read-only)
    if [ -z "$2" ]; then
      echo -e "${RED}Usage: ./scan.sh local /path/to/repo [options]${NC}"
      exit 1
    fi
    LOCAL_PATH="$(cd "$2" && pwd)"
    REPO_NAME="$(basename "$LOCAL_PATH")"
    shift 2

    # Auto-prefix --output
    ARGS=()
    while [ $# -gt 0 ]; do
      if [ "$1" = "--output" ] || [ "$1" = "-o" ]; then
        ARGS+=("--output")
        shift
        FILENAME="$1"
        if [[ "$FILENAME" != /* ]]; then
          FILENAME="/home/scanner/reports/$FILENAME"
        fi
        ARGS+=("$FILENAME")
      else
        ARGS+=("$1")
      fi
      shift
    done

    echo -e "${CYAN}Scanning local: ${LOCAL_PATH}${NC}"
    echo -e "${GREEN}Mounted: READ-ONLY${NC}"
    echo -e "${GREEN}Network: NONE (--network none)${NC}"
    echo -e "${GREEN}Capabilities: ALL DROPPED${NC}"
    echo ""

    # Mount to /mnt/target (avoids read_only conflict with /home/scanner/repos)
    docker run --rm \
      --read-only \
      --network none \
      --cap-drop ALL \
      --security-opt no-new-privileges:true \
      --memory 512m \
      --cpus 1.0 \
      --tmpfs /tmp:size=50M \
      -v "${LOCAL_PATH}:/mnt/target:ro" \
      -v "${SCRIPT_DIR}/reports:/home/scanner/reports" \
      compuute-scan-scan /mnt/target "${ARGS[@]}"

    for i in "${!ARGS[@]}"; do
      if [ "${ARGS[$i]}" = "--output" ]; then
        HOST_FILE="$SCRIPT_DIR/reports/$(basename "${ARGS[$((i+1))]}")"
        if [ -f "$HOST_FILE" ]; then
          echo -e "\n${GREEN}Report saved: ${HOST_FILE}${NC}"
        fi
      fi
    done
    ;;

  help|--help|-h)
    echo "compuute-scan — Secure Scanning Workflow"
    echo ""
    echo "Commands:"
    echo "  clone <git-url> [name]    Clone repo into isolated Docker volume"
    echo "  run <repo-name> [opts]    Scan repo (network disabled, read-only)"
    echo "  local /path/to/repo       Scan local dir (mounted read-only)"
    echo "  list                      List cloned repos"
    echo "  clean [repo-name]         Remove cloned repos"
    echo ""
    echo "Examples:"
    echo "  ./scan.sh clone https://github.com/client/mcp-server.git"
    echo "  ./scan.sh run mcp-server --output /reports/client-scan.md"
    echo "  ./scan.sh local ~/client-code --output /reports/local-scan.md"
    echo "  ./scan.sh list"
    echo "  ./scan.sh clean mcp-server"
    echo ""
    echo "Security:"
    echo "  • Scan: --network none (zero network stack, no IP/DNS)"
    echo "  • Clone: bridge network (only for git, not scanning)"
    echo "  • Filesystem: read-only (client code mounted :ro)"
    echo "  • Capabilities: ALL dropped (cap_drop: ALL)"
    echo "  • no-new-privileges enforced"
    echo "  • Resource limits: 1 CPU, 512MB RAM"
    echo "  • Non-root user (scanner) inside container"
    echo "  • Repos stored in isolated Docker volume"
    echo "  • Reports output to ./reports/"
    ;;

  *)
    echo -e "${RED}Unknown command: $1${NC}"
    echo "Run: ./scan.sh help"
    exit 1
    ;;
esac
