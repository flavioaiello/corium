#!/bin/bash
#
# Spawn a cluster of 7 corium nodes for testing.
#
# Usage:
#   ./scripts/spawn_cluster.sh        # Start 7 nodes
#   ./scripts/spawn_cluster.sh stop   # Stop all nodes
#   ./scripts/spawn_cluster.sh status # Check node status
#
# The first node is started without bootstrap (seed node).
# Nodes 1-6 are started with the seed node as bootstrap.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/target/release/corium"
PID_DIR="$PROJECT_DIR/target/cluster_pids"
LOG_DIR="$PROJECT_DIR/target/cluster_logs"

NODE_COUNT=7
BASE_PORT=19000

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

build_binary() {
    log_info "Building corium in release mode..."
    cd "$PROJECT_DIR"
    cargo build --release
    if [[ ! -f "$BINARY" ]]; then
        log_error "Binary not found at $BINARY"
        exit 1
    fi
    log_info "Build complete: $BINARY"
}

start_cluster() {
    # Ensure binary exists
    if [[ ! -f "$BINARY" ]]; then
        build_binary
    fi

    # Create directories and clear old logs
    mkdir -p "$PID_DIR" "$LOG_DIR"
    rm -f "$LOG_DIR"/*.log 2>/dev/null || true

    # Check if cluster is already running
    if [[ -f "$PID_DIR/node_0.pid" ]]; then
        local pid
        pid=$(cat "$PID_DIR/node_0.pid" 2>/dev/null)
        if kill -0 "$pid" 2>/dev/null; then
            log_error "Cluster already running. Use '$0 stop' first."
            exit 1
        fi
    fi

    log_info "Starting cluster with $NODE_COUNT nodes..."

    # Start seed node (node 0) without bootstrap
    local seed_port=$BASE_PORT
    local seed_addr="127.0.0.1:$seed_port"
    
    log_info "Starting seed node (node 0) on $seed_addr..."
    RUST_LOG=info "$BINARY" --bind "$seed_addr" --telemetry-interval 60 \
        >> "$LOG_DIR/node_0.log" 2>&1 &
    local seed_pid=$!
    echo "$seed_pid" > "$PID_DIR/node_0.pid"

    # Wait for seed node to start and log its NodeId
    log_info "Waiting for seed node to initialize..."
    local seed_node_id=""
    local attempts=0
    local max_attempts=50  # 5 seconds max

    while [[ -z "$seed_node_id" && $attempts -lt $max_attempts ]]; do
        sleep 0.1
        ((attempts++))
        
        # Check if process is still running
        if ! kill -0 "$seed_pid" 2>/dev/null; then
            log_error "Seed node failed to start. Check $LOG_DIR/node_0.log"
            cat "$LOG_DIR/node_0.log"
            exit 1
        fi
        
        # Try to extract NodeId from logs
        # New log format: "INFO corium: Node IP:PORT/NODEID"
        # Strip ANSI codes first, then extract the NodeId after the /
        if [[ -f "$LOG_DIR/node_0.log" ]]; then
            # Strip ANSI codes and extract NodeId from "Node IP:PORT/NODEID" format
            seed_node_id=$(sed 's/\x1b\[[0-9;]*m//g' "$LOG_DIR/node_0.log" 2>/dev/null | \
                grep ": Node " | \
                grep -v "Bootstrap" | \
                sed -n 's/.*: Node [^/]*\/\([0-9a-f]*\).*/\1/p' | \
                head -1)
        fi
    done

    if [[ -z "$seed_node_id" ]]; then
        log_error "Failed to extract seed node NodeId after ${max_attempts} attempts"
        log_error "Log contents:"
        cat "$LOG_DIR/node_0.log"
        exit 1
    fi

    # Build bootstrap argument in format: IP:PORT/NODEID
    # This is required because TLS identity pinning requires knowing the NodeId before connecting
    local bootstrap_arg="${seed_addr}/${seed_node_id}"

    # Display seed node info
    log_info "Seed node started (PID: $seed_pid)"
    log_info "  NodeId: $seed_node_id"
    log_info "  Bootstrap arg: $bootstrap_arg"

    # Start nodes 1 to NODE_COUNT-1 with seed as bootstrap
    for i in $(seq 1 $((NODE_COUNT - 1))); do
        local port=$((BASE_PORT + i))
        local addr="127.0.0.1:$port"
        
        log_info "Starting node $i on $addr with bootstrap $bootstrap_arg..."
        RUST_LOG=info "$BINARY" --bind "$addr" --bootstrap "$bootstrap_arg" --telemetry-interval 60 \
            >> "$LOG_DIR/node_$i.log" 2>&1 &
        local pid=$!
        echo "$pid" > "$PID_DIR/node_$i.pid"

        # Brief pause between node starts
        sleep 0.5
        
        # Display node info
        if kill -0 "$pid" 2>/dev/null; then
            # Wait a moment for logs to appear
            sleep 0.3
            # Show Node and Bootstrap lines in the new format
            grep -E "(: Node |: Bootstrap |Bootstrap complete)" "$LOG_DIR/node_$i.log" 2>/dev/null | while read -r line; do
                echo "         $line"
            done
        else
            log_error "Node $i failed to start. Check $LOG_DIR/node_$i.log"
        fi
    done

    # Wait for all nodes to initialize
    sleep 2

    log_info "Cluster started. Verifying nodes..."
    show_status
}

stop_cluster() {
    log_info "Stopping cluster..."

    local stopped=0
    for i in $(seq 0 $((NODE_COUNT - 1))); do
        local pid_file="$PID_DIR/node_$i.pid"
        if [[ -f "$pid_file" ]]; then
            local pid
            pid=$(cat "$pid_file")
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
                log_info "Stopped node $i (PID $pid)"
                ((stopped++))
            fi
            rm -f "$pid_file"
        fi
    done

    if [[ $stopped -eq 0 ]]; then
        log_warn "No running nodes found"
    else
        log_info "Stopped $stopped nodes"
    fi

    # Also kill any stray corium processes on our ports
    for i in $(seq 0 $((NODE_COUNT - 1))); do
        local port=$((BASE_PORT + i))
        local stray_pid
        stray_pid=$(lsof -ti :$port 2>/dev/null || true)
        if [[ -n "$stray_pid" ]]; then
            kill "$stray_pid" 2>/dev/null || true
            log_warn "Killed stray process on port $port (PID $stray_pid)"
        fi
    done
}

show_status() {
    echo ""
    echo "Node Status:"
    echo "============"
    printf "%-8s %-8s %-22s %-20s\n" "NODE" "PID" "ADDRESS" "STATUS"
    echo "------------------------------------------------------------"

    local running=0
    for i in $(seq 0 $((NODE_COUNT - 1))); do
        local port=$((BASE_PORT + i))
        local addr="127.0.0.1:$port"
        local pid_file="$PID_DIR/node_$i.pid"
        local status="NOT STARTED"
        local pid="-"

        if [[ -f "$pid_file" ]]; then
            pid=$(cat "$pid_file")
            if kill -0 "$pid" 2>/dev/null; then
                status="${GREEN}RUNNING${NC}"
                ((running++))
            else
                status="${RED}DEAD${NC}"
            fi
        fi

        printf "%-8s %-8s %-22s " "node_$i" "$pid" "$addr"
        echo -e "$status"
    done

    echo ""
    echo "Running: $running / $NODE_COUNT"
    echo ""
    echo "Log files: $LOG_DIR/"
    echo "PID files: $PID_DIR/"
}

show_logs() {
    local node="${1:-0}"
    local log_file="$LOG_DIR/node_$node.log"
    
    if [[ ! -f "$log_file" ]]; then
        log_error "Log file not found: $log_file"
        exit 1
    fi
    
    log_info "Showing logs for node $node:"
    tail -f "$log_file"
}

show_usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  start   Start the cluster (default)"
    echo "  stop    Stop all nodes"
    echo "  restart Restart the cluster"
    echo "  status  Show node status"
    echo "  logs N  Tail logs for node N (default: 0)"
    echo "  build   Build the binary only"
    echo "  clean   Stop cluster and remove logs/pids"
    echo ""
    echo "Examples:"
    echo "  $0              # Start 7-node cluster"
    echo "  $0 stop         # Stop all nodes"
    echo "  $0 logs 2       # Tail logs for node 2"
}

clean_cluster() {
    stop_cluster
    log_info "Cleaning up..."
    rm -rf "$PID_DIR" "$LOG_DIR"
    log_info "Cleaned PID and log directories"
}

# Main
case "${1:-start}" in
    start)
        start_cluster
        ;;
    stop)
        stop_cluster
        ;;
    restart)
        stop_cluster
        sleep 1
        start_cluster
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs "${2:-0}"
        ;;
    build)
        build_binary
        ;;
    clean)
        clean_cluster
        ;;
    -h|--help|help)
        show_usage
        ;;
    *)
        log_error "Unknown command: $1"
        show_usage
        exit 1
        ;;
esac
