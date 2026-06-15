#!/usr/bin/env bash
# FucyFuzz — vcan0 quick-setup script
# Run once per boot (or after reboot) to create the virtual CAN interface.
# Usage:  sudo bash setup_vcan.sh [interface_name]
#
# Default interface: vcan0

IFACE="${1:-vcan0}"

echo "=== FucyFuzz vcan Setup ==="
echo "Setting up virtual CAN interface: $IFACE"

# Load the vcan kernel module
if ! lsmod | grep -q "^vcan"; then
    echo "[1/3] Loading vcan kernel module..."
    modprobe vcan
    if [ $? -ne 0 ]; then
        echo "ERROR: modprobe vcan failed. Is this a Linux system with kernel CAN support?"
        exit 1
    fi
fi

# Create the interface (ignore if already exists)
if ! ip link show "$IFACE" > /dev/null 2>&1; then
    echo "[2/3] Creating interface $IFACE..."
    ip link add dev "$IFACE" type vcan
    if [ $? -ne 0 ]; then
        echo "ERROR: Could not create $IFACE"
        exit 1
    fi
else
    echo "[2/3] Interface $IFACE already exists."
fi

# Bring it up
echo "[3/3] Bringing up $IFACE..."
ip link set up "$IFACE"
if [ $? -ne 0 ]; then
    echo "ERROR: Could not set $IFACE up"
    exit 1
fi

echo ""
echo "SUCCESS: $IFACE is now UP and ready."
echo ""
ip link show "$IFACE"
echo ""
echo "Tip: You can verify with:  ip link show $IFACE"
echo "     Or listen to frames:  candump $IFACE"
