#!/usr/bin/env python3
"""Agent-Code Startup Script"""
#chmod 600 /home/ai-mas/ai-mas-node/keys/agent-code-private.pem
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from agent_node import AgentNode
from src.crypto.crypto_utils import CryptoUtils
import time

# CHANGE THIS TO YOUR ACTUAL IP
MY_IP = "192.168.1.88"  # <-- PUT YOUR IP HERE
MY_PORT = 8001

if __name__ == "__main__":
    print("Starting Agent-Code...")
    
    agent = AgentNode(
        node_id="Agent-Code",
        host="0.0.0.0",
        port=MY_PORT,
        specialty="code-generation",
        inference_time_ms=800
    )
    
    agent.start()
    
    print(f"\n{'='*60}")
    print(f"Agent-Code Started!")
    print(f"{'='*60}")
    print(f"Address: {MY_IP}:{MY_PORT}")
    print(f"{'='*60}\n")
    print("Press Ctrl+C to stop\n")

    try:
        while True:
            time.sleep(60)
            agent.print_stats()
    except KeyboardInterrupt:
        print("\nStopping...")
        agent.stop()