#!/usr/bin/env python3
"""Agent-Code Startup Script"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from agent_node import AgentNode
from src.crypto.crypto_utils import CryptoUtils
import time

MY_IP = "192.168.1.88"  
MY_PORT = 8001

if __name__ == "__main__":
    print("Starting Agent-Code...")
    
    agent = AgentNode(
        node_id="agent-code",
        host=MY_IP,
        port=MY_PORT,
        specialty="code-generation",
        inference_time_ms=800
    )
    
    agent.start()
    
    pubkey = CryptoUtils.serialize_public_key(agent.public_key)
    print(f"\n{'='*60}")
    print(f"Agent-Code Started!")
    print(f"{'='*60}")
    print(f"Address: {MY_IP}:{MY_PORT}")
    print(f"Specialty: code-generation")
    print(f"Public Key: {pubkey}")
    print(f"{'='*60}\n")
    
    try:
        while True:
            time.sleep(60)
            agent.print_stats()
    except KeyboardInterrupt:
        print("\nStopping Agent-Code...")
        agent.stop()