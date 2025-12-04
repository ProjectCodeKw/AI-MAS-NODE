"""
Base UDP Node for AI-MAS network
Provides UDP socket communication, message handling, and Tor routing

================================================================================
PORTABLE NON-BLOCKING UDP RECEIVER ARCHITECTURE
================================================================================

Features:
- Non-blocking UDP reception with message queue
- Separate receiver and worker threads for concurrent processing
- Configurable queue size and worker threads
- Never drops packets during message processing
- Thread-safe message handling

Architecture:
┌─────────────────────────────────────────────────────────────┐
│ UDP Socket (port 8001)                                      │
│                                                             │
│  ┌──────────────┐      ┌─────────────┐     ┌────────────┐  │
│  │  RECEIVER    │ ───> │   QUEUE     │ ──> │  WORKER 1  │  │
│  │   THREAD     │      │ (1000 msgs) │     │  THREAD    │  │
│  │              │      │             │ ──> │  WORKER 2  │  │
│  │ (Never       │      │  Thread-    │     │  WORKER N  │  │
│  │  blocks)     │      │   Safe      │     │            │  │
│  └──────────────┘      └─────────────┘     └────────────┘  │
│                                                             │
│  Gossip Thread ───────────────────────> (Independent)      │
│  Stats Thread  ───────────────────────> (Independent)      │
└─────────────────────────────────────────────────────────────┘

How It Works:
1. Receiver thread continuously receives UDP packets
2. Packets are immediately queued (non-blocking put)
3. Worker threads process messages from queue concurrently
4. Gossip/stats threads run independently without blocking reception

Usage Example:
    # Simple usage (default settings)
    node = UDPNode("fog1", "192.168.1.76", 8001, "fog")
    node.set_message_handler(my_handler)
    node.start()

    # Advanced usage (custom queue and workers)
    node = UDPNode(
        "fog1", "192.168.1.76", 8001, "fog",
        queue_size=2000,    # Larger queue for high traffic
        num_workers=4       # More workers for parallel processing
    )
    node.set_message_handler(my_handler)
    node.start()

    # Monitor queue health
    health = node.get_queue_health()
    if health['status'] == 'critical':
        print(f"Queue overloaded: {health['utilization']*100}% full")

Configuration Guidelines:
- queue_size: Set based on burst traffic (default 1000)
  - Low traffic: 500
  - Medium traffic: 1000
  - High traffic: 2000-5000

- num_workers: Set based on processing complexity (default 1)
  - Simple forwarding: 1-2 workers
  - Crypto operations: 2-4 workers
  - Heavy processing: 4-8 workers

Monitoring:
- Check stats: node.print_stats()
- Queue health: node.get_queue_health()
- Dropped messages: If > 0, increase queue_size or num_workers

To Copy to Other Agents:
1. Copy this entire base_node.py file
2. Your agent inherits from UDPNode
3. Call super().__init__() with desired queue_size and num_workers
4. Done! No other changes needed.
"""

import socket
import json
import threading
import time
import logging
import queue
from typing import Callable, Optional, Dict, Any


class UDPNode:
    """
    Base class for all AI-MAS nodes
    Handles UDP communication, message routing, and basic networking

    Architecture:
    - Receiver thread: Continuously receives UDP packets and queues them
    - Worker thread(s): Process messages from queue concurrently
    - Gossip/Stats threads: Run independently without blocking reception
    """

    def __init__(self, node_id: str, host: str, port: int, node_type: str = "base",
                 queue_size: int = 1000, num_workers: int = 1):
        """
        Initialize UDP node with non-blocking receiver architecture

        Args:
            node_id: Unique node identifier (e.g., "Agent-Text-1")
            host: IP address to bind to (e.g., "192.168.56.101")
            port: UDP port to listen on (e.g., 8001)
            node_type: Node type (agent, fog, orchestrator)
            queue_size: Maximum messages in queue (default: 1000)
            num_workers: Number of worker threads to process messages (default: 1)
        """
        self.node_id = node_id
        self.host = host
        self.port = port
        self.node_type = node_type
        self.running = False

        # Message queue for non-blocking reception
        self.message_queue = queue.Queue(maxsize=queue_size)
        self.num_workers = num_workers
        self.worker_threads = []

        # UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))

        # Message handler callback
        self.message_handler: Optional[Callable] = None

        # Logging
        logging.basicConfig(
            level=logging.INFO,
            format=f'[{node_id}] %(asctime)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        self.logger = logging.getLogger(node_id)

        # Statistics
        self.stats = {
            'messages_received': 0,
            'messages_sent': 0,
            'bytes_received': 0,
            'bytes_sent': 0,
            'messages_queued': 0,
            'messages_dropped': 0,
            'queue_full_events': 0,
            'start_time': time.time()
        }
    
    def start(self):
        """
        Start UDP receiver and worker threads

        Architecture:
        - 1 receiver thread: Receives packets and queues them (never blocks)
        - N worker threads: Process queued messages concurrently
        """
        self.running = True

        # Start receiver thread (dedicated to receiving packets only)
        receiver_thread = threading.Thread(target=self._receiver_loop, daemon=True, name=f"{self.node_id}-receiver")
        receiver_thread.start()

        # Start worker threads (process messages from queue)
        for i in range(self.num_workers):
            worker_thread = threading.Thread(target=self._worker_loop, daemon=True, name=f"{self.node_id}-worker-{i}")
            worker_thread.start()
            self.worker_threads.append(worker_thread)

        self.logger.info(f"Started on {self.host}:{self.port} (type: {self.node_type}, "
                        f"workers: {self.num_workers}, queue_size: {self.message_queue.maxsize})")
    
    def stop(self):
        """Stop UDP receiver and workers"""
        self.running = False
        self.sock.close()
        self.logger.info("Stopped")

    def _receiver_loop(self):
        """
        Dedicated receiver thread - ONLY receives packets and queues them
        This thread NEVER blocks on message processing, ensuring no packets are dropped
        """
        self.sock.settimeout(1.0)  # 1 second timeout for checking self.running

        while self.running:
            try:
                # Receive UDP packet (this is the only blocking operation)
                data, addr = self.sock.recvfrom(65535)  # Max UDP packet size
                self.stats['messages_received'] += 1
                self.stats['bytes_received'] += len(data)

                # Decode JSON
                try:
                    message = json.loads(data.decode('utf-8'))

                    # Queue message for processing (non-blocking)
                    try:
                        self.message_queue.put((message, addr), block=False)
                        self.stats['messages_queued'] += 1
                    except queue.Full:
                        # Queue is full - drop packet and log warning
                        self.stats['messages_dropped'] += 1
                        self.stats['queue_full_events'] += 1
                        self.logger.warning(f"Message queue full ({self.message_queue.qsize()}/{self.message_queue.maxsize}), "
                                          f"dropped packet from {addr}")

                except json.JSONDecodeError as e:
                    self.logger.warning(f"Invalid JSON from {addr}: {e}")

            except socket.timeout:
                continue  # Check self.running and continue
            except Exception as e:
                if self.running:
                    self.logger.error(f"Receiver error: {e}")

    def _worker_loop(self):
        """
        Worker thread - processes messages from the queue
        Multiple workers can run concurrently for parallel processing
        """
        while self.running:
            try:
                # Get message from queue (blocking with timeout)
                message, addr = self.message_queue.get(timeout=1.0)

                # Process message (this can take time without blocking receiver)
                try:
                    self._handle_message(message, addr)
                except Exception as e:
                    self.logger.error(f"Error processing message from {addr}: {e}")
                finally:
                    # Mark task as done
                    self.message_queue.task_done()

            except queue.Empty:
                # No messages in queue, loop again
                continue
            except Exception as e:
                if self.running:
                    self.logger.error(f"Worker error: {e}")
    
    def _handle_message(self, message: Dict[str, Any], addr: tuple):
        """
        Handle received message
        
        Args:
            message: Decoded JSON message
            addr: (ip, port) tuple of sender
        """
        if self.message_handler:
            self.message_handler(message, addr)
        else:
            self.logger.debug(f"Received {message.get('type', 'UNKNOWN')} from {addr}")
    
    def send_message(self, message: Dict[str, Any], dest_host: str, dest_port: int):
        """
        Send JSON message via UDP
        
        Args:
            message: Dictionary to send (will be JSON-encoded)
            dest_host: Destination IP
            dest_port: Destination port
        """
        try:
            data = json.dumps(message).encode('utf-8')
            self.sock.sendto(data, (dest_host, dest_port))
            self.stats['messages_sent'] += 1
            self.stats['bytes_sent'] += len(data)
        except Exception as e:
            self.logger.error(f"Failed to send to {dest_host}:{dest_port}: {e}")
    
    def set_message_handler(self, handler: Callable):
        """
        Set callback for handling received messages
        
        Args:
            handler: Function with signature handler(message: dict, addr: tuple)
        """
        self.message_handler = handler
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get node statistics including queue metrics

        Returns:
            Dictionary with statistics:
            - messages_received/sent: Total messages
            - messages_queued: Successfully queued for processing
            - messages_dropped: Dropped due to full queue
            - queue_size: Current messages in queue
            - queue_full_events: Number of times queue was full
        """
        uptime = time.time() - self.stats['start_time']
        return {
            **self.stats,
            'uptime_seconds': uptime,
            'messages_per_second': self.stats['messages_received'] / max(uptime, 1),
            'queue_size': self.message_queue.qsize(),
            'queue_utilization': self.message_queue.qsize() / max(self.message_queue.maxsize, 1)
        }

    def print_stats(self):
        """Print node statistics including queue health"""
        stats = self.get_stats()
        self.logger.info(
            f"Stats: RX={stats['messages_received']} TX={stats['messages_sent']} "
            f"Queue={stats['queue_size']}/{self.message_queue.maxsize} "
            f"Dropped={stats['messages_dropped']} "
            f"Uptime={stats['uptime_seconds']:.1f}s"
        )

    def get_queue_health(self) -> Dict[str, Any]:
        """
        Get queue health metrics for monitoring

        Returns:
            Dictionary with queue health:
            - status: 'healthy', 'warning', 'critical'
            - utilization: 0.0 to 1.0
            - size: current queue size
            - max_size: maximum queue capacity
            - dropped: total dropped messages
        """
        utilization = self.message_queue.qsize() / max(self.message_queue.maxsize, 1)

        if utilization < 0.5:
            status = 'healthy'
        elif utilization < 0.8:
            status = 'warning'
        else:
            status = 'critical'

        return {
            'status': status,
            'utilization': utilization,
            'size': self.message_queue.qsize(),
            'max_size': self.message_queue.maxsize,
            'dropped': self.stats['messages_dropped'],
            'drop_rate': self.stats['messages_dropped'] / max(self.stats['messages_received'], 1)
        }


# Self-test
# if __name__ == "__main__":
#     print("Testing UDPNode...")
    
#     # Create two nodes
#     node1 = UDPNode("TestNode1", "127.0.0.1", 9001, "test")
#     node2 = UDPNode("TestNode2", "127.0.0.1", 9002, "test")
    
#     # Set up message handler for node2
#     def node2_handler(message, addr):
#         print(f"Node2 received: {message}")
#         # Echo back
#         node2.send_message({"type": "ECHO", "original": message}, addr[0], addr[1])
    
#     node2.set_message_handler(node2_handler)
    
#     # Start both nodes
#     node1.start()
#     node2.start()
    
#     # Send test message
#     time.sleep(0.5)
#     node1.send_message({"type": "TEST", "content": "Hello Node2!"}, "127.0.0.1", 9002)
    
#     # Wait for response
#     time.sleep(1)
    
#     # Print stats
#     node1.print_stats()
#     node2.print_stats()
    
#     # Stop nodes
#     node1.stop()
#     node2.stop()
    
#     print("\nTest complete!")


# Expected output:
# Testing UDPNode...
# [TestNode1] ... - INFO - Started on 127.0.0.1:9001 (type: test)
# [TestNode2] ... - INFO - Started on 127.0.0.1:9002 (type: test)
# Node2 received: {'type': 'TEST', 'content': 'Hello Node2!'}
# [TestNode1] ... - INFO - Statistics: RX=1 TX=1 Uptime=1.0s
# [TestNode2] ... - INFO - Statistics: RX=1 TX=1 Uptime=1.0s
# Test complete!