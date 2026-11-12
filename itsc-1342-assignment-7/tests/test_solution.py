# [Everrett Nguyen] - Assignment 7 Unit Tests
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'code')))
from solution import dissect_packet

# Test 1: Standard TCP SYN handshake packet
pkt1 = dissect_packet("192.168.1.15", "10.0.0.1", "tcp", 64, flags=["SYN"])
assert pkt1["proto"] == "TCP", "Failed Test 1: Protocol must be uppercase"
assert pkt1["syn_flag"] is True, "Failed Test 1: SYN flag check"
assert pkt1["length"] == 64, "Failed Test 1: Length check"

# Test 2: UDP DNS query without flags, negative byte normalization
pkt2 = dissect_packet("10.0.0.1", "8.8.8.8", "UDP", -10)
# Look closely at how the dictionary is checked below:
assert pkt2["dst"] == "8.8.8.8", "Failed Test 2: Check destination address"
assert pkt2["length"] == 0, "Failed Test 2: Negative payload should normalize to 0"
assert pkt2["syn_flag"] is False, "Failed Test 2: SYN flag should be False when flags is None"

# Test 3: TCP ACK packet (no SYN)
pkt3 = dissect_packet("10.0.0.5", "10.0.0.1", "tcp", 120, flags=["ACK"])
assert pkt3["syn_flag"] is False, "Failed Test 3: Flag should be a boolean, not a string"

print("ALL UNIT TESTS PASSED - ASSIGNMENT 7")