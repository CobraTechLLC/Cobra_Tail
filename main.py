import os
import sys
import time
import struct

CHUNK_SIZE = 32          # 256 bits per burst
STREAM_DELAY = 0.01      # 10ms between chunks (~3.2 KB/s throughput)
HEALTH_INTERVAL = 10     # Health beacon every 10 seconds
STARTUP_DELAY = 3        # Wait for USB connection to stabilize

# Frame markers
SYNC_BYTE = 0xAA         # Entropy frame starts with this

def stream_entropy():
    total_bytes = 0
    last_health = time.time()

    # Give the USB-CDC link time to stabilize before writing anything
    time.sleep(STARTUP_DELAY)

    # Signal the Vault that we're alive and about to stream
    print("STATUS: TONGUE_READY")
    time.sleep(0.5)
    print("STATUS: ENTROPY_STREAM_START")
    time.sleep(0.5)

    while True:
        # Pull 32 bytes of raw hardware entropy
        # On ESP32-S3, os.urandom() calls the hardware TRNG directly
        raw_bits = os.urandom(CHUNK_SIZE)

        # Write framed entropy: [0xAA] [length high] [length low] [raw bytes]
        header = bytes([SYNC_BYTE]) + struct.pack(">H", CHUNK_SIZE)
        sys.stdout.buffer.write(header + raw_bits)

        total_bytes += CHUNK_SIZE

        # Periodic health beacon so the Vault knows we haven't died
        now = time.time()
        if now - last_health >= HEALTH_INTERVAL:
            print(f"STATUS: HEARTBEAT {total_bytes}")
            last_health = now

        time.sleep(STREAM_DELAY)

if __name__ == "__main__":
    try:
        stream_entropy()
    except KeyboardInterrupt:
        print("STATUS: STREAM_STOPPED")