#!/usr/bin/env python3
"""
Start BlackLoom Defense API server and run tests
"""

import subprocess
import time
import requests
import sys
import os
import signal


def is_server_running(url="http://localhost:8000"):
 """Check if server is already running"""
 try:
 response = requests.get(f"{url}/health", timeout=2)
 return response.status_code == 200
 except:
 return False


def start_server():
 """Start the API server"""
 print(" Starting BlackLoom Defense API server...")

 # Start server in background
 server_process = subprocess.Popen([
 sys.executable, "-m", "blackloom_defense.api.gateway"
 ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

 print(" Server starting...")

 # Wait for server to be ready
 for i in range(30): # Wait up to 30 seconds
 if is_server_running():
 print(" Server is ready!")
 return server_process
 time.sleep(1)
 print(f" Waiting for server... ({i+1}/30)")

 print(" Server failed to start within 30 seconds")
 server_process.terminate()
 return None


def run_tests():
 """Run the API tests"""
 print("\n Running API tests...")

 # Import and run the test function
 sys.path.insert(0, os.path.dirname(__file__))
 from test_api import test_api_endpoint

 return test_api_endpoint()


def main():
 server_process = None

 try:
 # Check if server is already running
 if is_server_running():
 print(" Server already running at http://localhost:8000")
 run_tests()
 else:
 # Start server
 server_process = start_server()

 if server_process:
 # Run tests
 success = run_tests()

 if success:
 print("\n Would you like to keep the server running for manual testing?")
 print(" Server is at: http://localhost:8000")
 print(" API docs at: http://localhost:8000/docs")
 print(" Press Ctrl+C to stop the server")

 try:
 # Keep server running
 server_process.wait()
 except KeyboardInterrupt:
 print("\n🛑 Shutting down server...")
 else:
 print(" Tests failed")
 else:
 print(" Could not start server")
 return 1

 except KeyboardInterrupt:
 print("\n🛑 Interrupted by user")

 finally:
 # Clean up server process
 if server_process and server_process.poll() is None:
 print(" Cleaning up server process...")
 server_process.terminate()
 time.sleep(1)
 if server_process.poll() is None:
 server_process.kill()

 return 0


if __name__ == "__main__":
 exit(main())