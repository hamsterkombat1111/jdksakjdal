#!/usr/bin/env python3
"""
PrankVZ Backend API Testing Suite
Tests all backend endpoints including Telegram integration
"""

import requests
import sys
import json
from datetime import datetime
import time

class PrankVZAPITester:
    def __init__(self, base_url="https://a3ea4ced-6820-47f9-b056-a84403c4cb11.preview.emergentagent.com"):
        self.base_url = base_url
        self.token = None
        self.tests_run = 0
        self.tests_passed = 0
        self.session = requests.Session()
        
    def log_result(self, test_name, success, details=""):
        """Log test result"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {test_name} - PASSED {details}")
        else:
            print(f"❌ {test_name} - FAILED {details}")
        return success

    def test_root_endpoint(self):
        """Test root endpoint"""
        try:
            response = self.session.get(f"{self.base_url}/")
            success = response.status_code == 200
            details = f"Status: {response.status_code}"
            if success:
                data = response.json()
                details += f" | Response: {data.get('message', 'No message')}"
            return self.log_result("Root Endpoint", success, details)
        except Exception as e:
            return self.log_result("Root Endpoint", False, f"Error: {str(e)}")

    def test_visit_logging(self):
        """Test visit logging endpoint - should trigger Telegram message"""
        try:
            response = self.session.get(f"{self.base_url}/api/visit")
            success = response.status_code == 200
            details = f"Status: {response.status_code}"
            if success:
                data = response.json()
                details += f" | Response: {data.get('status', 'No status')}"
                print("   📱 This should have sent a Telegram message to the channel")
            return self.log_result("Visit Logging", success, details)
        except Exception as e:
            return self.log_result("Visit Logging", False, f"Error: {str(e)}")

    def test_login(self):
        """Test admin login"""
        try:
            login_data = {
                "username": "admin",
                "password": "qwerqwer"
            }
            response = self.session.post(f"{self.base_url}/api/login", json=login_data)
            success = response.status_code == 200
            details = f"Status: {response.status_code}"
            
            if success:
                data = response.json()
                self.token = data.get('token')
                details += f" | User: {data.get('username')} | Role: {data.get('role')}"
                if self.token:
                    details += " | Token received"
                    # Set authorization header for future requests
                    self.session.headers.update({'Authorization': f'Bearer {self.token}'})
            
            return self.log_result("Admin Login", success, details)
        except Exception as e:
            return self.log_result("Admin Login", False, f"Error: {str(e)}")

    def test_get_admins(self):
        """Test getting admins list (public endpoint)"""
        try:
            response = self.session.get(f"{self.base_url}/api/admins")
            success = response.status_code == 200
            details = f"Status: {response.status_code}"
            
            if success:
                data = response.json()
                details += f" | Found {len(data)} admins"
                
            return self.log_result("Get Admins List", success, details)
        except Exception as e:
            return self.log_result("Get Admins List", False, f"Error: {str(e)}")

    def test_create_admin(self):
        """Test creating new admin (requires auth)"""
        if not self.token:
            return self.log_result("Create Admin", False, "No auth token available")
            
        try:
            admin_data = {
                "name": f"Test Admin {int(time.time())}",
                "telegram_handle": f"testadmin{int(time.time())}"
            }
            response = self.session.post(f"{self.base_url}/api/admins", json=admin_data)
            success = response.status_code == 200
            details = f"Status: {response.status_code}"
            
            if success:
                data = response.json()
                details += f" | Created admin: {data.get('name')} (@{data.get('telegram_handle')})"
                # Store admin ID for potential cleanup
                self.test_admin_id = data.get('id')
                
            return self.log_result("Create Admin", success, details)
        except Exception as e:
            return self.log_result("Create Admin", False, f"Error: {str(e)}")

    def test_get_blocked_ips(self):
        """Test getting blocked IPs (requires auth)"""
        if not self.token:
            return self.log_result("Get Blocked IPs", False, "No auth token available")
            
        try:
            response = self.session.get(f"{self.base_url}/api/blocked-ips")
            success = response.status_code == 200
            details = f"Status: {response.status_code}"
            
            if success:
                data = response.json()
                details += f" | Found {len(data)} blocked IPs"
                
            return self.log_result("Get Blocked IPs", success, details)
        except Exception as e:
            return self.log_result("Get Blocked IPs", False, f"Error: {str(e)}")

    def test_block_ip(self):
        """Test blocking an IP address (requires auth)"""
        if not self.token:
            return self.log_result("Block IP", False, "No auth token available")
            
        try:
            block_data = {
                "ip": "192.168.1.100",  # Test IP
                "reason": "Test blocking from API test"
            }
            response = self.session.post(f"{self.base_url}/api/block-ip", json=block_data)
            success = response.status_code == 200
            details = f"Status: {response.status_code}"
            
            if success:
                data = response.json()
                details += f" | Blocked IP: {data.get('ip')} | Reason: {data.get('reason')}"
                # Store blocked IP ID for cleanup
                self.test_blocked_ip_id = data.get('id')
                
            return self.log_result("Block IP", success, details)
        except Exception as e:
            return self.log_result("Block IP", False, f"Error: {str(e)}")

    def test_get_logs(self):
        """Test getting visit logs (requires auth)"""
        if not self.token:
            return self.log_result("Get Visit Logs", False, "No auth token available")
            
        try:
            response = self.session.get(f"{self.base_url}/api/logs")
            success = response.status_code == 200
            details = f"Status: {response.status_code}"
            
            if success:
                data = response.json()
                details += f" | Found {len(data)} log entries"
                if len(data) > 0:
                    latest_log = data[0]
                    details += f" | Latest: {latest_log.get('ip')} at {latest_log.get('timestamp')}"
                
            return self.log_result("Get Visit Logs", success, details)
        except Exception as e:
            return self.log_result("Get Visit Logs", False, f"Error: {str(e)}")

    def test_invalid_login(self):
        """Test login with invalid credentials"""
        try:
            login_data = {
                "username": "invalid",
                "password": "invalid"
            }
            response = self.session.post(f"{self.base_url}/api/login", json=login_data)
            success = response.status_code == 401  # Should fail with 401
            details = f"Status: {response.status_code} (Expected 401)"
            
            return self.log_result("Invalid Login Test", success, details)
        except Exception as e:
            return self.log_result("Invalid Login Test", False, f"Error: {str(e)}")

    def test_unauthorized_access(self):
        """Test accessing protected endpoints without auth"""
        # Temporarily remove auth header
        temp_headers = self.session.headers.copy()
        if 'Authorization' in self.session.headers:
            del self.session.headers['Authorization']
        
        try:
            response = self.session.get(f"{self.base_url}/api/blocked-ips")
            success = response.status_code == 403  # Should fail with 403
            details = f"Status: {response.status_code} (Expected 403)"
            
            result = self.log_result("Unauthorized Access Test", success, details)
            
            # Restore headers
            self.session.headers = temp_headers
            return result
        except Exception as e:
            # Restore headers
            self.session.headers = temp_headers
            return self.log_result("Unauthorized Access Test", False, f"Error: {str(e)}")

    def cleanup_test_data(self):
        """Clean up test data created during testing"""
        if not self.token:
            return
            
        print("\n🧹 Cleaning up test data...")
        
        # Clean up test admin if created
        if hasattr(self, 'test_admin_id') and self.test_admin_id:
            try:
                response = self.session.delete(f"{self.base_url}/api/admins/{self.test_admin_id}")
                if response.status_code == 200:
                    print("   ✅ Test admin deleted")
                else:
                    print(f"   ⚠️ Failed to delete test admin: {response.status_code}")
            except Exception as e:
                print(f"   ⚠️ Error deleting test admin: {e}")
        
        # Clean up test blocked IP if created
        if hasattr(self, 'test_blocked_ip_id') and self.test_blocked_ip_id:
            try:
                response = self.session.delete(f"{self.base_url}/api/blocked-ips/{self.test_blocked_ip_id}")
                if response.status_code == 200:
                    print("   ✅ Test blocked IP removed")
                else:
                    print(f"   ⚠️ Failed to remove test blocked IP: {response.status_code}")
            except Exception as e:
                print(f"   ⚠️ Error removing test blocked IP: {e}")

    def run_all_tests(self):
        """Run all API tests"""
        print("🚀 Starting PrankVZ Backend API Tests")
        print(f"🌐 Testing against: {self.base_url}")
        print("=" * 60)
        
        # Basic connectivity tests
        self.test_root_endpoint()
        self.test_visit_logging()  # This should trigger Telegram message
        
        # Authentication tests
        self.test_invalid_login()
        self.test_login()
        
        # Public endpoints
        self.test_get_admins()
        
        # Protected endpoints (require auth)
        self.test_unauthorized_access()
        self.test_get_blocked_ips()
        self.test_get_logs()
        self.test_create_admin()
        self.test_block_ip()
        
        # Cleanup
        self.cleanup_test_data()
        
        # Results summary
        print("\n" + "=" * 60)
        print(f"📊 Test Results: {self.tests_passed}/{self.tests_run} tests passed")
        
        if self.tests_passed == self.tests_run:
            print("🎉 All tests passed!")
            return 0
        else:
            print(f"⚠️ {self.tests_run - self.tests_passed} tests failed")
            return 1

def main():
    """Main test runner"""
    tester = PrankVZAPITester()
    return tester.run_all_tests()

if __name__ == "__main__":
    sys.exit(main())