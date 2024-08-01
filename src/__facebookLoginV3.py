import requests
import json
import string
import random
import logging
from typing import Dict, Optional, List

"""
Written by Nguyen Minh Huy (RainTee)
Facebook Login V2 - Fixed by Nguyen Minh Huy
Facebook Login V3 - Enhanced and Refactored By DoanDinHoang
Original Date: 28/12/2022
Last Update: 1/8/2024
"""

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class FacebookLoginError(Exception):
    pass

def generate_random_string(length: int) -> str:
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def generate_device_id() -> str:
    return f"{generate_random_string(8)}-{generate_random_string(4)}-{generate_random_string(4)}-{generate_random_string(4)}-{generate_random_string(12)}"

def get_2fa_token(key_2fa: str) -> str:
    try:
        response = requests.get(f"https://2fa.live/tok/{key_2fa.replace(' ', '')}")
        response.raise_for_status()
        return json.loads(response.text)["token"]
    except requests.RequestException as e:
        logging.error(f"Error fetching 2FA token: {e}")
        return str(random.randint(100000, 999999))

class FacebookLogin:
    def __init__(self, username: str, password: str, authentication_code: Optional[str] = None):
        self.device_id = self.ad_id = self.secure_family_device_id = generate_device_id()
        self.machine_id = generate_random_string(24)
        self.username = username
        self.password = password
        self.two_factor_code = authentication_code
        self.headers = self._generate_headers()

    def _generate_headers(self) -> Dict[str, str]:
        return {
            "Host": "b-graph.facebook.com",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Fb-Connection-Type": "unknown",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 7.1.2; SM-G988N Build/NRD90M) [FBAN/FB4A;FBAV/340.0.0.27.113;FBPN/com.facebook.katana;FBLC/vi_VN;FBBV/324485361;FBCR/Viettel Mobile;FBMF/samsung;FBBD/samsung;FBDV/SM-G988N;FBSV/7.1.2;FBCA/x86:armeabi-v7a;FBDM/{density=1.0,width=540,height=960};FB_FW/1;FBRV/0;]",
            "X-Fb-Connection-Quality": "EXCELLENT",
            "Authorization": "OAuth null",
            "X-Fb-Friendly-Name": "authenticate",
            "Accept-Encoding": "gzip, deflate",
            "X-Fb-Server-Cluster": "True"
        }

    def _generate_login_data(self, try_num: int = 1) -> Dict[str, str]:
        return {
            "adid": self.ad_id,
            "format": "json",
            "device_id": self.device_id,
            "email": self.username,
            "password": self.password,
            "generate_analytics_claim": "1",
            "community_id": "",
            "cpl": "true",
            "try_num": str(try_num),
            "family_device_id": self.device_id,
            "secure_family_device_id": self.secure_family_device_id,
            "credentials_type": "password",
            "fb4a_shared_phone_cpl_experiment": "fb4a_shared_phone_nonce_cpl_at_risk_v3",
            "fb4a_shared_phone_cpl_group": "enable_v3_at_risk",
            "enroll_misauth": "false",
            "generate_session_cookies": "1",
            "error_detail_type": "button_with_disabled",
            "source": "login",
            "machine_id": self.machine_id,
            "jazoest": "22421",
            "meta_inf_fbmeta": "",
            "advertiser_id": self.ad_id,
            "encrypted_msisdn": "",
            "currently_logged_in_userid": "0",
            "locale": "vi_VN",
            "client_country_code": "VN",
            "fb_api_req_friendly_name": "authenticate",
            "fb_api_caller_class": "Fb4aAuthHandler",
            "api_key": "882a8490361da98702bf97a021ddc14d",
            "access_token": "350685531728|62f8ce9f74b12f84c123cc23437a4a32"
        }

    def _generate_2fa_data(self, initial_response: Dict[str, Any]) -> Dict[str, str]:
        two_fa_code = get_2fa_token(self.two_factor_code)
        data = self._generate_login_data(try_num=2)
        data.update({
            "password": two_fa_code,
            "twofactor_code": two_fa_code,
            "userid": initial_response["error"]["error_data"]["uid"],
            "first_factor": initial_response["error"]["error_data"]["login_first_factor"],
            "credentials_type": "two_factor"
        })
        return data

    def _extract_cookies(self, response_data: Dict[str, Any]) -> List[str]:
        return [f"{cookie['name']}={cookie['value']}; " for cookie in response_data.get("session_cookies", [])]

    def _handle_login_response(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        if "error" in response_data:
            if response_data["error"].get("error_subcode") == 1348162:
                if not self.two_factor_code:
                    raise FacebookLoginError("Two-factor authentication required but no code provided")
                two_fa_data = self._generate_2fa_data(response_data)
                two_fa_response = self._send_request(two_fa_data)
                return self._handle_login_response(two_fa_response)
            else:
                raise FacebookLoginError(response_data["error"].get("error_user_msg", "Unknown error occurred"))
        
        cookies = self._extract_cookies(response_data)
        return {
            "success": {
                "setCookies": "".join(cookies),
                "accessTokenFB": response_data["access_token"],
                "cookiesKey-ValueList": response_data["session_cookies"]
            }
        }

    def _send_request(self, data: Dict[str, str]) -> Dict[str, Any]:
        try:
            response = requests.post("https://b-graph.facebook.com/auth/login", data=data, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logging.error(f"Request failed: {e}")
            raise FacebookLoginError("Failed to connect to Facebook servers")

    def login(self) -> Dict[str, Any]:
        try:
            initial_data = self._generate_login_data()
            response_data = self._send_request(initial_data)
            return self._handle_login_response(response_data)
        except FacebookLoginError as e:
            logging.error(f"Login failed: {e}")
            return {"error": {"description": str(e)}}
        except Exception as e:
            logging.exception("Unexpected error occurred")
            return {"error": {"description": "An unexpected error occurred"}}

# example (mẫu)
# if __name__ == "__main__":
#     fb_login = FacebookLogin("your_username", "your_password", "your_2fa_code_if_needed")
#     result = fb_login.login()
#     print(json.dumps(result, indent=2))
		"""
✓Remake by Nguyễn Minh Huy | Đoàn Đình Hoàng
✓Sửa đổi mới nhất vào thứ vào lúc 12:27 1/08/2024
✓Tôn trọng tác giả ❤️
"""
