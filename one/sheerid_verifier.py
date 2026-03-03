"""SheerID 学生验证主程序 — with anti-detection"""
import re
import random
import logging
import time
from typing import Dict, Optional, Tuple

from . import config
from .name_generator import NameGenerator, generate_birth_date
from .img_generator import generate_images, generate_psu_email
from .anti_detect import (
    get_sheerid_headers,
    generate_fingerprint,
    create_session,
    warm_session,
    human_delay,
)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


class SheerIDVerifier:
    """SheerID 学生身份验证器 (anti-detect enhanced)"""

    def __init__(self, verification_id: str, proxy: str = None):
        self.verification_id = verification_id
        self.device_fingerprint = generate_fingerprint()

        # Create anti-detect session (curl_cffi > httpx > requests)
        self.http_client, self.lib_name = create_session(proxy)
        logger.info(f"HTTP library: {self.lib_name}")

        # Warm up session (simulate browser page load)
        warm_session(self.http_client, config.PROGRAM_ID)

    def __del__(self):
        if hasattr(self, "http_client") and hasattr(self.http_client, "close"):
            self.http_client.close()

    @staticmethod
    def normalize_url(url: str) -> str:
        """规范化 URL（保留原样）"""
        return url

    @staticmethod
    def parse_verification_id(url: str) -> Optional[str]:
        match = re.search(r"verificationId=([a-f0-9]+)", url, re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    def _sheerid_request(
        self, method: str, url: str, body: Optional[Dict] = None
    ) -> Tuple[Dict, int]:
        """发送 SheerID API 请求 — with browser-like headers + delays"""
        headers = get_sheerid_headers()

        # Human-like delay between requests
        human_delay(300, 800)

        try:
            # Different libraries use different kwarg names
            try:
                response = self.http_client.request(
                    method=method, url=url, json=body, headers=headers
                )
            except TypeError:
                # Some curl_cffi versions need positional args
                response = self.http_client.request(
                    method, url, json=body, headers=headers
                )

            try:
                data = response.json()
            except Exception:
                data = response.text if hasattr(response, 'text') else str(response)
            return data, response.status_code
        except Exception as e:
            logger.error(f"SheerID 请求失败: {e}")
            raise

    def _upload_to_s3(self, upload_url: str, img_data: bytes) -> bool:
        """上传 PNG 到 S3"""
        attempts = [
            lambda: self.http_client.put(upload_url, content=img_data, headers={"Content-Type": "image/png"}, timeout=60),
            lambda: self.http_client.put(upload_url, data=img_data, headers={"Content-Type": "image/png"}, timeout=60),
            lambda: self.http_client.request("PUT", upload_url, data=img_data, headers={"Content-Type": "image/png"}, timeout=60),
        ]

        for fn in attempts:
            try:
                resp = fn()
                if hasattr(resp, "status_code") and 200 <= resp.status_code < 300:
                    return True
                elif hasattr(resp, "status_code"):
                    logger.warning(f"S3 upload HTTP {resp.status_code}")
                    return False
            except TypeError:
                continue
            except Exception as e:
                logger.error(f"S3 上传失败: {e}")
                return False
        return False

    def verify(
        self,
        first_name: str = None,
        last_name: str = None,
        email: str = None,
        birth_date: str = None,
        school_id: str = None,
    ) -> Dict:
        """执行验证流程"""
        try:
            current_step = "initial"

            if not first_name or not last_name:
                name = NameGenerator.generate()
                first_name = name["first_name"]
                last_name = name["last_name"]

            school_id = school_id or config.get_random_school_id()
            school = config.SCHOOLS[school_id]

            if not email:
                email = generate_psu_email(first_name, last_name, school['domain'])
            if not birth_date:
                birth_date = generate_birth_date()

            logger.info(f"学生信息: {first_name} {last_name}")
            logger.info(f"邮箱: {email}")
            logger.info(f"学校: {school['name']}")
            logger.info(f"生日: {birth_date}")
            logger.info(f"验证 ID: {self.verification_id}")

            # 生成两份文档 (class schedule + enrollment letter)
            logger.info("步骤 1/4: 生成学生文档 (2 份)...")
            assets = generate_images(first_name, last_name, school_id)
            for asset in assets:
                logger.info(f"  ✅ {asset['file_name']} ({len(asset['data']) / 1024:.1f}KB)")

            # 提交学生信息
            logger.info("步骤 2/4: 提交学生信息...")
            step2_body = {
                "firstName": first_name,
                "lastName": last_name,
                "birthDate": birth_date,
                "email": email,
                "phoneNumber": "",
                "organization": {
                    "id": int(school_id),
                    "idExtended": school["idExtended"],
                    "name": school["name"],
                },
                "deviceFingerprintHash": self.device_fingerprint,
                "locale": "en-US",
                "metadata": {
                    "marketConsentValue": False,
                    "refererUrl": f"{config.SHEERID_BASE_URL}/verify/{config.PROGRAM_ID}/?verificationId={self.verification_id}",
                    "verificationId": self.verification_id,
                    "flags": '{"collect-info-step-email-first":"default","doc-upload-considerations":"default","doc-upload-may24":"default","doc-upload-redesign-use-legacy-message-keys":false,"docUpload-assertion-checklist":"default","font-size":"default","include-cvec-field-france-student":"not-labeled-optional"}',
                    "submissionOptIn": "By submitting the personal information above, I acknowledge that my personal information is being collected under the privacy policy of the business from which I am seeking a discount",
                },
            }

            step2_data, step2_status = self._sheerid_request(
                "POST",
                f"{config.SHEERID_BASE_URL}/rest/v2/verification/{self.verification_id}/step/collectStudentPersonalInfo",
                step2_body,
            )

            if step2_status != 200:
                raise Exception(f"步骤 2 失败 (状态码 {step2_status}): {step2_data}")
            if step2_data.get("currentStep") == "error":
                error_msg = ", ".join(step2_data.get("errorIds", ["Unknown error"]))
                raise Exception(f"步骤 2 错误: {error_msg}")

            logger.info(f"✅ 步骤 2 完成: {step2_data.get('currentStep')}")
            current_step = step2_data.get("currentStep", current_step)

            # 跳过 SSO（如需要）
            if current_step in ["sso", "collectStudentPersonalInfo"]:
                logger.info("步骤 3/4: 跳过 SSO 验证...")
                step3_data, _ = self._sheerid_request(
                    "DELETE",
                    f"{config.SHEERID_BASE_URL}/rest/v2/verification/{self.verification_id}/step/sso",
                )
                logger.info(f"✅ 步骤 3 完成: {step3_data.get('currentStep')}")
                current_step = step3_data.get("currentStep", current_step)

            # 上传文档并完成提交 (2 份)
            logger.info("步骤 4/4: 请求上传链接 & 上传文档...")
            files_payload = [
                {"fileName": asset["file_name"], "mimeType": "image/png", "fileSize": len(asset["data"])}
                for asset in assets
            ]
            step4_body = {"files": files_payload}

            step4_data, step4_status = self._sheerid_request(
                "POST",
                f"{config.SHEERID_BASE_URL}/rest/v2/verification/{self.verification_id}/step/docUpload",
                step4_body,
            )
            if not step4_data.get("documents"):
                raise Exception("未能获取上传 URL")

            # Upload each document to S3
            for i, doc in enumerate(step4_data["documents"]):
                upload_url = doc["uploadUrl"]
                logger.info(f"  📤 上传文档 {i+1}/{len(assets)}: {assets[i]['file_name']}")
                if not self._upload_to_s3(upload_url, assets[i]["data"]):
                    raise Exception(f"S3 上传失败: {assets[i]['file_name']}")
                logger.info(f"  ✅ 文档 {i+1} 上传成功")

            step6_data, _ = self._sheerid_request(
                "POST",
                f"{config.SHEERID_BASE_URL}/rest/v2/verification/{self.verification_id}/step/completeDocUpload",
            )
            logger.info(f"✅ 文档提交完成: {step6_data.get('currentStep')}")
            final_status = step6_data

            # 不做状态轮询，直接返回等待审核
            return {
                "success": True,
                "pending": True,
                "message": "文档已提交，等待审核",
                "verification_id": self.verification_id,
                "redirect_url": final_status.get("redirectUrl"),
                "status": final_status,
            }

        except Exception as e:
            logger.error(f"❌ 验证失败: {e}")
            return {"success": False, "message": str(e), "verification_id": self.verification_id}


def main():
    """主函数 - 命令行界面"""
    import sys

    print("=" * 60)
    print("SheerID 学生身份验证工具 (Python版)")
    print("=" * 60)
    print()

    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input("请输入 SheerID 验证 URL: ").strip()

    if not url:
        print("❌ 错误: 未提供 URL")
        sys.exit(1)

    verification_id = SheerIDVerifier.parse_verification_id(url)
    if not verification_id:
        print("❌ 错误: 无效的验证 ID 格式")
        sys.exit(1)

    print(f"✅ 解析到验证 ID: {verification_id}")
    print()

    verifier = SheerIDVerifier(verification_id)
    result = verifier.verify()

    print()
    print("=" * 60)
    print("验证结果:")
    print("=" * 60)
    print(f"状态: {'✅ 成功' if result['success'] else '❌ 失败'}")
    print(f"消息: {result['message']}")
    if result.get("redirect_url"):
        print(f"跳转 URL: {result['redirect_url']}")
    print("=" * 60)

    return 0 if result["success"] else 1


if __name__ == "__main__":
    exit(main())