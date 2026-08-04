"""
完美校园 - 余额轮询监控
检测余额变化时通过 Gmail 发送通知邮件
支持从环境变量读取凭据（GitHub Actions）或本地配置文件
"""
import json
import os
import sys
import hashlib
import random
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "campus_card"))
from campus_card import des_3, rsa_encrypt as rsa

# ── 配置 ──────────────────────────────────────────────
HOST = "https://app.59wanmei.com/campus/cam_iface46"
CARD_HOST = "https://server.17wanxiao.com/YKT_Interface/xyk"
WANXIAO_VERSION = 10552101
UA = "Dalvik/2.1.0 (Linux; U; Android 12; LGE-AN10 Build/HUAWEI)"
LAST_BALANCE_FILE = "last_balance.json"
DEVICE_FILE_TEMPLATE = "{phone}.device"
CONFIG_FILE = "config.json"

# QQ邮箱 SMTP
SMTP_SERVER = "smtp.qq.com"
SMTP_PORT = 587
RECEIVER_EMAIL = "aweizihao@gmail.com"  # 接收通知的邮箱

# ── 加密工具 ──────────────────────────────────────────
def _encrypt(obj, app_key: str) -> str:
    return des_3.object_encrypt(obj, app_key)

def _decrypt(s: str, app_key: str) -> dict:
    return json.loads(des_3.des_3_decode(s.replace("\n", ""), app_key, "66666666"))

def _sign(payload: dict) -> str:
    return hashlib.sha256(json.dumps(payload).encode()).hexdigest()

def _api_call(endpoint: str, payload: dict, session_id: str, app_key: str) -> dict:
    body = {"session": session_id, "data": _encrypt(payload, app_key)}
    return requests.post(
        HOST + endpoint,
        headers={"campusSign": _sign(body), "User-Agent": UA},
        json=body, verify=False, timeout=15,
    ).json()

# ── 凭据加载 ──────────────────────────────────────────
def load_credentials():
    phone = os.getenv("WANXIAO_PHONE")
    password = os.getenv("WANXIAO_PASSWORD")
    mail_user = os.getenv("MAIL_USER")
    mail_pass = os.getenv("MAIL_PASS")

    if phone and password:
        return phone, password, mail_user, mail_pass

    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        return cfg["phone"], cfg["password"], cfg.get("mail_user"), cfg.get("mail_pass")

    raise RuntimeError(f"未找到凭据。请设置环境变量或创建 {CONFIG_FILE}")

# ── 设备持久化 ────────────────────────────────────────
def load_device(phone: str) -> dict:
    path = DEVICE_FILE_TEMPLATE.format(phone=phone)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.loads(f.read())
    return {"deviceId": str(random.randint(999999999999999, 9999999999999999)), "verified": False}

def save_device(phone: str, dev: dict):
    path = DEVICE_FILE_TEMPLATE.format(phone=phone)
    saveable = {"deviceId": dev["deviceId"], "verified": dev.get("verified", False)}
    if "rsaPublic" in dev:
        saveable["rsaPublic"] = dev["rsaPublic"]
        saveable["rsaPrivate"] = dev["rsaPrivate"]
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(saveable, ensure_ascii=False))

# ── 密钥交换 ──────────────────────────────────────────
def exchange_secret(rsa_public: str | None = None, rsa_private: str | None = None):
    if not rsa_public or not rsa_private:
        pub, priv = rsa.create_key_pair(1024)
    else:
        pub, priv = rsa_public, rsa_private
    resp = requests.post(
        HOST + "/exchangeSecretkey.action",
        headers={"User-Agent": UA},
        json={"key": pub}, verify=False, timeout=15,
    )
    info = json.loads(rsa.rsa_decrypt(resp.text.encode(resp.apparent_encoding), priv))
    return {"sessionId": info["session"], "appKey": info["key"][:24], "rsaPublic": pub, "rsaPrivate": priv}

# ── 密码登录 ──────────────────────────────────────────
def password_login(phone: str, password: str, dev: dict) -> tuple[bool, dict, str]:
    secret = exchange_secret(dev.get("rsaPublic"), dev.get("rsaPrivate"))
    pwd_list = [des_3.des_3_encrypt(c, secret["appKey"], "66666666") for c in password]
    args = {
        "appCode": "M002", "deviceId": dev["deviceId"], "netWork": "wifi",
        "password": pwd_list, "qudao": "tencent",
        "requestMethod": "cam_iface46/loginnew.action",
        "shebeixinghao": "LGE-AN10", "systemType": "android",
        "telephoneInfo": "12", "telephoneModel": "LGE-AN10",
        "type": "1", "userName": phone,
        "wanxiaoVersion": WANXIAO_VERSION, "yunyingshang": "07",
    }
    result = _api_call("/loginnew.action", args, secret["sessionId"], secret["appKey"])
    if result.get("result_"):
        secret["deviceId"] = dev["deviceId"]
        secret["verified"] = True
        return True, secret, ""
    return False, secret, result.get("message_", "登录失败")

# ── 校园卡查询 ────────────────────────────────────────
def get_card_info(session_id: str) -> dict:
    resp = requests.post(
        CARD_HOST,
        headers={
            "User-Agent": "Mozilla/5.0 (Linux; Android 12; LGE-AN10; wv) AppleWebKit/537.36 Wanxiao/10.5.5",
            "Origin": "https://server.17wanxiao.com",
        },
        data={"token": session_id, "method": "XYK_BASE_INFO", "param": "{}"},
        verify=False, timeout=15,
    )
    return json.loads(resp.json()["body"])

# ── 邮件发送 ──────────────────────────────────────────
def send_email(subject: str, body: str, mail_user: str, mail_pass: str):
    if not mail_user or not mail_pass:
        print("[!] 未配置邮箱凭据，跳过邮件发送")
        return

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = mail_user
    msg["To"] = RECEIVER_EMAIL

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=15)
        server.starttls()
        server.login(mail_user, mail_pass)
        server.sendmail(mail_user, [RECEIVER_EMAIL], msg.as_string())
        server.quit()
        print("[+] 邮件已发送")
    except Exception as e:
        print(f"[!] 邮件发送失败: {e}")

# ── 余额记录 ──────────────────────────────────────────
def load_last_balance() -> dict:
    if os.path.exists(LAST_BALANCE_FILE):
        with open(LAST_BALANCE_FILE, "r", encoding="utf-8") as f:
            return json.loads(f.read())
    return {}

def save_last_balance(data: dict):
    with open(LAST_BALANCE_FILE, "w", encoding="utf-8") as f:
        f.write(json.dumps(data, ensure_ascii=False, indent=2))

# ── 主流程 ────────────────────────────────────────────
def main():
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 余额监控启动")

    phone, password, mail_user, mail_pass = load_credentials()
    dev = load_device(phone)

    print(f"[*] 登录 {phone} ...")
    ok, dev, msg = password_login(phone, password, dev)
    if not ok:
        print(f"[!] 登录失败: {msg}")
        sys.exit(1)

    save_device(phone, dev)
    print(f"[+] 登录成功")

    try:
        info = get_card_info(dev["sessionId"])
    except Exception as e:
        print(f"[!] 查询余额失败: {e}")
        sys.exit(1)

    name = info.get("name", "?")
    card_no = info.get("cardNo", "?")
    main_fare = info.get("mainFare", 0)
    subsidy_fare = info.get("subsidyFare", 0)
    total = main_fare + subsidy_fare

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"  姓名: {name}  卡号: {card_no}")
    print(f"  主钱包: {main_fare}  补助: {subsidy_fare}  合计: {total}")

    last = load_last_balance()
    last_total = last.get("total")
    last_main = last.get("mainFare")

    current_data = {
        "last_update": now_str,
        "name": name,
        "cardNo": card_no,
        "mainFare": main_fare,
        "subsidyFare": subsidy_fare,
        "total": total,
    }

    if last_total is None:
        print("[*] 首次记录余额")
        save_last_balance(current_data)
        return

    if total != last_total:
        diff = total - last_total
        direction = "增加" if diff > 0 else "减少"
        change_msg = (
            f"校园卡余额变动通知\n"
            f"==================\n"
            f"姓名: {name}\n"
            f"卡号: {card_no}\n"
            f"时间: {now_str}\n\n"
            f"上次余额: {last_total:.2f}\n"
            f"当前余额: {total:.2f}\n"
            f"变动: {direction} {abs(diff):.2f}\n\n"
            f"明细:\n"
            f"  主钱包: {main_fare:.2f} (变动 {'+' if main_fare - (last_main or 0) >= 0 else ''}{main_fare - (last_main or 0):.2f})\n"
            f"  补助钱包: {subsidy_fare:.2f}\n"
        )

        print(f"\n[!] 余额变动: {direction} {abs(diff):.2f}")
        send_email(f"[校园卡] 余额变动 - {direction} {abs(diff):.2f}", change_msg, mail_user, mail_pass)

        save_last_balance(current_data)
    else:
        print(f"[*] 余额未变化 ({total:.2f})")


if __name__ == "__main__":
    main()
