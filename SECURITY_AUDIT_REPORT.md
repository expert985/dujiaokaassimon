# 独角数卡(DuJiaoKa)安全审计报告

## 审计信息
- **审计日期**: 2025-10-28
- **系统版本**: DuJiaoKa v2.0.6
- **技术栈**: Laravel 6.x, PHP 7.4+/8.0+, MySQL 5.6+, Redis
- **审计范围**: 应用层安全、认证授权、数据验证、敏感信息保护

---

## 执行摘要

本次安全审计针对独角数卡(DuJiaoKa)开源数字卡密销售系统进行全面的安全评估。该系统是一个基于Laravel 6框架的电子商务平台,集成了12+种支付网关,用于销售数字产品和卡密。

审计共发现 **3个严重漏洞**, **5个中等风险**, **7个低风险** 问题。主要安全问题集中在安装模块、全局变量使用、敏感信息泄露等方面。

### 风险等级分布
- 🔴 **严重 (Critical)**: 3个
- 🟠 **高危 (High)**: 0个
- 🟡 **中危 (Medium)**: 5个
- 🟢 **低危 (Low)**: 7个

---

## 一、严重安全漏洞 (Critical)

### 1.1 安装模块SQL注入与代码注入风险 🔴

**位置**: `app/Http/Controllers/Home/HomeController.php:132-186`

**问题描述**:
安装功能(doInstall方法)存在多个严重安全问题:

1. **SQL注入风险** (行175):
```php
DB::unprepared(file_get_contents($installSql));
```
虽然当前实现读取的是固定的SQL文件,但使用`DB::unprepared()`方法执行未经参数化的SQL语句存在潜在风险。

2. **环境变量注入** (行169-171):
```php
foreach ($postData as $key => $item) {
    $envTemp = str_replace('{' . $key . '}', $item, $envTemp);
}
file_put_contents($envPath, $envTemp);
```
用户输入直接通过`str_replace`写入.env文件,可能导致环境变量注入攻击。攻击者可以注入恶意配置。

3. **缺乏安装后保护**:
安装完成后仅依赖`install.lock`文件,如果该文件被删除,安装页面可再次访问。

**风险等级**: 🔴 严重 (CVSS 8.5)

**影响**:
- 攻击者可能通过重新安装覆盖数据库
- 注入恶意环境变量获取系统控制权
- 数据库凭证泄露

**修复建议**:
```php
// 1. 添加IP白名单验证
if (!in_array($request->ip(), config('install.allowed_ips', []))) {
    abort(403, 'Installation not allowed from this IP');
}

// 2. 增强输入验证
$validator = Validator::make($request->all(), [
    'db_host' => 'required|string|max:255',
    'db_port' => 'required|integer|min:1|max:65535',
    'db_database' => 'required|string|max:64|regex:/^[a-zA-Z0-9_]+$/',
    'db_username' => 'required|string|max:32',
    'db_password' => 'string|max:255',
    'admin_path' => 'required|string|max:50|regex:/^[a-zA-Z0-9_-]+$/',
]);

// 3. 使用安全的方式写入环境变量
$envVars = [
    'DB_HOST' => $validated['db_host'],
    'DB_PORT' => $validated['db_port'],
    // ... 其他变量
];
foreach ($envVars as $key => $value) {
    // 转义特殊字符
    $value = str_replace(['"', '\\'], ['\\"', '\\\\'], $value);
    $envTemp = preg_replace(
        "/^{$key}=.*/m",
        "{$key}=\"{$value}\"",
        $envTemp
    );
}

// 4. 添加安装令牌验证机制
```

---

### 1.2 默认管理员弱口令 🔴

**位置**: `database/sql/install.sql` (根据探索结果推断)

**问题描述**:
根据代码注释和DcatAdmin配置,系统默认管理员账户为:
- 用户名: `admin`
- 密码: `admin`

这是一个极其常见的默认凭证,容易被暴力破解或字典攻击。

**风险等级**: 🔴 严重 (CVSS 8.0)

**影响**:
- 攻击者可直接登录后台管理系统
- 获取所有订单数据、用户信息、支付配置
- 修改商品价格、窃取卡密库存

**修复建议**:
1. 安装时强制用户设置强密码
2. 首次登录强制修改默认密码
3. 实施密码复杂度策略(至少8位,包含大小写字母、数字、特殊字符)
4. 添加登录失败次数限制和账户锁定机制

---

### 1.3 生产环境调试模式开启风险 🔴

**位置**: `.env.example:4`

```env
APP_DEBUG=true
```

**问题描述**:
示例配置文件中`APP_DEBUG`设置为`true`,如果用户直接在生产环境使用该配置,会导致:

1. **详细错误信息泄露**:
   - 数据库查询语句
   - 文件系统完整路径
   - 第三方API密钥
   - 代码堆栈跟踪

2. **敏感配置暴露**:
   Laravel调试页面会显示所有环境变量,包括数据库密码、Redis密码、支付密钥等。

**风险等级**: 🔴 严重 (CVSS 7.5)

**影响**:
- 敏感信息泄露
- 为攻击者提供系统详细信息
- 可能导致数据库凭证、API密钥被窃取

**修复建议**:
```env
# 修改.env.example
APP_DEBUG=false
APP_ENV=production

# 添加安装后检查
if (app()->environment('production') && config('app.debug')) {
    Log::critical('Production environment running with DEBUG enabled!');
    // 可选: 自动关闭或发送告警
}
```

---

## 二、中等风险漏洞 (Medium)

### 2.1 直接使用超全局变量 🟡

**位置**:
- `app/Helpers/functions.php:160-162`
- `app/Http/Controllers/Pay/CoinbaseController.php:84`

**问题描述**:
```php
// functions.php - site_url()
$protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'
    || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
$domainName = $_SERVER['HTTP_HOST'] . '/';

// CoinbaseController.php
$sig = $_SERVER['HTTP_X_CC_WEBHOOK_SIGNATURE'];
```

直接使用`$_SERVER`超全局变量存在以下风险:
1. HTTP Host头注入攻击
2. 缺少输入验证
3. 可能被代理或负载均衡器伪造

**风险等级**: 🟡 中等 (CVSS 5.5)

**影响**:
- Host头注入可能导致钓鱼攻击
- 缓存投毒
- 密码重置链接被劫持

**修复建议**:
```php
// 使用Laravel的Request对象
function site_url()
{
    return rtrim(config('app.url'), '/') . '/';
}

// CoinbaseController.php
$sig = $request->header('X-CC-Webhook-Signature');
if (empty($sig)) {
    return 'fail|Missing signature';
}
```

---

### 2.2 查询密码验证不足 🟡

**位置**: `app/Rules/SearchPwd.php:27-32`

**问题描述**:
```php
public function passes($attribute, $value)
{
    if (dujiaoka_config_get('is_open_search_pwd') == BaseModel::STATUS_OPEN
        && empty($value)) {
        return false;
    }
    return true;
}
```

查询密码仅验证是否为空,没有:
- 最小长度要求
- 复杂度验证
- 防暴力破解机制

**风险等级**: 🟡 中等 (CVSS 5.0)

**影响**:
- 用户可能设置弱密码如"1"、"a"
- 订单信息容易被暴力破解
- 客户隐私泄露

**修复建议**:
```php
public function passes($attribute, $value)
{
    if (dujiaoka_config_get('is_open_search_pwd') == BaseModel::STATUS_OPEN) {
        if (empty($value)) {
            $this->message = '查询密码不能为空';
            return false;
        }
        if (strlen($value) < 6) {
            $this->message = '查询密码至少需要6位字符';
            return false;
        }
    }
    return true;
}

// 添加订单查询频率限制
// app/Http/Controllers/Home/OrderController.php
RateLimiter::hit('order-search:' . $request->ip(), 60 * 5);
if (RateLimiter::tooManyAttempts('order-search:' . $request->ip(), 10)) {
    return $this->err('查询过于频繁,请5分钟后再试');
}
```

---

### 2.3 Cookie安全配置不足 🟡

**位置**: `config/session.php`, `app/Http/Controllers/Home/OrderController.php:98-109`

**问题描述**:
订单Cookie处理缺少安全属性:
```php
Cookie::queue('dujiaoka_orders', json_encode([$orderSN]));
```

未设置:
- `HttpOnly`标志(防XSS窃取)
- `Secure`标志(HTTPS传输)
- `SameSite`属性(防CSRF)

**风险等级**: 🟡 中等 (CVSS 4.5)

**影响**:
- XSS攻击可窃取订单Cookie
- 中间人攻击可劫持会话
- CSRF攻击风险

**修复建议**:
```php
// config/session.php
'secure' => env('SESSION_SECURE_COOKIE', true),
'http_only' => true,
'same_site' => 'lax',

// OrderController.php
Cookie::queue(
    'dujiaoka_orders',
    json_encode($cookies),
    60 * 24 * 7, // 7天
    '/',
    null,
    true,  // secure
    true,  // httpOnly
    false,
    'lax'  // sameSite
);
```

---

### 2.4 支付回调缺少请求来源验证 🟡

**位置**: `app/Http/Controllers/Pay/AlipayController.php:77-107`

**问题描述**:
虽然支付回调有签名验证,但缺少:
1. IP白名单验证
2. 重放攻击防护
3. 金额二次验证日志

**风险等级**: 🟡 中等 (CVSS 5.5)

**影响**:
- 可能被伪造支付通知
- 重放攻击导致订单重复处理
- 金额篡改风险

**修复建议**:
```php
public function notifyUrl(Request $request)
{
    // 1. IP白名单验证(支付宝官方IP段)
    $allowedIps = config('payment.alipay.notify_ips', []);
    if (!empty($allowedIps) && !in_array($request->ip(), $allowedIps)) {
        Log::warning('Alipay notify from invalid IP: ' . $request->ip());
        return 'error';
    }

    // 2. 防重放攻击
    $notifyId = $request->input('notify_id');
    $cacheKey = 'alipay:notify:' . $notifyId;
    if (Cache::has($cacheKey)) {
        Log::warning('Duplicate Alipay notify: ' . $notifyId);
        return 'success'; // 已处理过
    }
    Cache::put($cacheKey, true, 86400); // 24小时

    // 3. 金额验证日志
    if ($result->total_amount != $order->actual_price) {
        Log::error('Alipay amount mismatch', [
            'order_sn' => $order->order_sn,
            'expected' => $order->actual_price,
            'received' => $result->total_amount,
        ]);
        return 'error';
    }

    // ... 原有逻辑
}
```

---

### 2.5 订单状态查询无频率限制 🟡

**位置**: `app/Http/Controllers/Home/OrderController.php:144-159`

**问题描述**:
```php
public function checkOrderStatus(string $orderSN)
{
    $order = $this->orderService->detailOrderSN($orderSN);
    // 没有频率限制
}
```

订单状态轮询接口缺少:
- 请求频率限制
- IP限流
- 验证码保护

**风险等级**: 🟡 中等 (CVSS 4.0)

**影响**:
- 资源耗尽(DoS)
- 数据库压力
- 订单号枚举攻击

**修复建议**:
```php
// 添加频率限制中间件
// routes/web.php
Route::get('/check-order-status/{orderSN}', 'OrderController@checkOrderStatus')
    ->middleware('throttle:60,1'); // 每分钟60次

// 或者在控制器内
public function checkOrderStatus(string $orderSN)
{
    $key = 'order-check:' . $request->ip() . ':' . $orderSN;
    if (RateLimiter::tooManyAttempts($key, 10)) {
        return response()->json(['msg' => 'too many requests', 'code' => 429]);
    }
    RateLimiter::hit($key, 60);

    // ... 原有逻辑
}
```

---

## 三、低风险问题 (Low)

### 3.1 CSRF保护未覆盖所有端点 🟢

**位置**: `app/Http/Middleware/VerifyCsrfToken.php`

**问题描述**:
需确认所有POST请求都启用CSRF保护,特别是支付回调接口应在`$except`数组中正确配置。

**风险等级**: 🟢 低 (CVSS 3.0)

**修复建议**:
```php
protected $except = [
    'pay/*/notify_url',
    'pay/*/return_url',
];
```

---

### 3.2 缺少XSS过滤 🟢

**位置**: 用户输入字段

**问题描述**:
虽然Laravel默认转义Blade模板输出,但需确认:
- 商品描述富文本编辑器输出
- 订单备注字段
- 邮件模板内容

使用`{!! !!}`输出的地方需要额外审查。

**风险等级**: 🟢 低 (CVSS 3.5)

**修复建议**:
```php
// 对富文本内容使用HTML净化库
use HTMLPurifier;

$clean_html = (new HTMLPurifier())->purify($input['description']);
```

---

### 3.3 日志可能包含敏感信息 🟢

**位置**: 全局日志记录

**问题描述**:
异常处理和日志记录可能包含:
- 用户密码(登录失败时)
- 支付密钥
- 数据库密码

**风险等级**: 🟢 低 (CVSS 2.5)

**修复建议**:
```php
// config/logging.php
'processors' => [
    \App\Logging\SensitiveDataProcessor::class,
],

// 创建处理器过滤敏感字段
class SensitiveDataProcessor
{
    public function __invoke($record)
    {
        $sensitive = ['password', 'api_key', 'secret', 'token'];
        foreach ($sensitive as $field) {
            if (isset($record['context'][$field])) {
                $record['context'][$field] = '***REDACTED***';
            }
        }
        return $record;
    }
}
```

---

### 3.4 Session固定攻击防护 🟢

**位置**: 认证模块

**问题描述**:
需确认登录成功后重新生成Session ID。

**风险等级**: 🟢 低 (CVSS 3.0)

**修复建议**:
```php
// 登录成功后
$request->session()->regenerate();
```

---

### 3.5 缺少安全响应头 🟢

**位置**: HTTP响应

**问题描述**:
缺少安全相关的HTTP响应头:
- `X-Frame-Options`
- `X-Content-Type-Options`
- `X-XSS-Protection`
- `Content-Security-Policy`
- `Strict-Transport-Security`

**风险等级**: 🟢 低 (CVSS 3.0)

**修复建议**:
```php
// app/Http/Middleware/SecurityHeaders.php
class SecurityHeaders
{
    public function handle($request, Closure $next)
    {
        $response = $next($request);

        $response->headers->set('X-Frame-Options', 'SAMEORIGIN');
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('X-XSS-Protection', '1; mode=block');
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');

        if ($request->secure()) {
            $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        }

        return $response;
    }
}
```

---

### 3.6 Redis未设置密码 🟢

**位置**: `.env.example:19`

```env
REDIS_PASSWORD={redis_password}
```

**问题描述**:
示例配置中Redis密码为占位符,用户可能不设置密码直接使用。

**风险等级**: 🟢 低 (CVSS 3.5)

**修复建议**:
在安装文档中明确说明必须为Redis设置强密码,并在安装程序中验证Redis密码不为空。

---

### 3.7 文件上传类型验证 🟢

**位置**: `app/Admin/Forms/ImportCarmis.php:69-73`

**问题描述**:
```php
$this->file('carmis_txt')
    ->disk('public')
    ->uniqueName()
    ->accept('txt')
    ->maxSize(5120)
```

前端验证`accept('txt')`可被绕过,需要后端MIME类型验证。

**风险等级**: 🟢 低 (CVSS 3.0)

**修复建议**:
```php
public function handle(array $input)
{
    if (!empty($input['carmis_txt'])) {
        // 验证MIME类型
        $file = Storage::disk('public')->path($input['carmis_txt']);
        $mime = mime_content_type($file);

        if (!in_array($mime, ['text/plain', 'application/octet-stream'])) {
            Storage::disk('public')->delete($input['carmis_txt']);
            return $this->response()->error('仅支持txt文本文件');
        }

        $carmisContent = Storage::disk('public')->get($input['carmis_txt']);
    }
    // ...
}
```

---

## 四、安全加固建议

### 4.1 数据库安全

1. **最小权限原则**:
   - 应用数据库账户不应有DROP、CREATE DATABASE权限
   - 分离只读查询和写入账户

2. **连接加密**:
```php
// config/database.php
'mysql' => [
    // ...
    'options' => [
        PDO::MYSQL_ATTR_SSL_CA => env('MYSQL_ATTR_SSL_CA'),
        PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => true,
    ],
],
```

### 4.2 API密钥管理

1. 所有支付网关密钥应加密存储
2. 使用Laravel的`encrypt()`和`decrypt()`函数
3. 定期轮换API密钥

### 4.3 备份与恢复

1. 定期自动备份数据库
2. 备份文件加密存储
3. 测试备份恢复流程

### 4.4 监控与审计

1. **安全事件日志**:
   - 登录失败
   - 权限违规
   - 支付异常
   - SQL注入尝试

2. **实时告警**:
```php
// 检测异常登录
if ($failedLoginAttempts > 5) {
    Log::critical('Potential brute force attack from IP: ' . $ip);
    // 发送告警邮件/短信
}
```

### 4.5 依赖管理

1. 定期运行`composer audit`检查依赖漏洞
2. 及时更新Laravel和第三方包
3. 使用Dependabot自动监控

---

## 五、合规性检查

### 5.1 GDPR合规

需要添加:
- 用户数据导出功能
- 数据删除请求处理
- 隐私政策页面
- Cookie同意横幅

### 5.2 PCI DSS(支付卡行业数据安全标准)

当前系统不存储信用卡信息,通过第三方支付网关处理,符合要求。但需:
- 加密传输所有支付数据
- 记录支付审计日志
- 定期安全扫描

---

## 六、修复优先级

| 优先级 | 漏洞 | 预计工时 | 影响面 |
|--------|------|----------|--------|
| P0 | 安装模块SQL/代码注入 | 8小时 | 系统级 |
| P0 | 默认弱口令 | 4小时 | 系统级 |
| P0 | 调试模式配置 | 1小时 | 信息泄露 |
| P1 | 超全局变量使用 | 3小时 | 部分模块 |
| P1 | 查询密码验证 | 2小时 | 订单模块 |
| P2 | Cookie安全配置 | 2小时 | 会话管理 |
| P2 | 支付回调验证增强 | 4小时 | 支付模块 |
| P3 | 添加安全响应头 | 2小时 | 全局 |
| P3 | 频率限制 | 3小时 | 多个接口 |

**总计预计工时**: 29小时

---

## 七、代码审计详情

### 7.1 认证与授权

✅ **安全实现**:
- 使用Laravel内置认证系统
- 密码使用bcrypt哈希存储
- DcatAdmin RBAC权限系统

⚠️ **需改进**:
- 缺少双因素认证(2FA)
- 没有登录IP白名单功能
- Session超时时间过长(120分钟)

### 7.2 数据验证

✅ **安全实现**:
- 使用Laravel Validator进行输入验证
- 邮箱格式验证
- 订单金额、数量验证

⚠️ **需改进**:
- 部分字段缺少长度限制
- 查询密码强度不足
- 缺少防暴力破解机制

### 7.3 SQL注入防护

✅ **安全实现**:
- 大部分查询使用Eloquent ORM
- 参数绑定正确使用

⚠️ **需改进**:
- `DB::raw()` 使用需要审查
- `DB::unprepared()` 在安装模块使用

### 7.4 XSS防护

✅ **安全实现**:
- Blade模板默认转义
- 验证码防护

⚠️ **需改进**:
- 富文本编辑器内容净化
- 确认所有用户输入都经过转义

### 7.5 CSRF防护

✅ **安全实现**:
- Laravel内置CSRF中间件
- 表单自动添加token

⚠️ **需改进**:
- 确认支付回调正确配置豁免

---

## 八、第三方依赖安全

### 8.1 核心依赖

| 依赖 | 版本 | 已知漏洞 | 建议 |
|------|------|----------|------|
| laravel/framework | 6.x | 检查CVE列表 | 升级到最新6.x版本 |
| dcat/laravel-admin | 2.x | 审查中 | 关注官方更新 |
| yansongda/pay | - | 审查中 | 定期更新 |

### 8.2 JavaScript依赖

建议运行`npm audit`检查前端依赖漏洞。

---

## 九、渗透测试建议

建议进行以下渗透测试:

1. **身份认证测试**
   - 暴力破解
   - Session固定
   - Cookie劫持

2. **授权测试**
   - 垂直越权(普通用户访问管理功能)
   - 水平越权(查看其他用户订单)

3. **输入验证测试**
   - SQL注入(所有输入点)
   - XSS(存储型、反射型、DOM型)
   - 命令注入
   - 文件上传

4. **业务逻辑测试**
   - 订单金额篡改
   - 优惠券重复使用
   - 库存竞态条件
   - 支付回调重放

5. **信息泄露测试**
   - 错误信息
   - 敏感文件访问(.env, .git)
   - 目录遍历

---

## 十、总结

独角数卡系统整体采用了Laravel框架的安全最佳实践,核心安全机制(认证、ORM、CSRF)实施良好。主要安全风险集中在:

1. **安装模块** - 需要完全重构以消除注入风险
2. **默认配置** - 需要强化默认安全设置
3. **输入验证** - 需要增强密码策略和频率限制
4. **安全监控** - 需要添加异常检测和告警机制

修复严重漏洞后,系统安全性将得到显著提升。建议按优先级逐步实施修复,并在生产环境部署前进行完整的渗透测试。

---

## 附录A: 安全检查清单

- [ ] 修复安装模块注入漏洞
- [ ] 强制修改默认管理员密码
- [ ] 生产环境关闭调试模式
- [ ] 使用Request对象替代超全局变量
- [ ] 实施强密码策略
- [ ] 配置安全Cookie属性
- [ ] 添加支付回调IP白名单
- [ ] 实施API频率限制
- [ ] 添加安全响应头
- [ ] 启用Redis密码认证
- [ ] 配置HTTPS和HSTS
- [ ] 实施日志脱敏
- [ ] 文件上传MIME验证
- [ ] 定期依赖漏洞扫描
- [ ] 配置自动备份
- [ ] 实施安全监控告警

---

## 附录B: 紧急响应流程

如发现系统被攻击:

1. **立即行动**:
   - 隔离受影响服务器
   - 启用维护模式
   - 保留日志证据

2. **评估影响**:
   - 检查数据泄露范围
   - 分析攻击向量
   - 统计受影响用户

3. **修复漏洞**:
   - 应用安全补丁
   - 修改所有密码和密钥
   - 清理恶意代码

4. **恢复服务**:
   - 从可信备份恢复
   - 验证系统完整性
   - 逐步恢复服务

5. **通知披露**:
   - 通知受影响用户
   - 向监管机构报告
   - 发布安全公告

---

**审计人员**: Claude (AI Security Auditor)
**报告日期**: 2025-10-28
**报告版本**: 1.0
**机密等级**: 内部使用

---

**免责声明**: 本报告基于静态代码审计,未进行实际渗透测试。实际安全状况可能因配置、部署环境等因素而异。建议结合动态测试和专业安全团队评估。
