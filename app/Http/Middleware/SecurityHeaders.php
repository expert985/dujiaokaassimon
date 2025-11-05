<?php

namespace App\Http\Middleware;

use Closure;

/**
 * 安全响应头中间件
 *
 * 添加安全相关的HTTP响应头，防止常见的Web攻击
 *
 * Class SecurityHeaders
 * @package App\Http\Middleware
 */
class SecurityHeaders
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $response = $next($request);

        // X-Frame-Options: 防止点击劫持攻击
        // SAMEORIGIN: 只允许同源iframe嵌入
        $response->headers->set('X-Frame-Options', 'SAMEORIGIN');

        // X-Content-Type-Options: 防止MIME类型嗅探
        // nosniff: 强制浏览器遵循Content-Type
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        // X-XSS-Protection: 启用浏览器XSS过滤器
        // 1; mode=block: 检测到XSS时阻止页面加载
        $response->headers->set('X-XSS-Protection', '1; mode=block');

        // Referrer-Policy: 控制Referer头信息泄露
        // strict-origin-when-cross-origin: 同源完整URL，跨域仅发送源
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');

        // Strict-Transport-Security (HSTS): 强制HTTPS
        // 仅在HTTPS连接时添加
        if ($request->secure()) {
            // max-age=31536000: 1年有效期
            // includeSubDomains: 应用到所有子域
            $response->headers->set(
                'Strict-Transport-Security',
                'max-age=31536000; includeSubDomains'
            );
        }

        // Content-Security-Policy (CSP): 内容安全策略
        // 可根据实际需求调整，这里使用较宽松的配置
        $csp = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'", // 允许内联脚本（可能需要调整）
            "style-src 'self' 'unsafe-inline'",                 // 允许内联样式
            "img-src 'self' data: https:",                      // 允许data URI和HTTPS图片
            "font-src 'self' data:",                            // 允许字体
            "connect-src 'self'",                               // XHR/WebSocket等
            "frame-ancestors 'self'",                           // 防止被iframe嵌入
        ];

        // 生产环境启用CSP（开发环境可能需要更宽松的策略）
        if (config('app.env') === 'production') {
            $response->headers->set('Content-Security-Policy', implode('; ', $csp));
        }

        // Permissions-Policy: 控制浏览器特性访问
        $response->headers->set('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

        return $response;
    }
}
