<?php

namespace App\Rules;

use App\Models\BaseModel;
use Illuminate\Contracts\Validation\Rule;

class SearchPwd implements Rule
{
    /**
     * 错误消息
     * @var string
     */
    private $errorMessage = '';

    /**
     * Create a new rule instance.
     *
     * @return void
     */
    public function __construct()
    {
        //
    }

    /**
     * Determine if the validation rule passes.
     *
     * @param  string  $attribute
     * @param  mixed  $value
     * @return bool
     */
    public function passes($attribute, $value)
    {
        // 如果开启了查询密码功能
        if (dujiaoka_config_get('is_open_search_pwd') == BaseModel::STATUS_OPEN) {
            // 安全增强：检查密码是否为空
            if (empty($value)) {
                $this->errorMessage = __('dujiaoka.prompt.search_password_can_not_be_empty');
                return false;
            }

            // 安全增强：检查最小长度（至少6位字符）
            if (mb_strlen($value) < 6) {
                $this->errorMessage = '查询密码至少需要6位字符';
                return false;
            }

            // 安全增强：检查最大长度（防止DoS）
            if (mb_strlen($value) > 50) {
                $this->errorMessage = '查询密码最多50位字符';
                return false;
            }

            // 安全增强：建议使用复杂密码（可选，仅警告）
            // 检查是否过于简单（如纯数字、纯字母）
            if (preg_match('/^[0-9]+$/', $value) || preg_match('/^[a-zA-Z]+$/', $value)) {
                // 注意：这里仅记录日志，不阻止用户
                \Log::info('用户设置了简单查询密码', ['length' => mb_strlen($value)]);
            }
        }

        return true;
    }

    /**
     * Get the validation error message.
     *
     * @return string
     */
    public function message()
    {
        return $this->errorMessage ?: __('dujiaoka.prompt.search_password_can_not_be_empty');
    }
}
