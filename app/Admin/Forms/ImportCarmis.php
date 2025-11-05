<?php

namespace App\Admin\Forms;

use App\Models\Carmis;
use App\Models\Goods;
use Dcat\Admin\Widgets\Form;
use Illuminate\Support\Facades\Storage;

class ImportCarmis extends Form
{

    /**
     * Handle the form request.
     *
     * @param array $input
     *
     * @return mixed
     */
    public function handle(array $input)
    {
        if (empty($input['carmis_list']) && empty($input['carmis_txt'])) {
            return $this->response()->error(admin_trans('carmis.rule_messages.carmis_list_and_carmis_txt_can_not_be_empty'));
        }
        $carmisContent = "";
        if (!empty($input['carmis_txt'])) {
            // 安全增强：验证文件MIME类型
            $filePath = Storage::disk('public')->path($input['carmis_txt']);

            if (!file_exists($filePath)) {
                return $this->response()->error('文件不存在');
            }

            // 检查文件MIME类型
            $mimeType = mime_content_type($filePath);
            $allowedMimes = ['text/plain', 'application/octet-stream'];

            if (!in_array($mimeType, $allowedMimes)) {
                // 删除非法文件
                Storage::disk('public')->delete($input['carmis_txt']);
                \Log::warning('非法文件上传尝试', [
                    'mime' => $mimeType,
                    'file' => $input['carmis_txt'],
                ]);
                return $this->response()->error('仅支持txt文本文件，检测到的文件类型：' . $mimeType);
            }

            // 安全增强：检查文件大小（不超过5MB）
            $fileSize = filesize($filePath);
            if ($fileSize > 5 * 1024 * 1024) {
                Storage::disk('public')->delete($input['carmis_txt']);
                return $this->response()->error('文件大小不能超过5MB');
            }

            $carmisContent = Storage::disk('public')->get($input['carmis_txt']);
        }
        if (!empty($input['carmis_list'])) {
            $carmisContent = $input['carmis_list'];
        }

        // 安全增强：检查内容长度，防止内存溢出
        if (strlen($carmisContent) > 10 * 1024 * 1024) { // 10MB
            if (!empty($input['carmis_txt'])) {
                Storage::disk('public')->delete($input['carmis_txt']);
            }
            return $this->response()->error('内容过大，请分批导入');
        }

        $carmisData = [];
        $tempList = explode(PHP_EOL, $carmisContent);

        // 安全增强：限制导入数量，防止大批量攻击
        if (count($tempList) > 100000) { // 最多10万条
            if (!empty($input['carmis_txt'])) {
                Storage::disk('public')->delete($input['carmis_txt']);
            }
            return $this->response()->error('一次性导入数量不能超过10万条，请分批导入');
        }

        foreach ($tempList as $val) {
            if (trim($val) != "") {
                $carmisData[] = [
                    'goods_id' => $input['goods_id'],
                    'carmi' => trim($val),
                    'status' => Carmis::STATUS_UNSOLD,
                    'created_at' => date('Y-m-d H:i:s'),
                    'updated_at' => date('Y-m-d H:i:s'),
                ];
            }
        }
        if ($input['remove_duplication'] == 1) {
            $carmisData = assoc_unique($carmisData, 'carmi');
        }
        Carmis::query()->insert($carmisData);
        // 删除文件
        if (!empty($input['carmis_txt'])) {
            Storage::disk('public')->delete($input['carmis_txt']);
        }
        return $this
				->response()
				->success(admin_trans('carmis.rule_messages.import_carmis_success'))
				->location('/carmis');
    }

    /**
     * Build a form here.
     */
    public function form()
    {
        $this->confirm(admin_trans('carmis.fields.are_you_import_sure'));
        $this->select('goods_id')->options(
            Goods::query()->where('type', Goods::AUTOMATIC_DELIVERY)->pluck('gd_name', 'id')
        )->required();
        $this->textarea('carmis_list')
            ->rows(20)
            ->help(admin_trans('carmis.helps.carmis_list'));
        $this->file('carmis_txt')
            ->disk('public')
            ->uniqueName()
            ->accept('txt')
            ->maxSize(5120)
            ->help(admin_trans('carmis.helps.carmis_list'));
        $this->switch('remove_duplication');
    }

}
