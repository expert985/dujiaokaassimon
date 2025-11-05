<?php

namespace App\Http\Controllers\Home;

use App\Exceptions\RuleValidationException;
use App\Http\Controllers\BaseController;
use App\Models\Pay;
use Germey\Geetest\Geetest;
use Illuminate\Database\DatabaseServiceProvider;
use Illuminate\Database\QueryException;
use Illuminate\Encryption\Encrypter;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Redis;

class HomeController extends BaseController
{

    /**
     * 商品服务层.
     * @var \App\Service\PayService
     */
    private $goodsService;

    /**
     * 支付服务层
     * @var \App\Service\PayService
     */
    private $payService;

    public function __construct()
    {
        $this->goodsService = app('Service\GoodsService');
        $this->payService = app('Service\PayService');
    }

    /**
     * 首页.
     *
     * @param Request $request
     *
     * @author    assimon<ashang@utf8.hk>
     * @copyright assimon<ashang@utf8.hk>
     * @link      http://utf8.hk/
     */
    public function index(Request $request)
    {
        $goods = $this->goodsService->withGroup();
        return $this->render('static_pages/home', ['data' => $goods], __('dujiaoka.page-title.home'));
    }

    /**
     * 商品详情
     *
     * @param int $id
     * @return \Illuminate\Contracts\Foundation\Application|\Illuminate\Contracts\View\Factory|\Illuminate\View\View
     *
     * @author    assimon<ashang@utf8.hk>
     * @copyright assimon<ashang@utf8.hk>
     * @link      http://utf8.hk/
     */
    public function buy(int $id)
    {
        try {
            $goods = $this->goodsService->detail($id);
            $this->goodsService->validatorGoodsStatus($goods);
            // 有没有优惠码可以展示
            if (count($goods->coupon)) {
                $goods->open_coupon = 1;
            }
            $formatGoods = $this->goodsService->format($goods);
            // 加载支付方式.
            $client = Pay::PAY_CLIENT_PC;
            if (app('Jenssegers\Agent')->isMobile()) {
                $client = Pay::PAY_CLIENT_MOBILE;
            }
            $formatGoods->payways = $this->payService->pays($client);
            return $this->render('static_pages/buy', $formatGoods, $formatGoods->gd_name);
        } catch (RuleValidationException $ruleValidationException) {
            return $this->err($ruleValidationException->getMessage());
        }

    }

    /**
     * 极验行为验证
     *
     * @param Request $request
     *
     * @author    assimon<ashang@utf8.hk>
     * @copyright assimon<ashang@utf8.hk>
     * @link      http://utf8.hk/
     */
    public function geetest(Request $request)
    {
        $data = [
            'user_id' => @Auth::user()?@Auth::user()->id:'UnLoginUser',
            'client_type' => 'web',
            'ip_address' => \Illuminate\Support\Facades\Request::ip()
        ];
        $status = Geetest::preProcess($data);
        session()->put('gtserver', $status);
        session()->put('user_id', $data['user_id']);
        return Geetest::getResponseStr();
    }

    /**
     * 安装页面
     *
     * @param Request $request
     * @return \Illuminate\Contracts\Foundation\Application|\Illuminate\Contracts\View\Factory|\Illuminate\View\View
     *
     * @author    assimon<ashang@utf8.hk>
     * @copyright assimon<ashang@utf8.hk>
     * @link      http://utf8.hk/
     */
    public function install(Request $request)
    {
        return view('common/install');
    }

    /**
     * 执行安装
     *
     * @param Request $request
     *
     * @author    assimon<ashang@utf8.hk>
     * @copyright assimon<ashang@utf8.hk>
     * @link      http://utf8.hk/
     */
    public function doInstall(Request $request)
    {
        try {
            // 安全增强：输入验证
            $validator = \Validator::make($request->all(), [
                'db_host' => 'required|string|max:255',
                'db_port' => 'required|integer|min:1|max:65535',
                'db_database' => 'required|string|max:64|regex:/^[a-zA-Z0-9_]+$/',
                'db_username' => 'required|string|max:32',
                'db_password' => 'nullable|string|max:255',
                'redis_host' => 'required|string|max:255',
                'redis_port' => 'required|integer|min:1|max:65535',
                'redis_password' => 'nullable|string|max:255',
                'admin_path' => 'required|string|max:50|regex:/^[a-zA-Z0-9_-]+$/',
                'title' => 'required|string|max:100',
                'app_url' => 'required|url|max:255',
            ], [
                'db_database.regex' => '数据库名称只能包含字母、数字和下划线',
                'admin_path.regex' => '管理路径只能包含字母、数字、下划线和连字符',
            ]);

            if ($validator->fails()) {
                return '输入验证失败：' . $validator->errors()->first();
            }

            $validated = $validator->validated();

            $dbConfig = config('database');
            $mysqlDB = [
                'host' => $validated['db_host'],
                'port' => $validated['db_port'],
                'database' => $validated['db_database'],
                'username' => $validated['db_username'],
                'password' => $validated['db_password'] ?? '',
            ];
            $dbConfig['connections']['mysql'] = array_merge($dbConfig['connections']['mysql'], $mysqlDB);
            // Redis
            $redisDB = [
                'host' => $validated['redis_host'],
                'password' => $validated['redis_password'] ?? 'null',
                'port' => $validated['redis_port'],
            ];
            $dbConfig['redis']['default'] = array_merge($dbConfig['redis']['default'], $redisDB);
            config(['database' => $dbConfig]);
            DB::purge();
            // db测试
            DB::connection()->select('select 1 limit 1');
            // redis测试
            Redis::set('dujiaoka_com', 'ok');
            Redis::get('dujiaoka_com');
            // 获得文件模板
            $envExamplePath = base_path() . DIRECTORY_SEPARATOR . '.env.example';
            $envPath =  base_path() . DIRECTORY_SEPARATOR . '.env';
            $installLock = base_path() . DIRECTORY_SEPARATOR . 'install.lock';
            $installSql = database_path() . DIRECTORY_SEPARATOR . 'sql' . DIRECTORY_SEPARATOR . 'install.sql';

            // 安全增强：验证模板文件存在
            if (!file_exists($envExamplePath)) {
                return '错误：.env.example 文件不存在';
            }
            if (!file_exists($installSql)) {
                return '错误：install.sql 文件不存在';
            }

            $envTemp = file_get_contents($envExamplePath);

            // 安全增强：生成应用密钥
            $appKey = 'base64:' . base64_encode(
                Encrypter::generateKey(config('app.cipher'))
            );

            // 安全增强：使用白名单方式替换环境变量，防止注入
            $envVars = [
                'title' => $validated['title'],
                'app_key' => $appKey,
                'app_url' => $validated['app_url'],
                'db_host' => $validated['db_host'],
                'db_port' => $validated['db_port'],
                'db_database' => $validated['db_database'],
                'db_username' => $validated['db_username'],
                'db_password' => $validated['db_password'] ?? '',
                'redis_host' => $validated['redis_host'],
                'redis_password' => $validated['redis_password'] ?? 'null',
                'redis_port' => $validated['redis_port'],
                'admin_path' => $validated['admin_path'],
            ];

            // 安全增强：转义特殊字符并使用模板替换
            foreach ($envVars as $key => $value) {
                // 转义反斜杠和双引号
                $escapedValue = str_replace(['\\', '"'], ['\\\\', '\\"'], $value);
                $envTemp = str_replace('{' . $key . '}', $escapedValue, $envTemp);
            }

            // 写入配置
            file_put_contents($envPath, $envTemp);

            // 安全增强：使用事务执行SQL安装
            DB::beginTransaction();
            try {
                // 读取并执行SQL文件
                $sqlContent = file_get_contents($installSql);
                // 分割SQL语句（简单处理，按分号和换行分割）
                $statements = array_filter(
                    array_map('trim', explode(';', $sqlContent)),
                    function($stmt) {
                        return !empty($stmt) && !preg_match('/^--/', $stmt);
                    }
                );

                foreach ($statements as $statement) {
                    if (!empty(trim($statement))) {
                        DB::statement($statement);
                    }
                }

                DB::commit();
            } catch (\Exception $e) {
                DB::rollBack();
                throw new \Exception('数据库安装失败：' . $e->getMessage());
            }

            // 写入安装锁
            file_put_contents($installLock, 'install ok - ' . date('Y-m-d H:i:s'));

            // 安全日志
            \Log::info('系统安装成功', [
                'ip' => $request->ip(),
                'time' => date('Y-m-d H:i:s'),
            ]);

            return 'success';
        } catch (\RedisException $exception) {
            \Log::error('Redis配置错误', ['error' => $exception->getMessage()]);
            return 'Redis配置错误 :' . $exception->getMessage();
        } catch (QueryException $exception) {
            \Log::error('数据库配置错误', ['error' => $exception->getMessage()]);
            return '数据库配置错误 :' . $exception->getMessage();
        } catch (\Exception $exception) {
            \Log::error('安装过程错误', ['error' => $exception->getMessage()]);
            return $exception->getMessage();
        }
    }


}
