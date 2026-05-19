<?php

namespace App\Library;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;

class ComJwt
{
    //使用HMAC生成信息所使用的密钥111333
    private string $key = "SFDI25@#8FG";
    //头部定义
    private array $header = array(
        'alg' => 'HS256',
        'type' => 'JWT',
    );
    //负载
    public array $payload = array(
        'iss' => '',         //签发者111333
        'aud' => '',         //面向的用户
        'iat' => '',         //签发时间
        'nbf' => '',         //生效时间
        'exp' => '',         //过期时间时间
    );

    public function __construct(){}

    /**
     * 生成JWT签名
     * @param string $iss   签发者
     * @param int $exp   过期时间
     * @param array $data  签发参数
     * @return string
     *
     *@author flyer
     * @date  2024-3-3
     */
     public function getToken(array $data = [], int $exp=86400, string $iss='', $aud = '') :string
     {
        $time = time();
        $this->payload = [
            'iss' => '11',         //签发者
            'aud' => $aud,         //面向的用户
            'iat' => $time,        //签发时间
            'nbf' => $time,        //生效时间
            'exp'  => $time+$exp,  //过期时间时间
        ];
        $this->payload = array_merge($this->payload, $data);
        return JWT::encode($this->payload, $this->key, "HS256");
     }

    /**
     * 验证JWT签名
     * @param string $token 签名
     * @date  2024-3-3
     * @return array
     *
     *@author flyer
     */
     public function checkToken(string $token = ''): array
     {
         try {
            JWT::$leeway = 60;//当前时间减去60
            $data = json_encode(JWT::decode($token, new Key($this->key, 'HS256')));
            $msg = ['errno' => 0, 'data' => json_decode($data, true)];
        } catch (\Exception $e)  {
             $msg = match (get_class($e)) {
                 'Firebase\JWT\SignatureInvalidException' => ['errno' => 100, 'msg' => '签名被修改'],
                 'Firebase\JWT\BeforeValidException' => ['errno' => 100, 'msg' => '签名已被停用'],
                 'Firebase\JWT\ExpiredException' => ['errno' => 500, 'msg' => '签名过期'],
                 default => ['errno' => 100, 'msg' => '签名信息有误'],
             };
         }
         return $msg;
     }



}
