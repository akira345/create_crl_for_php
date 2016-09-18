<?php
//クライアント証明書失効リスト(CRL)作成サンプルプログラム
//
// openssl_x509_gencrl(https://github.com/ukrbublik/openssl_x509_gencrl)を使ったCRL作成サンプルです。
// 

require_once("./openssl_x509_gencrl-master/src/x509_cert.php");
require_once("./openssl_x509_gencrl-master/src/x509_crl.php");

//Check server requirements
X509::checkServer();

$ca_passphrase = "casecret_password"; //CAの秘密鍵パスフレーズ

$client_passhrase = "client_password";//クライアント証明書のパスフレーズ
$client_cert_filename = "client_cert.p12"; //失効させたいクライアント証明書(P12形式)
$serial = 0;

//クライアント証明書読み込み
if (!$cert_store = file_get_contents($client_cert_filename)) {
    echo "Error: クライアント証明書が読み込めません。\n";
    exit;
}
//クライアント証明書を読み込み、シリアル番号を取得
if (openssl_pkcs12_read($cert_store, $cert_info, $client_passhrase)) {
    //証明書の内容をデコード
    $data = X509_cert::decode(X509::pem2der($cert_info['cert']));
    $is_v1 = false;
    if($data->content[0]->findContext(0) === null){
      $is_v1 = true;
    }
    //シリアル番号を取得
    $serial = $data->content[0]->content[$is_v1 ? 0 : 1]->content;
    var_dump($serial);
} else {
    echo "Error: 証明書の内容が読めません。\n";
    exit;
}


//失効証明書(CRL)作成。
// 下記のパラメーターは
// https://www.ipa.go.jp/security/pki/042.htmlを参考
//
$ci = array(
	'no' => 1,  //CRLを更新するたびにインクリメントすること。ここではサンプルなので固定にしている。
	'version' => 2,  //CRL Version
	'days' => 30, //次のCRL更新予定日。CRLの有効期限。
	'alg' => OPENSSL_ALGO_SHA1, //CRLのハッシュアルゴリズム。ライブラリが対応していないので、SHA2を指定するとエラーになる。
	'revoked' => array(  // 失効したい証明書を配列で指定。ここではサンプルなので上記で読み込んだ証明書を一つだけ指定している。
		array(
			'serial' => $serial, //失効させたい証明書のシリアル
			'rev_date' => time(), //失効日
			'reason' => X509::getRevokeReasonCodeByName("cessationOfOperation"), //失効理由。運用停止を指定してある。
			'compr_date' => strtotime("-1 day"),
			'hold_instr' => null,
		)
	)
);

//失効証明書を作成
$ca_pkey = openssl_pkey_get_private(file_get_contents('ca_key.key'),$ca_passphrase);  //クライアント証明書に署名したCAの秘密鍵
$ca_cert = X509::pem2der(file_get_contents('ca_cert.cer')); //クライアント証明書に署名したCA証明書
$crl_data = X509_CRL::create($ci, $ca_pkey, $ca_cert);
if(file_put_contents('test_crl.crl', $crl_data)) {  //失効証明書出力
	echo "失効証明書を作成しました。\n";
}

