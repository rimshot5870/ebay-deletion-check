<?php
require __DIR__ . '/vendor/autoload.php';

// Test variable write
// echo 'My variable is ' .$_ENV["ENV_VAR"] . '!';
 
##########################################################
### Marketplace Account Deletion Notifications Handler ###
### By Swappart 2021                                   ###
##########################################################
 
### Sign into eBay Developers Program and find your Client ID and Client Secret under 
### application access keys.
### Your endpoint and verificationToken are values you specify when subscribing to 
### Marketplace Account Deletion Notifications in your developer account.
### The endpoint URL must not contain the word eBay.
### The verification token has to be between 32 and 80 characters, and allowed 
### characters include alphanumeric characters, underscore (_),  and hyphen (-).
### No other characters are allowed. Example: 654321abcdef654321abcefd123456fe;
 
$client_id =  $_ENV["CLIENT_ID"];  //Also known as App ID.
$client_secret =  $_ENV["CLIENT_SECRET"]; //Also known as Cert ID.
$verificationToken = $_ENV["VERIFICATIONTOKEN"];
$endpoint = $_ENV["ENDPOINT"];
 
// Sets base file location to one level above webroot. You can
// change this if you want to use a specific location.
// $fileStorageLocation = realpath(dirname(__FILE__) . '/..');
$fileStorageLocation = '/workspace/files/';
 
 
 
#####################################
### This part validates endpoint. ###
#####################################
if(isset($_GET['challenge_code'])){
$challengeCode = $_GET['challenge_code'];
header('Content-Type: application/json'); 
$d=$challengeCode.$verificationToken.$endpoint; 
$hd=array("challengeResponse"=>hash("sha256", $d));
 
echo(json_encode($hd));
}
 
 
$json = file_get_contents('php://input');
$message = json_decode($json, true);
 
####################################################
### Creates file to help with debugging script   ###
### Find file debug.txt in the directory above   ###
### webroot. May contain sensitive info, so do   ###
### not post the contents if you have a problem. ###
####################################################
$config['Decoded JSON Message'] = $message;
$config['Server'] = $_SERVER;
$data = parseArray($config);
$debug = $fileStorageLocation . '/debug.txt';
write_to_file($debug, $data);
 
 
 
 
#######################################
### This part handles notfications. ###
#######################################
if(isset($_SERVER['HTTP_X_EBAY_SIGNATURE'])){
    
if (!$message) {
    throw new Exception('Invalid message');
}
 
if (empty($_SERVER['HTTP_X_EBAY_SIGNATURE'])) {
    throw new Exception('No signature passed');
}
 
$signature = json_decode(base64_decode($_SERVER['HTTP_X_EBAY_SIGNATURE']), true) ?: [];
if (empty($signature['kid'])) {
    throw new Exception('Signature not decoded');
}
 
 
 
$token = retrieveToken($client_id, $client_secret, $fileStorageLocation);
 
$ch = curl_init();
$fp = fopen($fileStorageLocation . '/curlLog.txt', 'w') or die('Unable to open file!');
curl_setopt($ch, CURLOPT_URL, "https://api.ebay.com/commerce/notification/v1/public_key/" . $signature['kid']);
curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type = application/json','Accept: application/json', 'Authorization:bearer ' . $token));
curl_setopt($ch, CURLOPT_FILE, $fp);
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
 
 
 
$response = curl_exec($ch);
 
 
 
$curl_errno = curl_errno($ch);
$curl_error = curl_error($ch);
 
if ($curl_errno > 0) {
    
   fwrite($fp, "cURL Error ($curl_errno): $curl_error\n");
        } else {
            fwrite($fp, "Data received: $response\n");
            
        }
 
$publicKey = json_decode($response, true);
 
curl_close($ch);
fclose($fp);
 
if (empty($publicKey['key'])) {
    throw new Exception(
        'getPublicKey response: ' . json_encode($publicKey) . ' for signature ' . $signature['kid']
    );
}
 
if ($publicKey['algorithm'] !== 'ECDSA' || $publicKey['digest'] !== 'SHA1') {
    throw new Exception('Unsupported encryption algorithm/digest');
}
 
if (preg_match('/^-----BEGIN PUBLIC KEY-----(.+)-----END PUBLIC KEY-----$/', $publicKey['key'], $matches)) {
    $key = "-----BEGIN PUBLIC KEY-----\n"
        . implode("\n", str_split($matches[1], 64))
        . "\n-----END PUBLIC KEY-----";
} else {
    throw new Exception('Invalid key');
}
 
 
$verificationResult = openssl_verify(
    json_encode($message),
    base64_decode($signature['signature']),
    $key,
    OPENSSL_ALGO_SHA1
);
 
 
 
if ($verificationResult === 1) {
    echo 'OK';
    
    // If you need to check to see if you have any data related to the deleted user
    // this is where you do it. You would pass the below username and/or userId 
    // variables to a script which could check your database, and then handle the
    // result accordingly.
    
    
      $username = $message['notification']['data']['username']; //orders.guest_id
      $userId = $message['notification']['data']['userId'];
      $eiasToken = $message['notification']['data']['eiasToken'];
    
        if ($username) {
            // escape data just in case.  No insert of this data is being done.
            //$username = htmlspecialchars($username, ENT_QUOTES, 'UTF-8');
            $data = http_build_query(array('userName' => $username));
            $curl = curl_init();
            curl_setopt($curl, CURLOPT_URL, 'http://www.process.abugames.com/ebay/deletePersonalInfo/deletePersonalInfo.php');
            curl_setopt($curl, CURLOPT_POST, true);
            //curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
            curl_setopt($curl, CURLOPT_POSTFIELDS, "userName=$username");
            curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
            $response = curl_exec($curl);
            curl_close($curl);

            write_to_file($fileStorageLocation . '/randallTest.txt', array('something'));
        }
    
    
} else {
$myfile = fopen($fileStorageLocation . '/verification-error.txt', 'w') or die('Unable to open file!');
$txt = "Verification Failed!";
fwrite($myfile, $txt);
fclose($myfile);
    throw new Exception('Verification failure', 412);
}
}
 
 
 
 
#############################################################
### This part returns stored OAuth token, or new token if ###
### stored one is expired. Tokens only valid for 2 hours. ###
#############################################################
function retrieveToken($client_id, $client_secret, $fileStorageLocation){
 $date = new DateTime();
 $date->getTimestamp();
 $auth = null;
 if(file_exists($fileStorageLocation . '/auth.ini')){
  $auth = parse_ini_file($fileStorageLocation . '/auth.ini', true);   
if(!isset($auth['time']) ||  !isset($auth['token'])){
    //ini file exists but doesn't contain token. We'll fetch one and update the file.
    $token = getNewToken($client_id, $client_secret, $fileStorageLocation);
}else{
   $s = $auth['time'];
   $t= new DateTime("@$s");
   
    if($date->getTimestamp() > $t->add(new DateInterval('PT7170S'))->getTimestamp()){
        //Token expired. We'll fetch a new one.
        $token = getNewToken($client_id, $client_secret, $fileStorageLocation);
    }else{
        //Stored token still good! Using it"
        $token = $auth['token'];
        
    }
}
 
 }else{
     //ini file doesn't exist yet. We'll fetch a token and create the file.
     $token = getNewToken($client_id, $client_secret, $fileStorageLocation); 
 }
 
 return $token;
 
}
 
 
####################################################
### This part fetches new OAuth token as needed. ###
####################################################
function getNewToken($client_id, $client_secret, $fileStorageLocation) {
 
$ch = curl_init();
 
curl_setopt($ch, CURLOPT_URL, 'https://api.ebay.com/identity/v1/oauth2/token');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS, "grant_type=client_credentials&scope=https://api.ebay.com/oauth/api_scope");
 
$headers = array();
$headers[] = 'Content-Type: application/x-www-form-urlencoded';
$headers[] = 'Authorization: Basic ' . base64_encode($client_id . ':' . $client_secret);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
 
$result = curl_exec($ch);
if (curl_errno($ch)) {
    echo 'Error:' . curl_error($ch);
}
curl_close($ch);
$tk = json_decode($result, true);
$date = new DateTime();
$time = $date->getTimestamp();
 
 
// Update values
$config['time'] = $time;
$config['token'] = $tk['access_token'];
 
$data = parseArray($config);
 
 
// Write ini file values
$inifile = fopen($fileStorageLocation . '/auth.ini', 'w') or die('Unable to open file!');
write_to_file($fileStorageLocation . '/auth.ini', $data);
fclose($inifile);
    
  return $tk['access_token']; 
}
 
 
 
#######################################################################
### This part parses arrays.                                        ###
#######################################################################
function parseArray($array = []) {
       
        // check second argument is array
        if (!is_array($array)) {
            throw new \InvalidArgumentException('Function argument must be an array.');
        }
 
                              // process array
        $data = array();
        foreach ($array as $key1 => $val1) {
            if (is_array($val1)) {
                $data[] = "[$key1]";
                
                
                foreach ($val1 as $key2 => $val2) {
                    if (is_array($val2)) {
                        
                        foreach ($val2 as $key3 => $val3) {
                             if (is_array($val3)) {
                            foreach ($val3 as $key4 => $val4) {
                                
                                
                            if (is_numeric($key3)) {
                                $data[] = $key3.'[] = '.(is_numeric($val4) ? $val4 : (ctype_upper($val4) ? $val4 : '"'.$val4.'"'));
                            } else {
                                $data[] = $key2.'['.$key3.'] ['.$key4.']= '.(is_numeric($val4) ? $val4 : (ctype_upper($val4) ? $val4 : '"'.$val4.'"'));
                            }
                             
                            }
                            }else {
                                $data[] = $key2.'['.$key3.'] = '.(is_numeric($val3) ? $val3 : (ctype_upper($val3) ? $val3 : '"'.$val3.'"'));
                            }
                        }
                        
                        
                    } else {
                        $data[] = $key2.' = '.(is_numeric($val2) ? $val2 : (ctype_upper($val2) ? $val2 : '"'.$val2.'"'));
                    }
                }
                
                
                
            } else {
                $data[] = $key1.' = '.(is_numeric($val1) ? $val1 : (ctype_upper($val1) ? $val1 : '"'.$val1.'"'));
            }
            
            $data[] = null;
        }
 
      return $data;
    }
 
###########################################################
### This part writes arrays to file.                    ### 
### Used for storing OAuth token for later use.         ###
### Also used to create debug file.                     ###
###########################################################
function write_to_file($file, $dataArray = []) {
        
// check first argument is string
        if (!is_string($file)) {
            throw new \InvalidArgumentException('Function argument 1 must be a string.');
        }
 
        // check second argument is array
        if (!is_array($dataArray)) {
            throw new \InvalidArgumentException('Function argument 2 must be an array.');
        }
        // open file pointer, init flock options
        $fp = fopen($file, 'w');
        $retries = 0;
        $max_retries = 100;
 
        if (!$fp) {
            return false;
        }
 
        // loop until get lock, or reach max retries
        do {
            if ($retries > 0) {
                usleep(rand(1, 5000));
            }
            $retries += 1;
        } while (!flock($fp, LOCK_EX) && $retries <= $max_retries);
 
        // couldn't get the lock
        if ($retries == $max_retries) {
            return false;
        }
 
        // got lock, write data
        fwrite($fp, implode(PHP_EOL, $dataArray).PHP_EOL);
 
        // release lock
        flock($fp, LOCK_UN);
        fclose($fp);
 
        return true;
    }

?>
