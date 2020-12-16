<?php
	include '../scripts/.env';

	$SEPARATOR = "/:::/";
	$X_WWW_FORM_URLENCODED = 1;
	$JSON = 2;
	$STATE_COOKIE = 'auth-state';
	$COOKIE_AGE = 600;
	$cookiePath = '/library/drawio/google.php';
	$postType = $X_WWW_FORM_URLENCODED;

	$queries = getQuery([]);
	if(array_key_exists('getState', $queries)) {
		$stateOnly = getParam('getState');
		if($stateOnly == "1") {
			// $stateB = generateRandomString(32);
			$key = generateRandomString(32);
			setcookie($STATE_COOKIE, $key, time()+3600*24);
			header("HTTP/1.1 200 OK");
			header("Set-Cookie:{$STATE_COOKIE}={$key}; Max-Age={$COOKIE_AGE}; path={$cookiePath}; Secure; HttpOnly; SameTime=none");
			header("Content-Type:text/plain");
			// response.setHeader("Set-Cookie", STATE_COOKIE + "=" + key + "; Max-Age=" + COOKIE_AGE + ";path=" + cookiePath + "; Secure; HttpOnly; SameSite=none"); //10 min to finish auth
			// response.setHeader("Content-Type", "text/plain");
			return;
		}
	}

	$code = null;
	if(array_key_exists('code', $queries)) {
		$code = getParam('code');
	}
	$refreshToken = null;
	if(array_key_exists('refresh_token', $queries)) {
		$refreshToken = getParam('refresh_token');
	}
	$error = null;
	if(array_key_exists('error', $queries)) {
		$error = getParam('error');
	}

	// In env
	$secret = $client_secret;
	$redirectUri = 'https://' . $_SERVER['HTTP_HOST'] . '/library/drawio/google.php';
	$client = $client_id;
	$service_url = "https://www.googleapis.com/oauth2/v4/token";

	$domain = null;
	$stateToken = null;
	$cookieToken = null;
	$version = null;
	$successRedirect = null;

	try {
		$state = array();

		try {

			if(array_key_exists('state', $queries)) {

				parse_str(getParam('state'), $state);
				$domain = $state['domain'];
				$client = $state['cId'];
				$stateToken = $state['token'];
				$version = $state['ver'];
				if(array_key_exists('redirect', $state)) {
					$successRedirect = $state['redirect'];
				}
				if($successRedirect != null) {
					$pos = strpos('http', $successRedirect);
					if($pos != false && $pos == 0) {
						$successRedirect = null;
					}
				}

				if(isset($_COOKIE[$STATE_COOKIE])) {
					$cacheKey = $_COOKIE[$STATE_COOKIE];
					// Todo, get cached token, or simply make cookie the token
					$cookieToken = $cacheKey;
					header("Set-Cookie:{$STATE_COOKIE}={$key}; path={$cookiePath}; expires=Thu, 01 Jan 1970 00:00:00 UTC; Secure; HttpOnly; SameSite=none");
				}
			}
		}
		catch(Exception $e) {	

		}

		if (($code == null && $refreshToken == null) || $client == null || $redirectUri == null || $secret == null) {
			// Bad request
			http_response_code(400);
		}
		// else if (!"Non".equals(SystemProperty.environment.get()) && (stateToken == null || !stateToken.equals(cookieToken)))
		// TODO: get cookies working
		else if (($stateToken == null || $stateToken != $cookieToken) && false) {
			// Unauthorized
			http_response_code(401);
		} else {
			$resp = contactOAuthServer($service_url, $code, $refreshToken, $secret, $client, $redirectUri, $successRedirect != null, 1);
			http_response_code($resp['status']);
			if(array_key_exists('content', $resp)) {
				if($successRedirect != null) {
					header('Location: '. $successRedirect . '#' . urlencode($resp['content']) );
				} else {
					echo $resp['content'];
				}
			}
		}
	} catch(Exception $e) {
		// Internal error
		echo $e;
		http_response_code(500);

	}

	function contactOAuthServer($authSrvUrl, $code, $refreshToken, $secret, $client, $redirectUri, $directResp, $retryCount) {
		global $postType;
		global $X_WWW_FORM_URLENCODED;
		$response = null;
		try {
			$url = $authSrvUrl;
			$headers = null;
			$jsonResponse = false;

			if($postType == $X_WWW_FORM_URLENCODED) {
			
				$headers = [
					'Content-Type: application/x-www-form-urlencoded',
					'Content-Length: 0'
				];

				$url .= "?client_id={$client}";
				$url .= "&redirect_uri={$redirectUri}";
				$url .= "&client_secret={$secret}";

				if($code != null) {
					$url .= "&code={$code}";
					$url .= "&grant_type=authorization_code";
				} else {
					$url .= "&refresh_token={$refreshToken}";
					$url .= "&grant_type=refresh_token";
					$jsonResponse = true;
				}


			} else if ($postType == $JSON) {
				// Don't need this
				// $headers = ['Content-Type: application/json'];
				// urlParameters.append("{");
				// urlParameters.append("\"client_id\": \"");
				// urlParameters.append(client);
				// urlParameters.append("\", \"redirect_uri\": \"");
				// urlParameters.append(redirectUri);
				// urlParameters.append("\", \"client_secret\": \"");
				// urlParameters.append(secret);
			
				// if (code != null)
				// {
				// 	urlParameters.append("\", \"code\": \"");
				// 	urlParameters.append(code);
				// 	urlParameters.append("\", \"grant_type\": \"authorization_code\"}");
				// }
				// else
				// {
				// 	urlParameters.append("\", \"refresh_token\": \"");
				// 	urlParameters.append(refreshToken);
				// 	urlParameters.append("\", \"grant_type\": \"refresh_token\"}");
				// 	jsonResponse = true;
				// }
			}

	 		$curl = curl_init($url);
		    curl_setopt($curl, CURLOPT_POST, true);
		    // curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($data));
		    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
		    $resp = curl_exec($curl);
	  		$info = curl_getinfo($curl);
	  		$response = array();
	  		$response['status'] = $info['http_code'];

	  		// Break down response json into one string
	  		$content = $resp;
	  		// foreach($resp as $line) {
	  			// $content .= $line;
	  		// }

	  		if($directResp) {
	  			$response['content'] = $content;
	  		} else {
	  			$response['content'] = processAuthResponse($content, $jsonResponse);
	  		}

		    curl_close($curl);

		} catch(Exception $e) {
			if($retryCount > 0 && str_contains($e->getMessage(), "Connection timed out")) {
				$retryCount -= 1;
				return contactOAuthServer($authSrvUrl, $code, $refreshToken, $secret, $client, $redirectUri, $directResp, $retryCount);
			} else {
				echo $e;
				http_response_code(500);

			}
		}
		return $response;

	}

	function processAuthResponse($authRes, $jsonResponse) {
		$res = '';
		if(!$jsonResponse) {
			$res .= "<!DOCTYPE html><head>";
			$res .= "<script src=\"/connect/office365/js/drive.js\" type=\"text/javascript\"></script>";
			$res .= "<script type=\"text/javascript\">";
			$res .= "var authInfo = ";
		}

		$res .= $authRes;

		if(!$jsonResponse) {
			$res .= ";";
			$res .= "if (window.opener != null && window.opener.onGoogleDriveCallback != null)";
			$res .= "{";
			$res .= "	window.opener.onGoogleDriveCallback(authInfo, window);";
			$res .= "} else {";
			$res .= "	onGDriveCallback(authInfo);";
			$res .= "}";
			$res .= "</script>";
			$res .= "</head><body></body></html>";
		}
		return $res;

	}

	function generateRandomString($length = 10) {
	    // $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
	    $characters = '0123456789';
	    $charactersLength = strlen($characters);
	    $randomString = '';
	    for ($i = 0; $i < $length; $i++) {
	        $randomString .= $characters[rand(0, $charactersLength - 1)];
	    }
	    return $randomString;
	}

	function escape($value) {
	    $return = '';
	    for($i = 0; $i < strlen($value); ++$i) {
	        $char = $value[$i];
	        $ord = ord($char);
	        if($char !== "'" && $char !== "\"" && $char !== '\\' && $ord >= 32 && $ord <= 126)
	            $return .= $char;
	        else
	            $return .= '\\x' . dechex($ord);
	    }
	    return $return;
	}

	function getQuery($required=[]) {
		$queries = array();
		parse_str($_SERVER["QUERY_STRING"], $queries);

		foreach($required as $key) {
			if(!array_key_exists($key, $queries)) {
				error_response('Missing ' . $key . ' argument');
			}	
		}
		return $queries;
	}

	function getParam($param) {
		global $queries;
		return escape($queries[$param]);
	}
?>