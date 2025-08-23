<?php
/**
*    EazyHttp
*    easy, simple and fast HTTP requests for PHP, JavaScript, Python
*    https://github.com/foo123/EazyHttp
**/
if (!class_exists('EazyHttp', false))
{
class EazyHttp
{
    const VERSION = '0.1.0';

    public function __construct()
    {
    }

    public function get($uri, $data = array(), $headers = null, $cookies = null)
    {
        return $this->server_request('GET', $uri, $data, $headers, $cookies);
    }

    public function post($uri, $data = array(), $headers = null, $cookies = null)
    {
        return $this->server_request('POST', $uri, $data, $headers, $cookies);
    }

    public function getClient($uri, $data = array())
    {
        $this->client_request('GET', $uri, $data);
        return null;
    }

    public function postClient($uri, $data = array())
    {
        $this->client_request('POST', $uri, $data);
        return null;
    }

    protected function server_request($method, $uri, $data = null, $headers = null, $cookies = null)
    {
        $this->do_http(
            $method,
            $uri,
            $data,
            $headers,
            $cookies,
            $responseBody,
            $responseStatus,
            $responseHeaders,
            $responseCookies,
            array(
                'client'            => false,
                'follow_location'   => 1,
                'max_redirects'     => 3,
                'timeout'           => 40, // sec
            )
        );
        /*if (is_array($responseHeaders) && isset($responseHeaders['set-cookie']))
        {
            unset($responseHeaders['set-cookie']);
        }*/
        return (object)array(
            'status'    => $responseStatus,
            'content'   => $responseBody,
            'headers'   => $responseHeaders,
            'cookies'   => $responseCookies,
        );
    }

    protected function client_request($method, $uri, $data = null)
    {
        $this->do_http(
            $method,
            $uri,
            $data,
            null,
            null,
            $responseBody,
            $responseStatus,
            $responseHeaders,
            $responseCookies,
            array(
                'client'    => true,
            )
        );
    }

    protected function do_http($method = 'GET', $uri = '', $data = null, $headers = null, $cookies = null, &$responseBody = '', &$responseStatus = 0, &$responseHeaders = null, &$responseCookies = null, $options = array())
    {
        // TODO: support POST files ??
        // TODO: support more methods, eg PUT, DELETE, ..
        $responseStatus = 0;
        $responseBody = false;
        $responseHeaders = array();
        $responseCookies = array();

        if (!empty($uri))
        {
            $method = strtoupper((string)$method);

            if ($options['client'])
            {
                switch ($method)
                {
                    case 'POST':
                    $responseBody = $this->do_http_client('POST', $uri, $data, $options);
                    break;

                    case 'GET':
                    default:
                    $responseBody = $this->do_http_client('GET', $uri.(!empty($data) ? ((false === strpos($uri, '?') ? '?' : '&').http_build_query($data, '', '&')) : ''), '', $options);
                    break;
                }
            }
            else
            {
                if ('POST' === $method)
                {
                    $requestHeaders = $this->format_http_cookies($cookies, $this->format_http_header($headers, array('Content-type: application/x-www-form-urlencoded'), ': '), ': ');
                }
                else
                {
                    $requestHeaders = $this->format_http_cookies($cookies, $this->format_http_header($headers, array(), ': '), ': ');
                }

                if (function_exists('curl_init'))
                {
                    switch ($method)
                    {
                        case 'POST':
                        $responseBody = $this->do_http_curl('POST', $uri, !empty($data) ? http_build_query($data, '', '&') : '', $requestHeaders, $responseStatus, $responseHeaders, $responseCookies, $options);
                        break;

                        case 'GET':
                        default:
                        $responseBody = $this->do_http_curl('GET', $uri.(!empty($data) ? ((false === strpos($uri, '?') ? '?' : '&').http_build_query($data, '', '&')) : ''), '', $requestHeaders, $responseStatus, $responseHeaders, $responseCookies, $options);
                        break;
                    }
                }
                elseif (function_exists('stream_context_create') && function_exists('file_get_contents') && ini_get('allow_url_fopen'))
                {
                    switch ($method)
                    {
                        case 'POST':
                        $responseBody = $this->do_http_file('POST', $uri, !empty($data) ? http_build_query($data, '', '&') : '', $requestHeaders, $responseStatus, $responseHeaders, $responseCookies, $options);
                        break;

                        case 'GET':
                        default:
                        $responseBody = $this->do_http_file('GET', $uri.(!empty($data) ? ((false === strpos($uri, '?') ? '?' : '&').http_build_query($data, '', '&')) : ''), '', $requestHeaders, $responseStatus, $responseHeaders, $responseCookies, $options);
                        break;
                    }
                }
                elseif (('http://' === substr(strtolower($uri), 0, 7)) && function_exists('fsockopen'))
                {
                    switch ($method)
                    {
                        case 'POST':
                        $responseBody = $this->do_http_socket('POST', $uri, !empty($data) ? http_build_query($data, '', '&') : '', $requestHeaders, $responseStatus, $responseHeaders, $responseCookies, $options);
                        break;

                        case 'GET':
                        default:
                        $responseBody = $this->do_http_socket('GET', $uri.(!empty($data) ? ((false === strpos($uri, '?') ? '?' : '&').http_build_query($data, '', '&')) : ''), '', $requestHeaders, $responseStatus, $responseHeaders, $responseCookies, $options);
                        break;
                    }
                }
            }
        }
        return $this;
    }

    protected function datetime($time = null)
    {
        if (is_null($time)) $time = time();
        return gmdate('D, d M Y H:i:s', $time) . ' GMT';
    }

    protected function flatten($input, $output = array(), $prefix = null)
    {
        if (!empty($input))
        {
            foreach ($input as $key => $val)
            {
                $name = empty($prefix) ? $key : ($prefix."[$key]");

                if (is_array($val)) $output = $this->flatten($val, $output, $name);
                else $output[$name] = $val;
            }
        }
        return $output;
    }

    protected function parse_http_header($responseHeader)
    {
        $responseHeaders = array();
        foreach ($responseHeader as $header)
        {
            $header = explode(':', $header, 2);
            if (count($header) >= 2)
            {
                $k = strtolower(trim($header[0])); $v = trim($header[1]);
                if (!isset($responseHeaders[$k])) $responseHeaders[$k] = array($v);
                else $responseHeaders[$k][] = $v;
            }
        }
        return $responseHeaders;
    }

    protected function format_http_header($headers, $output = array(), $glue = '')
    {
        if (!empty($headers))
        {
            foreach ($headers as $key => $val)
            {
                if (is_array($val))
                {
                    foreach ($val as $v)
                    {
                        if (isset($v) && strlen((string)$v))
                        {
                            $output[] = ((string)$key) . $glue . ((string)$v);
                        }
                    }
                }
                else
                {
                    if (isset($val) && strlen((string)$val))
                    {
                        $output[] = ((string)$key) . $glue . ((string)$val);
                    }
                }
            }
        }
        return $output;
    }

    protected function parse_cookie($str, $isRaw = false)
    {
        $cookie = array(
            'isRaw' => $isRaw,
            'expires' => 0,
            'path' => '/',
            'domain' => null,
            'secure' => false,
            'httponly' => false,
            'samesite' => null,
            'partitioned' => false,
        );

        $parts = explode(';', strval($str));
        foreach ($parts as $i => $part) $parts[$i] = explode('=', $part, 2);

        $part = array_shift($parts);
        $name = !$isRaw ? urldecode(trim($part[0])) : trim($part[0]);
        $value = isset($part[1]) ? (!$isRaw ? urldecode(trim($part[1])) : trim($part[1])) : null;
        $cookie['name'] = $name;
        $cookie['value'] = $value;

        $data = array();
        foreach ($parts as $part)
        {
            $name = strtolower(trim($part[0]));
            $value = isset($part[1]) ? trim($part[1]) : true;
            $data[$name] = $value;
        }
        $cookie = array_merge($cookie, $data);

        if (!is_numeric($cookie['expires']))
        {
            $cookie['expires'] = strtotime($cookie['expires']) || 0;
        }
        $cookie['expires'] = 0 < $cookie['expires'] ? (int)$cookie['expires'] : 0;

        if (isset($cookie['max-age']) && ($cookie['max-age'] > 0 || $cookie['expires'] > time()))
        {
            $cookie['expires'] = time() + (int)$cookie['max-age'];
        }

        return $cookie;
    }

    protected function format_cookie($cookie, $toSet = false)
    {
        $RESERVED_CHARS_LIST = "=,; \t\r\n\v\f";
        $RESERVED_CHARS_FROM = array('=', ',', ';', ' ', "\t", "\r", "\n", "\v", "\f");
        $RESERVED_CHARS_TO = array('%3D', '%2C', '%3B', '%20', '%09', '%0D', '%0A', '%0B', '%0C');

        if (empty($cookie)) return '';

        $cookie = (array)$cookie;

        if (!isset($cookie['name'])) return '';

        $isRaw = !empty($cookie['isRaw']);

        $str = '';

        if ($isRaw)
        {
            $str = strval($cookie['name']);
        }
        else
        {
            $str = str_replace($RESERVED_CHARS_FROM, $RESERVED_CHARS_TO, strval($cookie['name']));
        }

        $str .= '=';

        if ('' === (string) $cookie['value'])
        {
            if ($toSet)
            {
                $str .= 'deleted; expires='.gmdate('D, d M Y H:i:s T', time() - 31536001).'; Max-Age=0';
            }
            else
            {
                return '';
            }
        }
        else
        {
            $str .= $isRaw ? strval($cookie['value']) : rawurlencode(strval($cookie['value']));
            if ($toSet)
            {
                if (0 !== $cookie['expires'])
                {
                    $str .= '; expires='.gmdate('D, d M Y H:i:s T', $cookie['expires']).'; Max-Age='.max(0, $cookie['expires']-time());
                }
            }
        }

        if ($toSet)
        {
            if (isset($cookie['path']))
            {
                $str .= '; path='.$cookie['path'];
            }

            if (isset($cookie['domain']))
            {
                $str .= '; domain='.$cookie['domain'];
            }

            if (!empty($cookie['secure']))
            {
                $str .= '; secure';
            }

            if (!empty($cookie['httponly']))
            {
                $str .= '; httponly';
            }

            if (isset($cookie['samesite']))
            {
                $str .= '; samesite='.$cookie['samesite'];
            }

            if (!empty($cookie['partitioned']))
            {
                $str .= '; partitioned';
            }
        }

        return $str;
    }

    protected function parse_http_cookies($responseHeaders)
    {
        $cookies = array();
        if (!empty($responseHeaders) && !empty($responseHeaders['set-cookie']))
        {
            foreach ($responseHeaders['set-cookie'] as $cookie_str)
            {
                $cookie = $this->parse_cookie($cookie_str);
                if (!empty($cookie)) $cookies[] = $cookie;
            }
        }
        return $cookies;
    }

    protected function format_http_cookies($cookies, $output = array(), $glue = '', $toSet = false)
    {
        if (!empty($cookies))
        {
            foreach ($cookies as $cookie)
            {
                if (!empty($cookie))
                {
                    if ($toSet)
                    {
                        $cookie_str = $this->format_cookie($cookie, true);
                        if (strlen($cookie_str)) $output[] = 'Set-Cookie' . $glue . $cookie_str;
                    }
                    else
                    {
                        $cookie_str = $this->format_cookie($cookie, false);
                        if (strlen($cookie_str)) $output[] = 'Cookie' . $glue . $cookie_str;
                    }
                }
            }
        }
        return $output;
    }

    protected function do_http_curl($method, $uri, $requestBody = '', $requestHeaders = array(), &$responseStatus = 0, &$responseHeaders = null, &$responseCookies = null, $options = array())
    {
        $responseHeader = array();
        // init
        $curl = curl_init($uri);

        // setup
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_FOLLOWLOCATION, $options['follow_location']);
        curl_setopt($curl, CURLOPT_MAXREDIRS, $options['max_redirects']);
        curl_setopt($curl, CURLOPT_TIMEOUT, (int)$options['timeout']); // sec
        curl_setopt($curl, CURLOPT_HEADERFUNCTION, function($curl, $header) use (&$responseHeader) {
            $responseHeader[] = trim($header);
            return strlen($header);
        });
        curl_setopt($curl, CURLOPT_HTTPHEADER, $requestHeaders);

        if ('POST' === strtoupper($method))
        {
            curl_setopt($curl, CURLOPT_POST, true);
            curl_setopt($curl, CURLOPT_POSTFIELDS, $requestBody);
        }
        else
        {
            curl_setopt($curl, CURLOPT_HTTPGET, true);
        }

        // make request
        try {
            $responseBody = @curl_exec($curl);
            $responseStatus = @curl_getinfo($curl, CURLINFO_HTTP_CODE);
        } catch (Exception $e) {
            $responseBody = false;
        }

        // close connection
        curl_close($curl);

        $responseHeaders = $this->parse_http_header($responseHeader);
        $responseCookies = $this->parse_http_cookies($responseHeaders);
        return $responseBody;
    }

    protected function do_http_socket($method, $uri, $requestBody = '', $requestHeaders = array(), &$responseStatus = 0, &$responseHeaders = null, &$responseCookies = null, $options = array())
    {
        // NOTE: cannot handle HTTPS, results in redirect to https://
        $redirects = 0;
        while ($redirects <= $options['max_redirects'])
        {
            $uri = parse_url($uri);
            $host = $uri['host'];
            $port = isset($uri['port']) ? intval($uri['port']) : 80;
            $path = $uri['path'];
            if (empty($path)) $path = '/';
            $query = $uri['query'];
            if (!empty($query)) $path .= '?'.$query;
            $timeout = (int)$options['timeout']; // sec
            $chunk = 1024; // bytes

            // open socket
            try {
                $fp = @fsockopen($host, $port, $errno, $errstr, $timeout);
            } catch (Exception $e) {
                $fp = null;
            }
            if (!$fp) return false;

            // make request
            $contentLength = strlen((string)$requestBody);
            fputs($fp, ('POST' === strtoupper($method) ? "POST" : "GET")." $path HTTP/1.1");
            fputs($fp, "\r\n"."Host: $host");
            if (!empty($requestHeaders)) fputs($fp, "\r\n".implode("\r\n", (array)$requestHeaders));
            fputs($fp, "\r\n"."Content-length: $contentLength");
            fputs($fp, "\r\n"."Connection: close");
            fputs($fp, "\r\n\r\n".($contentLength ? ((string)$requestBody) : ""));

            // receive response
            $response = '';
            while (!feof($fp)) $response .= fgets($fp, $chunk);

            // close socket
            fclose($fp);

            // parse headers and content
            $response = explode("\r\n\r\n", $response, 2);
            $responseHeader = isset($response[0]) ? $response[0] : '';
            $responseBody = isset($response[1]) ? $response[1] : '';
            $responseHeaders = $this->parse_http_header(empty($responseHeader) ? array() : array_map('trim', explode("\r\n", $responseHeader)));
            $responseCookies = $this->parse_http_cookies($responseHeaders);
            if (!empty($responseHeader) && preg_match('#HTTP/\\S*\\s+(\\d{3})#', $responseHeader, $m)) $responseStatus = (int)$m[1];
            if ($options['follow_location'] && (301 <= $responseStatus && $responseStatus <= 304) && preg_match('#Location:\\s*(\\S+)#i', $responseHeader, $m))
            {
                ++$redirects;
                $uri = $m[1];
                continue;
            }
            else
            {
                break;
            }
        }
        return $responseBody;
    }

    protected function do_http_file($method, $uri, $requestBody = '', $requestHeaders = array(), &$responseStatus = 0, &$responseHeaders = null, &$responseCookies = null, $options = array())
    {
        // setup
        $contentLength = strlen((string)$requestBody);
        // is content-length needed?? probably not
        $requestHeader = '';
        if (!empty($requestHeaders))
        {
            $requestHeader = implode("\r\n", (array)$requestHeaders);
            //$requestHeader .= "\r\nContent-length: $contentLength";
        }
        else
        {
            //$requestHeader = "Content-length: $contentLength";
        }
        $http = stream_context_create(array(
            'http' => array(
                'method'            => 'POST' === strtoupper($method) ? 'POST' : 'GET',
                'header'            => $requestHeader,
                'content'           => (string)$requestBody,
                'follow_location'   => $options['follow_location'],
                'max_redirects'     => $options['max_redirects'],
                'timeout'           => (float)$options['timeout'], // sec
                'ignore_errors'     => true,
            ),
        ));

        // open, make request and close
        try {
            $responseBody = @file_get_contents($uri, false, $http);
        } catch (Exception $e) {
            $responseBody = false;
        }

        if (!empty($http_response_header))
        {
            $responseHeader = array_merge(array(), $http_response_header);
            if (!empty($responseHeader) && preg_match('#HTTP/\\S*\\s+(\\d{3})#', $responseHeader[0], $m)) $responseStatus = (int)$m[1];
            $responseHeaders = $this->parse_http_header($responseHeader);
            $responseCookies = $this->parse_http_cookies($responseHeaders);
        }
        else
        {
            $responseStatus = 0;
            $responseHeaders = array();
            $responseCookies = array();
        }
        return $responseBody;
    }

    protected function do_http_client($method, $uri, $requestBody = '', $options = array())
    {
        switch (strtoupper($method))
        {
            case 'POST':
            if (!empty($requestBody))
            {
                if (is_array($requestBody))
                {
                    $requestData = $requestBody;
                }
                else
                {
                    $requestData = array();
                    @parse_str((string)$requestBody, $requestData);
                }
                $requestData = $this->flatten($requestData);
                $formData = implode('', array_map(function($name, $value) {return '<input type="hidden" name="'.$name.'" value="'.$value.'" />';}, array_keys($requestData), $requestData));
            }
            else
            {
                $formData = '';
            }
            try {
                @header('Content-Type: text/html; charset=UTF-8', true, 200);
                @header('Date: '.$this->datetime(time()), true, 200);
                echo ('<!DOCTYPE html><html><head><meta http-equiv="content-type" content="text/html; charset=UTF-8"/><title>POST '.$uri.'</title></head><body onload="do_post();"><form name="post_form" id="post_form" method="post" enctype="application/x-www-form-urlencoded" action="'.$uri.'">'.$formData.'</form><script type="text/javascript">function do_post() {document.post_form.submit();}</script></body></html>');
            } catch (Exception $e) {
            }
            break;

            case 'GET':
            default:
            try {
                @header("Location: $uri", true, 303);
                @header('Content-Type: text/html; charset=UTF-8', true, 303);
                @header('Date: '.$this->datetime(time()), true, 303);
                echo ('<!DOCTYPE html><html><head><meta http-equiv="content-type" content="text/html; charset=UTF-8"/><meta http-equiv="refresh" content="0; URL='.$uri.'"/><title>GET '.$uri.'</title></head><body onload="do_get();"><script type="text/javascript">function do_get() {window.location.href = "'.$uri.'";}</script></body></html>');
            } catch (Exception $e) {
            }
            break;
        }
        return '';
    }

    /*protected function do_http_request($method, $uri, $requestBody = '', $requestHeaders = array(), &$responseStatus = 0, &$responseHeaders = null, &$responseCookies = null, $options = array())
    {
        // not available
        $responseBody = http_request($method, $uri, $requestBody, $opts, &$info);
        return $responseBody;
    }*/
}
class EazyHttpException extends Exception
{
}
}