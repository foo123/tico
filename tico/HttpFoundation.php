<?php
/*
 * HttpFoundation for PHP5+
 * adapted from Symfony https://github.com/symfony/http-foundation v.7.3.1 06/2025
 * originally by Fabien Potencier <fabien@symfony.com>
 *
 */

class ParameterBag implements \IteratorAggregate, \Countable
{
    protected $parameters;
    public function __construct(/*array*/ $parameters = array())
    {
        $this->parameters = $parameters;
    }

    public function all($key = null)
    {
        return null !== $key ? (isset($this->parameters[$key]) ? $this->parameters[$key] : null) : $this->parameters;
    }

    public function keys()
    {
        return array_keys($this->parameters);
    }

    public function replace(/*array*/ $parameters = array())
    {
        $this->parameters = $parameters;
    }

    public function add(/*array*/ $parameters = array())
    {
        $this->parameters = array_replace($this->parameters, $parameters);
    }

    public function get($key, $default = null)
    {
        return array_key_exists($key, $this->parameters) ? $this->parameters[$key] : $default;
    }

    public function set($key, $value)
    {
        $this->parameters[$key] = $value;
    }

    public function has($key)
    {
        return array_key_exists($key, $this->parameters);
    }

    public function remove($key)
    {
        unset($this->parameters[$key]);
    }

    public function getAlpha($key, $default = '')
    {
        return preg_replace('/[^a-zA-Z]/', '', $this->getString($key, $default));
    }

    public function getAlnum($key, $default = '')
    {
        return preg_replace('/[^a-zA-Z0-9]/', '', $this->getString($key, $default));
    }

    public function getDigits($key, $default = '')
    {
        return preg_replace('/[^0-9]/', '', $this->getString($key, $default));
    }

    public function getString($key, $default = '')
    {
        return (string) $this->get($key, $default);
    }

    public function getInt($key, $default = 0)
    {
        return (int) $this->filter($key, $default, FILTER_VALIDATE_INT, array('flags' => FILTER_REQUIRE_SCALAR));
    }

    public function getBoolean($key, $default = false)
    {
        return (bool) $this->filter($key, $default, FILTER_VALIDATE_BOOLEAN, array('flags' => FILTER_REQUIRE_SCALAR));
    }

    public function getEnum($key, $class, $default = null)
    {
        $value = $this->get($key);

        if (null === $value) {
            return $default;
        }

        return $class::from($value);
    }

    public function filter($key, $default = null, $filter = FILTER_DEFAULT, $options = array())
    {
        $value = $this->get($key, $default);

        // Always turn $options into an array - this allows filter_var option shortcuts.
        if (!is_array($options) && $options) {
            $options = array('flags' => $options);
        }

        // Add a convenience check for arrays.
        if (is_array($value) && !isset($options['flags'])) {
            $options['flags'] = FILTER_REQUIRE_ARRAY;
        }

        /*if (!isset($options['flags'])) $options['flags'] = 0;
        $nullOnFailure = $options['flags'] & FILTER_NULL_ON_FAILURE;
        $options['flags'] |= FILTER_NULL_ON_FAILURE;

        $value = filter_var($value, $filter, $options);

        if ((null !== $value) || $nullOnFailure) {
            return $value;
        }*/
        return filter_var($value, $filter, $options);
    }

    #[\ReturnTypeWillChange]
    public function getIterator()
    {
        return new \ArrayIterator($this->parameters);
    }

    #[\ReturnTypeWillChange]
    public function count()
    {
        return count($this->parameters);
    }

    public function getHeaders()
    {
        $headers = array();
        foreach ($this->parameters as $key => $value) {
            if (0 === strpos($key, 'HTTP_')) {
                $headers[substr($key, 5)] = $value;
            } elseif (in_array($key, array('CONTENT_TYPE', 'CONTENT_LENGTH', 'CONTENT_MD5'), true) && '' !== $value) {
                $headers[$key] = $value;
            }
        }

        if (isset($this->parameters['PHP_AUTH_USER'])) {
            $headers['PHP_AUTH_USER'] = $this->parameters['PHP_AUTH_USER'];
            $headers['PHP_AUTH_PW'] = isset($this->parameters['PHP_AUTH_PW']) ? $this->parameters['PHP_AUTH_PW'] :  '';
        } else {
            /*
             * php-cgi under Apache does not pass HTTP Basic user/pass to PHP by default
             * For this workaround to work, add these lines to your .htaccess file:
             * RewriteCond %{HTTP:Authorization} .+
             * RewriteRule ^ - [E=HTTP_AUTHORIZATION:%0]
             *
             * A sample .htaccess file:
             * RewriteEngine On
             * RewriteCond %{HTTP:Authorization} .+
             * RewriteRule ^ - [E=HTTP_AUTHORIZATION:%0]
             * RewriteCond %{REQUEST_FILENAME} !-f
             * RewriteRule ^(.*)$ index.php [QSA,L]
             */

            $authorizationHeader = null;
            if (isset($this->parameters['HTTP_AUTHORIZATION'])) {
                $authorizationHeader = $this->parameters['HTTP_AUTHORIZATION'];
            } elseif (isset($this->parameters['REDIRECT_HTTP_AUTHORIZATION'])) {
                $authorizationHeader = $this->parameters['REDIRECT_HTTP_AUTHORIZATION'];
            }

            if (null !== $authorizationHeader) {
                if (0 === stripos($authorizationHeader, 'basic ')) {
                    // Decode AUTHORIZATION header into PHP_AUTH_USER and PHP_AUTH_PW when authorization header is basic
                    $exploded = explode(':', base64_decode(substr($authorizationHeader, 6)), 2);
                    if (2 == \count($exploded)) {
                        list($AUTH_USER, $AUTH_PW) = $exploded;
                        $headers['PHP_AUTH_USER'] = $AUTH_USER;
                        $headers['PHP_AUTH_PW'] = $AUTH_PW;
                    }
                } elseif (empty($this->parameters['PHP_AUTH_DIGEST']) && (0 === stripos($authorizationHeader, 'digest '))) {
                    // In some circumstances PHP_AUTH_DIGEST needs to be set
                    $headers['PHP_AUTH_DIGEST'] = $authorizationHeader;
                    $this->parameters['PHP_AUTH_DIGEST'] = $authorizationHeader;
                } elseif (0 === stripos($authorizationHeader, 'bearer ')) {
                    /*
                     * XXX: Since there is no PHP_AUTH_BEARER in PHP predefined variables,
                     *      I'll just set $headers['AUTHORIZATION'] here.
                     *      https://php.net/reserved.variables.server
                     */
                    $headers['AUTHORIZATION'] = $authorizationHeader;
                }
            }
        }

        if (isset($headers['AUTHORIZATION'])) {
            return $headers;
        }

        // PHP_AUTH_USER/PHP_AUTH_PW
        if (isset($headers['PHP_AUTH_USER'])) {
            $headers['AUTHORIZATION'] = 'Basic '.base64_encode($headers['PHP_AUTH_USER'].':'.(isset($headers['PHP_AUTH_PW']) ? $headers['PHP_AUTH_PW'] : ''));
        } elseif (isset($headers['PHP_AUTH_DIGEST'])) {
            $headers['AUTHORIZATION'] = $headers['PHP_AUTH_DIGEST'];
        }

        return $headers;
    }
}

class HttpFileBag extends ParameterBag
{
    private static $fileKeys0 = array('error', 'name', 'size', 'tmp_name', 'type');
    private static $fileKeys = array('error', 'full_path', 'name', 'size', 'tmp_name', 'type');

    public function __construct(/*array*/ $parameters = array())
    {
        $this->replace($parameters);
    }

    public function replace(/*array*/ $files = array())
    {
        $this->parameters = array();
        $this->add($files);
    }

    public function set($key, $value)
    {
        if (!is_array($value) /*&& !$value instanceof UploadedFile*/) {
            throw new \InvalidArgumentException('An uploaded file must be an array or an instance of UploadedFile.');
        }

        parent::set($key, $this->convertFileInformation($value));
    }

    public function add(/*array*/ $files = array())
    {
        foreach ($files as $key => $file) {
            $this->set($key, $file);
        }
    }

    protected function convertFileInformation($file)
    {
        /*if ($file instanceof UploadedFile) {
            return $file;
        }*/

        $file = $this->fixPhpFilesArray($file);
        if (is_array($file)) {
            $keys = array_keys($file);
            sort($keys);

            if ($keys == self::$fileKeys || $keys == self::$fileKeys0) {
                if (UPLOAD_ERR_NO_FILE == $file['error']) {
                    $file = null;
                } else {
                    //$file = new UploadedFile($file['tmp_name'], $file['name'], $file['type'], $file['size'], $file['error']);
                }
            } else {
                $file = array_map(array($this, 'convertFileInformation'), $file);
                if (array_keys($keys) === $keys) {
                    $file = array_filter($file);
                }
            }
        }

        return $file;
    }

    protected function fixPhpFilesArray($data)
    {
        if (!is_array($data)) {
            return $data;
        }

        $keys = array_keys($data);
        sort($keys);

        if ((self::$fileKeys != $keys && self::$fileKeys0 != $keys) || !isset($data['name']) || !is_array($data['name'])) {
            return $data;
        }

        $files = $data;
        foreach (self::$fileKeys as $k) {
            unset($files[$k]);
        }

        foreach ($data['name'] as $key => $name) {
            $files[$key] = $this->fixPhpFilesArray(array(
                'error' => $data['error'][$key],
                'full_path' => isset($data['full_path'][$key]) ? $data['full_path'][$key] : null,
                'name' => $name,
                'tmp_name' => $data['tmp_name'][$key],
                'size' => $data['size'][$key],
                'type' => $data['type'][$key],
            ));
        }

        return $files;
    }
}

class HttpIpUtils
{
    const PRIVATE_SUBNETS = array(
        // PRIVATE_SUBNETS
        '127.0.0.0/8',    // RFC1700 (Loopback)
        '10.0.0.0/8',     // RFC1918
        '192.168.0.0/16', // RFC1918
        '172.16.0.0/12',  // RFC1918
        '169.254.0.0/16', // RFC3927
        '0.0.0.0/8',      // RFC5735
        '240.0.0.0/4',    // RFC1112
        '::1/128',        // Loopback
        'fc00::/7',       // Unique Local Address
        'fe80::/10',      // Link Local Address
        '::ffff:0:0/96',  // IPv4 translations
        '::/128',         // Unspecified address
    );

    private static $checkedIps = array();

    private function __construct()
    {
    }

    public static function checkIp($requestIp, $ips)
    {
        if (!is_array($ips)) {
            $ips = array($ips);
        }

        $method = substr_count($requestIp, ':') > 1 ? 'checkIp6' : 'checkIp4';

        if ('checkIp6' === $method) {
            foreach ($ips as $ip) {
                if (self::checkIp6($requestIp, $ip)) {
                    return true;
                }
            }
        } else {
            foreach ($ips as $ip) {
                if (self::checkIp4($requestIp, $ip)) {
                    return true;
                }
            }
        }

        return false;
    }

    public static function checkIp4($requestIp, $ip)
    {
        $cacheKey = $requestIp.'-'.$ip.'-v4';
        if (isset(self::$checkedIps[$cacheKey])) {
            return self::$checkedIps[$cacheKey];
        }

        if (!filter_var($requestIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return self::$checkedIps[$cacheKey] = false;
        }

        if (false !== strpos($ip, '/')) {
            list($address, $netmask) = explode('/', $ip, 2);

            if ('0' === $netmask) {
                return self::$checkedIps[$cacheKey] = filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
            }

            if ($netmask < 0 || $netmask > 32) {
                return self::$checkedIps[$cacheKey] = false;
            }
        } else {
            $address = $ip;
            $netmask = 32;
        }

        if (false === ip2long($address)) {
            return self::$checkedIps[$cacheKey] = false;
        }

        return self::$checkedIps[$cacheKey] = 0 === substr_compare(sprintf('%032b', ip2long($requestIp)), sprintf('%032b', ip2long($address)), 0, $netmask);
    }

    public static function checkIp6($requestIp, $ip)
    {
        $cacheKey = $requestIp.'-'.$ip.'-v6';
        if (isset(self::$checkedIps[$cacheKey])) {
            return self::$checkedIps[$cacheKey];
        }

        if (!((extension_loaded('sockets') && defined('AF_INET6')) || @inet_pton('::1'))) {
            throw new \RuntimeException('Unable to check Ipv6. Check that PHP was not compiled with option "disable-ipv6".');
        }

        // Check to see if we were given a IP4 $requestIp or $ip by mistake
        if (!filter_var($requestIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return self::$checkedIps[$cacheKey] = false;
        }

        if (false !== strpos($ip, '/')) {
            list($address, $netmask) = explode('/', $ip, 2);

            if (!filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                return self::$checkedIps[$cacheKey] = false;
            }

            if ('0' === $netmask) {
                return (bool) unpack('n*', @inet_pton($address));
            }

            if ($netmask < 1 || $netmask > 128) {
                return self::$checkedIps[$cacheKey] = false;
            }
        } else {
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                return self::$checkedIps[$cacheKey] = false;
            }
            $address = $ip;
            $netmask = 128;
        }

        $bytesAddr = unpack('n*', @inet_pton($address));
        $bytesTest = unpack('n*', @inet_pton($requestIp));

        if (empty($bytesAddr) || empty($bytesTest)) {
            return self::$checkedIps[$cacheKey] = false;
        }

        for ($i = 1, $ceil = ceil($netmask / 16); $i <= $ceil; ++$i) {
            $left = $netmask - 16 * ($i - 1);
            $left = ($left <= 16) ? $left : 16;
            $mask = ~(0xffff >> $left) & 0xffff;
            if (($bytesAddr[$i] & $mask) != ($bytesTest[$i] & $mask)) {
                return self::$checkedIps[$cacheKey] = false;
            }
        }

        return self::$checkedIps[$cacheKey] = true;
    }

    public static function anonymize($ip/* , int $v4Bytes = 1, int $v6Bytes = 8 */)
    {
        $v4Bytes = 1 < func_num_args() ? func_get_arg(1) : 1;
        $v6Bytes = 2 < func_num_args() ? func_get_arg(2) : 8;

        if ($v4Bytes < 0 || $v6Bytes < 0) {
            throw new \InvalidArgumentException('Cannot anonymize less than 0 bytes.');
        }

        if ($v4Bytes > 4 || $v6Bytes > 16) {
            throw new \InvalidArgumentException('Cannot anonymize more than 4 bytes for IPv4 and 16 bytes for IPv6.');
        }

        /**
         * If the IP contains a % symbol, then it is a local-link address with scoping according to RFC 4007
         * In that case, we only care about the part before the % symbol, as the following functions, can only work with
         * the IP address itself. As the scope can leak information (containing interface name), we do not want to
         * include it in our anonymized IP data.
         */
        if (false !== ($pos=strpos($ip, '%'))) {
            $ip = substr($ip, 0, $pos);
        }

        $wrappedIPv6 = false;
        if ('[' === substr($ip, 0, 1) && ']' === substr($ip, -1, 1)) {
            $wrappedIPv6 = true;
            $ip = substr($ip, 1, -1);
        }

        $mappedIpV4MaskGenerator = function ($mask, $bytesToAnonymize) {
            $mask .= str_repeat('ff', 4 - $bytesToAnonymize);
            $mask .= str_repeat('00', $bytesToAnonymize);

            return '::'.implode(':', str_split($mask, 4));
        };

        $packedAddress = inet_pton($ip);
        if (4 === strlen($packedAddress)) {
            $mask = rtrim(str_repeat('255.', 4 - $v4Bytes).str_repeat('0.', $v4Bytes), '.');
        } elseif ($ip === inet_ntop($packedAddress & inet_pton('::ffff:ffff:ffff'))) {
            $mask = $mappedIpV4MaskGenerator('ffff', $v4Bytes);
        } elseif ($ip === inet_ntop($packedAddress & inet_pton('::ffff:ffff'))) {
            $mask = $mappedIpV4MaskGenerator('', $v4Bytes);
        } else {
            $mask = str_repeat('ff', 16 - $v6Bytes).str_repeat('00', $v6Bytes);
            $mask = implode(':', str_split($mask, 4));
        }
        $ip = inet_ntop($packedAddress & inet_pton($mask));

        if ($wrappedIPv6) {
            $ip = '['.$ip.']';
        }

        return $ip;
    }

    public static function isPrivateIp($requestIp)
    {
        return self::checkIp($requestIp, self::PRIVATE_SUBNETS);
    }
}

class HttpHeaderUtils
{
    private function __construct()
    {
    }

    public static function split(/*string*/ $header, /*string*/ $separators)/*: array*/
    {
        $quotedSeparators = preg_quote($separators, '/');

        preg_match_all('
            /
                (?!\s)
                    (?:
                        # quoted-string
                        "(?:[^"\\\\]|\\\\.)*(?:"|\\\\|$)
                    |
                        # token
                        [^"'.$quotedSeparators.']+
                    )+
                (?<!\s)
            |
                # separator
                \s*
                '//(?<separator>['.$quotedSeparators.'])
                .'(['.$quotedSeparators.'])
                \s*
            /x', trim($header), $matches, PREG_SET_ORDER);

        return self::groupParts($matches, $separators);
    }

    public static function combine(/*array*/ $parts)/*: array*/
    {
        $assoc = array();
        foreach ($parts as $part) {
            $name = strtolower($part[0]);
            $value = isset($part[1]) ? $part[1] : true;
            $assoc[$name] = $value;
        }

        return $assoc;
    }

    public static function toString(/*array*/ $assoc, /*string*/ $separator)/*: string*/
    {
        $parts = array();
        foreach ($assoc as $name => $value) {
            if (true === $value) {
                $parts[] = $name;
            } else {
                $parts[] = $name.'='.self::quote($value);
            }
        }

        return implode($separator.' ', $parts);
    }

    public static function quote(/*string*/ $s)/*: string*/
    {
        if (preg_match('/^[a-z0-9!#$%&\'*.^_`|~-]+$/i', $s)) {
            return $s;
        }

        return '"'.addcslashes($s, '"\\"').'"';
    }

    public static function unquote(/*string*/ $s)/*: string*/
    {
        return preg_replace('/\\\\(.)|"/', '$1', $s);
    }

    public static function makeDisposition(/*string*/ $disposition, /*string*/ $filename, /*string*/ $filenameFallback = '')/*: string*/
    {
        if (!in_array($disposition, array('attachment', 'inline'))) {
            throw new \InvalidArgumentException(\sprintf('The disposition must be either "%s" or "%s".', 'attachment', 'inline'));
        }

        if ('' === $filenameFallback) {
            $filenameFallback = $filename;
        }

        // filenameFallback is not ASCII.
        if (!preg_match('/^[\x20-\x7e]*$/', $filenameFallback)) {
            throw new \InvalidArgumentException('The filename fallback must only contain ASCII characters.');
        }

        // percent characters aren't safe in fallback.
        if (false !== strpos($filenameFallback, '%')) {
            throw new \InvalidArgumentException('The filename fallback cannot contain the "%" character.');
        }

        // path separators aren't allowed in either.
        if (false !== strpos($filename, '/') || false !== strpos($filename, '\\') || false !== strpos($filenameFallback, '/') || false !== strpos($filenameFallback, '\\')) {
            throw new \InvalidArgumentException('The filename and the fallback cannot contain the "/" and "\\" characters.');
        }

        $params = array('filename' => $filenameFallback);
        if ($filename !== $filenameFallback) {
            $params['filename*'] = "utf-8''".rawurlencode($filename);
        }

        return $disposition.'; '.self::toString($params, ';');
    }

    public static function parseQuery(/*string*/ $query, /*bool*/ $ignoreBrackets = false, /*string*/ $separator = '&')/*: array*/
    {
        $q = array();

        $arr = explode($separator, $query);
        foreach ($arr as $v) {
            if (false !== $i = strpos($v, "\0")) {
                $v = substr($v, 0, $i);
            }

            if (false === $i = strpos($v, '=')) {
                $k = urldecode($v);
                $v = '';
            } else {
                $k = urldecode(substr($v, 0, $i));
                $v = substr($v, $i);
            }

            if (false !== $i = strpos($k, "\0")) {
                $k = substr($k, 0, $i);
            }

            $k = ltrim($k, ' ');

            if ($ignoreBrackets) {
                $q[$k][] = urldecode(substr($v, 1));

                continue;
            }

            if (false === $i = strpos($k, '[')) {
                $q[] = bin2hex($k).$v;
            } else {
                $q[] = bin2hex(substr($k, 0, $i)).rawurlencode(substr($k, $i)).$v;
            }
        }

        if ($ignoreBrackets) {
            return $q;
        }

        parse_str(implode('&', $q), $q);

        $query = array();

        foreach ($q as $k => $v) {
            if (false !== $i = strpos($k, '_')) {
                $query[substr_replace($k, hex2bin(substr($k, 0, $i)).'[', 0, 1 + $i)] = $v;
            } else {
                $query[hex2bin($k)] = $v;
            }
        }

        return $query;
    }

    private static function groupParts(/*array*/ $matches, /*string*/ $separators, /*bool*/ $first = true)/*: array*/
    {
        $separator = substr($separators, 0, 1);
        $separators = substr($separators, 1);
        $i = 0;

        if ('' === $separators && !$first) {
            $parts = array('');

            foreach ($matches as $match) {
                if (!$i && isset($match[1/*'separator'*/])) {
                    $i = 1;
                    $parts[1] = '';
                } else {
                    $parts[$i] .= self::unquote($match[0]);
                }
            }

            return $parts;
        }

        $parts = array();
        $partMatches = array();

        foreach ($matches as $match) {
            if ((isset($match[1/*'separator'*/]) && $match[1/*'separator'*/] === $separator) || (!isset($match[1/*'separator'*/]) && '' === $separator)) {
                ++$i;
            } else {
                if (!isset($partMatches[$i])) $partMatches[$i] = array();
                $partMatches[$i][] = $match;
            }
        }

        foreach ($partMatches as $matches) {
            if ('' === $separators && '' !== $unquoted = self::unquote($matches[0][0])) {
                $parts[] = $unquoted;
            } elseif ($groupedParts = self::groupParts($matches, $separators, false)) {
                $parts[] = $groupedParts;
            }
        }

        return $parts;
    }
}

class HttpAcceptHeader
{
    private $items = array();

    private $sorted = true;

    public function __construct(/*array*/ $items)
    {
        foreach ($items as $item) {
            $this->add($item);
        }
    }

    public static function fromString($headerValue)
    {
        $parts = HttpHeaderUtils::split(isset($headerValue) ? $headerValue : '', ',;=');

        return new self(array_map(function ($subParts) {
            static $index = 0;
            $part = array_shift($subParts);
            $attributes = HttpHeaderUtils::combine($subParts);

            $item = new HttpAcceptHeaderItem($part[0], $attributes);
            $item->setIndex($index++);

            return $item;
        }, $parts));
    }

    public function __toString()
    {
        return implode(',', $this->items);
    }

    public function has($value)
    {
        return isset($this->items[$value]);
    }

    public function get($value)
    {
        if (isset($this->items[$value])) return $this->items[$value];
        $vs = explode('/', $value);
        $v = $vs[0].'/*';
        if (isset($this->items[$v])) return $this->items[$v];
        if (isset($this->items['*/*'])) return $this->items['*/*'];
        if (isset($this->items['*'])) return $this->items['*'];
        return null;
    }

    public function add(/*HttpAcceptHeaderItem*/ $item)
    {
        $this->items[$item->getValue()] = $item;
        $this->sorted = false;

        return $this;
    }

    public function all()
    {
        $this->sort();

        return $this->items;
    }

    public function filter($pattern)
    {
        return new self(array_filter($this->items, function (/*HttpAcceptHeaderItem*/ $item) use ($pattern) {
            return preg_match($pattern, $item->getValue());
        }));
    }

    public function first()
    {
        $this->sort();

        return !empty($this->items) ? reset($this->items) : null;
    }

    private function sort()
    {
        if (!$this->sorted) {
            uasort($this->items, function (/*HttpAcceptHeaderItem*/ $a, /*HttpAcceptHeaderItem*/ $b) {
                $qA = $a->getQuality();
                $qB = $b->getQuality();

                if ($qA === $qB) {
                    return $a->getIndex() > $b->getIndex() ? 1 : -1;
                }

                return $qA > $qB ? -1 : 1;
            });

            $this->sorted = true;
        }
    }
}

class HttpAcceptHeaderItem
{
    private $value;
    private $quality = 1.0;
    private $index = 0;
    private $attributes = array();

    public function __construct(/*string*/ $value, /*array*/ $attributes = array())
    {
        $this->value = $value;
        foreach ($attributes as $name => $value) {
            $this->setAttribute($name, $value);
        }
    }

    public static function fromString($itemValue)
    {
        $parts = HttpHeaderUtils::split(isset($itemValue) ? $itemValue : '', ';=');

        $part = array_shift($parts);
        $attributes = HttpHeaderUtils::combine($parts);

        return new self($part[0], $attributes);
    }

    public function __toString()
    {
        $string = $this->value.($this->quality < 1 ? ';q='.$this->quality : '');
        if (count($this->attributes) > 0) {
            $string .= '; '.HttpHeaderUtils::toString($this->attributes, ';');
        }

        return $string;
    }

    public function setValue($value)
    {
        $this->value = $value;

        return $this;
    }

    public function getValue()
    {
        return $this->value;
    }

    public function setQuality($quality)
    {
        $this->quality = $quality;

        return $this;
    }

    public function getQuality()
    {
        return $this->quality;
    }

    public function setIndex($index)
    {
        $this->index = $index;

        return $this;
    }

    public function getIndex()
    {
        return $this->index;
    }

    public function hasAttribute($name)
    {
        return isset($this->attributes[$name]);
    }

    public function getAttribute($name, $default = null)
    {
        return isset($this->attributes[$name]) ? $this->attributes[$name] : $default;
    }

    public function getAttributes()
    {
        return $this->attributes;
    }

    public function setAttribute($name, $value)
    {
        if ('q' === $name) {
            $this->quality = (float) $value;
        } else {
            $this->attributes[$name] = (string) $value;
        }

        return $this;
    }
}

class HttpRequest
{
    const HEADER_FORWARDED = 0b000001; // When using RFC 7239
    const HEADER_X_FORWARDED_FOR = 0b000010;
    const HEADER_X_FORWARDED_HOST = 0b000100;
    const HEADER_X_FORWARDED_PROTO = 0b001000;
    const HEADER_X_FORWARDED_PORT = 0b010000;
    const HEADER_X_FORWARDED_PREFIX = 0b100000;

    const HEADER_X_FORWARDED_AWS_ELB = 0b0011010; // AWS ELB doesn't send X-Forwarded-Host
    const HEADER_X_FORWARDED_TRAEFIK = 0b0111110; // All "X-Forwarded-*" headers sent by Traefik reverse proxy

    const METHOD_HEAD = 'HEAD';
    const METHOD_GET = 'GET';
    const METHOD_POST = 'POST';
    const METHOD_PUT = 'PUT';
    const METHOD_PATCH = 'PATCH';
    const METHOD_DELETE = 'DELETE';
    const METHOD_PURGE = 'PURGE';
    const METHOD_OPTIONS = 'OPTIONS';
    const METHOD_TRACE = 'TRACE';
    const METHOD_CONNECT = 'CONNECT';

    protected static $trustedProxies = array();

    protected static $trustedHostPatterns = array();

    protected static $trustedHosts = array();

    protected static $httpMethodParameterOverride = false;

    public $attributes;

    public $request;

    public $query;
    public $queryci;

    public $server;

    public $files;

    public $cookies;

    public $headers;

    protected $content;

    protected $languages;

    protected $charsets;

    protected $encodings;

    protected $acceptableContentTypes;

    protected $pathInfo;

    protected $requestUri;

    protected $baseUrl;

    protected $basePath;

    protected $method;

    protected $format;

    protected $session;

    protected $locale;

    protected $defaultLocale = 'en';

    protected static $formats;

    protected static $requestFactory;

    private $preferredFormat = null;
    private $isHostValid = true;
    private $isForwardedValid = true;
    private $isSafeContentPreferred;

    private $trustedValuesCache = array();

    private static $trustedHeaderSet = -1;

    private static $forwardedParams = array(
        self::HEADER_X_FORWARDED_FOR => 'for',
        self::HEADER_X_FORWARDED_HOST => 'host',
        self::HEADER_X_FORWARDED_PROTO => 'proto',
        self::HEADER_X_FORWARDED_PORT => 'host',
    );

    private static $trustedHeaders = array(
        self::HEADER_FORWARDED => 'FORWARDED',
        self::HEADER_X_FORWARDED_FOR => 'X_FORWARDED_FOR',
        self::HEADER_X_FORWARDED_HOST => 'X_FORWARDED_HOST',
        self::HEADER_X_FORWARDED_PROTO => 'X_FORWARDED_PROTO',
        self::HEADER_X_FORWARDED_PORT => 'X_FORWARDED_PORT',
        self::HEADER_X_FORWARDED_PREFIX => 'X_FORWARDED_PREFIX',
    );

    private $isIisRewrite = false;

    public static function queryCI($query)
    {
        $queryci = array();
        foreach ($query as $key => $val) {
            $queryci[strtolower($key)] = $val;
        }
        return $queryci;
    }

    public function __construct(/*array*/ $query = array(), /*array*/ $request = array(), /*array*/ $attributes = array(), /*array*/ $cookies = array(), /*array*/ $files = array(), /*array*/ $server = array(), $content = null)
    {
        $this->initialize($query, $request, $attributes, $cookies, $files, $server, $content);
    }

    public function initialize(/*array*/ $query = array(), /*array*/ $request = array(), /*array*/ $attributes = array(), /*array*/ $cookies = array(), /*array*/ $files = array(), /*array*/ $server = array(), $content = null)
    {
        $this->request = new ParameterBag($request);
        $this->query = new ParameterBag($query);
        $this->queryci = new ParameterBag(self::queryCI($query));
        $this->attributes = new ParameterBag($attributes);
        $this->cookies = new ParameterBag($cookies);
        $this->files = new HttpFileBag($files);
        $this->server = new ParameterBag($server);
        $this->headers = new HttpHeaderBag($this->server->getHeaders());

        $this->content = $content;
        $this->languages = null;
        $this->charsets = null;
        $this->encodings = null;
        $this->acceptableContentTypes = null;
        $this->pathInfo = null;
        $this->requestUri = null;
        $this->baseUrl = null;
        $this->basePath = null;
        $this->method = null;
        $this->format = null;
    }

    public static function createFromGlobals()
    {
        $request = self::createRequestFromFactory($_GET, $_POST, array(), $_COOKIE, $_FILES, $_SERVER);
        $contentType = $request->headers->get('CONTENT_TYPE');

        if (is_string($contentType) && (0 == strpos($contentType, 'application/x-www-form-urlencoded'))
            && in_array(strtoupper($request->server->get('REQUEST_METHOD', 'GET')), array('PUT', 'DELETE', 'PATCH'))
        ) {
            parse_str($request->getContent(), $data);
            $request->request = new ParameterBag($data);
        }

        return $request;
    }

    public static function create($uri, $method = 'GET', $parameters = array(), $cookies = array(), $files = array(), $server = array(), $content = null)
    {
        $server = array_replace(array(
            'SERVER_NAME' => 'localhost',
            'SERVER_PORT' => 80,
            'HTTP_HOST' => 'localhost',
            'HTTP_USER_AGENT' => 'Tico',
            'HTTP_ACCEPT' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'HTTP_ACCEPT_LANGUAGE' => 'en-us,en;q=0.5',
            'HTTP_ACCEPT_CHARSET' => 'ISO-8859-1,utf-8;q=0.7,*;q=0.7',
            'REMOTE_ADDR' => '127.0.0.1',
            'SCRIPT_NAME' => '',
            'SCRIPT_FILENAME' => '',
            'SERVER_PROTOCOL' => 'HTTP/1.1',
            'REQUEST_TIME' => time(),
            'REQUEST_TIME_FLOAT' => microtime(true),
        ), $server);

        $server['PATH_INFO'] = '';
        $server['REQUEST_METHOD'] = strtoupper($method);

        $components = parse_url(strlen($uri) !== strcspn($uri, '?#') ? $uri : $uri.'#');

        if (isset($components['host'])) {
            $server['SERVER_NAME'] = $components['host'];
            $server['HTTP_HOST'] = $components['host'];
        }

        if (isset($components['scheme'])) {
            if ('https' === $components['scheme']) {
                $server['HTTPS'] = 'on';
                $server['SERVER_PORT'] = 443;
            } else {
                unset($server['HTTPS']);
                $server['SERVER_PORT'] = 80;
            }
        }

        if (isset($components['port'])) {
            $server['SERVER_PORT'] = $components['port'];
            $server['HTTP_HOST'] .= ':'.$components['port'];
        }

        if (isset($components['user'])) {
            $server['PHP_AUTH_USER'] = $components['user'];
        }

        if (isset($components['pass'])) {
            $server['PHP_AUTH_PW'] = $components['pass'];
        }

        if (!isset($components['path'])) {
            $components['path'] = '/';
        }

        switch (strtoupper($method)) {
            case 'POST':
            case 'PUT':
            case 'DELETE':
                if (!isset($server['CONTENT_TYPE'])) {
                    $server['CONTENT_TYPE'] = 'application/x-www-form-urlencoded';
                }
                // no break
            case 'PATCH':
                $request = $parameters;
                $query = array();
                break;
            default:
                $request = array();
                $query = $parameters;
                break;
        }

        $queryString = '';
        if (isset($components['query'])) {
            parse_str(html_entity_decode($components['query']), $qs);

            if ($query) {
                $query = array_replace($qs, $query);
                $queryString = http_build_query($query, '', '&');
            } else {
                $query = $qs;
                $queryString = $components['query'];
            }
        } elseif ($query) {
            $queryString = http_build_query($query, '', '&');
        }

        $server['REQUEST_URI'] = $components['path'].('' !== $queryString ? '?'.$queryString : '');
        $server['QUERY_STRING'] = $queryString;

        return self::createRequestFromFactory($query, $request, array(), $cookies, $files, $server, $content);
    }

    public static function setFactory($callable)
    {
        self::$requestFactory = $callable;
    }

    public function duplicate(/*array*/ $query = null, /*array*/ $request = null, /*array*/ $attributes = null, /*array*/ $cookies = null, /*array*/ $files = null, /*array*/ $server = null)
    {
        $dup = clone $this;
        if (null !== $query) {
            $dup->query = new ParameterBag($query);
            $dup->queryci = new ParameterBag(self::queryCI($query));
        }
        if (null !== $request) {
            $dup->request = new ParameterBag($request);
        }
        if (null !== $attributes) {
            $dup->attributes = new ParameterBag($attributes);
        }
        if (null !== $cookies) {
            $dup->cookies = new ParameterBag($cookies);
        }
        if (null !== $files) {
            $dup->files = new HttpFileBag($files);
        }
        if (null !== $server) {
            $dup->server = new ParameterBag($server);
            $dup->headers = new HttpHeaderBag($dup->server->getHeaders());
        }
        $dup->languages = null;
        $dup->charsets = null;
        $dup->encodings = null;
        $dup->acceptableContentTypes = null;
        $dup->pathInfo = null;
        $dup->requestUri = null;
        $dup->baseUrl = null;
        $dup->basePath = null;
        $dup->method = null;
        $dup->format = null;

        if (!$dup->get('_format') && $this->get('_format')) {
            $dup->attributes->set('_format', $this->get('_format'));
        }

        if (!$dup->getRequestFormat(null)) {
            $dup->setRequestFormat($this->getRequestFormat(null));
        }

        return $dup;
    }

    public function __clone()
    {
        $this->query = clone $this->query;
        $this->queryci = clone $this->queryci;
        $this->request = clone $this->request;
        $this->attributes = clone $this->attributes;
        $this->cookies = clone $this->cookies;
        $this->files = clone $this->files;
        $this->server = clone $this->server;
        $this->headers = clone $this->headers;
    }

    public function __toString()
    {
        $content = $this->getContent();

        $cookieHeader = '';
        $cookies = array();

        foreach ($this->cookies as $k => $v) {
            if (is_array($v))
            {
                $params = array();
                $params[$k] = $v;
                $cookies[] = http_build_query($params, '', '; ', PHP_QUERY_RFC3986);
            }
            else
            {
                $cookies[] = "{$k}={$v}";
            }
        }

        if (!empty($cookies)) {
            $cookieHeader = 'Cookie: '.implode('; ', $cookies)."\r\n";
        }

        return
            sprintf('%s %s %s', $this->getMethod(), $this->getRequestUri(), $this->server->get('SERVER_PROTOCOL'))."\r\n".
            $this->headers.
            $cookieHeader."\r\n".
            $content;
    }

    public function overrideGlobals()
    {
        $this->server->set('QUERY_STRING', self::normalizeQueryString(http_build_query($this->query->all(), '', '&')));

        $_GET = $this->query->all();
        $_POST = $this->request->all();
        $_SERVER = $this->server->all();
        $_COOKIE = $this->cookies->all();

        foreach ($this->headers->all() as $key => $value) {
            $key = strtoupper(str_replace('-', '_', $key));
            if (in_array($key, array('CONTENT_TYPE', 'CONTENT_LENGTH'), true)) {
                $_SERVER[$key] = implode(', ', $value);
            } else {
                $_SERVER['HTTP_'.$key] = implode(', ', $value);
            }
        }

        $request = array('g' => $_GET, 'p' => $_POST, 'c' => $_COOKIE);

        $iniRequestOrder = ini_get('request_order');
        $requestOrder = $iniRequestOrder ? $iniRequestOrder : ini_get('variables_order');
        $reqOrdMatch = preg_replace('#[^cgp]#', '', strtolower($requestOrder));
        $requestOrder = $reqOrdMatch ? $reqOrdMatch : 'gp';

        $_REQUEST = array();
        foreach (str_split($requestOrder) as $order) {
            $_REQUEST = array_merge($_REQUEST, $request[$order]);
        }
    }

    public static function setTrustedProxies(/*array*/ $proxies, /*int*/ $trustedHeaderSet)
    {
        if (false !== $i = array_search('REMOTE_ADDR', $proxies, true)) {
            if (isset($_SERVER['REMOTE_ADDR'])) {
                $proxies[$i] = $_SERVER['REMOTE_ADDR'];
            } else {
                unset($proxies[$i]);
                $proxies = array_values($proxies);
            }
        }

        if (false !== ($i = array_search('PRIVATE_SUBNETS', $proxies, true)) || false !== ($i = array_search('private_ranges', $proxies, true))) {
            unset($proxies[$i]);
            $proxies = array_merge($proxies, HttpIpUtils::PRIVATE_SUBNETS);
        }

        self::$trustedProxies = $proxies;
        self::$trustedHeaderSet = $trustedHeaderSet;
    }

    public static function getTrustedProxies()
    {
        return self::$trustedProxies;
    }

    public static function getTrustedHeaderSet()
    {
        return self::$trustedHeaderSet;
    }

    public static function setTrustedHosts(/*array*/ $hostPatterns)
    {
        self::$trustedHostPatterns = array_map(function ($hostPattern) {
            return sprintf('#%s#i', $hostPattern);
        }, $hostPatterns);
        // we need to reset trusted hosts on trusted host patterns change
        self::$trustedHosts = array();
    }

    public static function getTrustedHosts()
    {
        return self::$trustedHostPatterns;
    }

    public static function normalizeQueryString($qs)
    {
        $qs = isset($qs) ? $qs : '';
        if ('' === $qs) {
            return '';
        }

        $qs = HttpHeaderUtils::parseQuery($qs);
        ksort($qs);

        return http_build_query($qs, '', '&', PHP_QUERY_RFC3986);
    }

    public static function enableHttpMethodParameterOverride()
    {
        self::$httpMethodParameterOverride = true;
    }

    public static function getHttpMethodParameterOverride()
    {
        return self::$httpMethodParameterOverride;
    }

    public function get($key, $default = null)
    {
        if ($this !== ($result = $this->attributes->get($key, $this))) {
            return $result;
        }

        if ($this !== ($result = $this->query->get($key, $this))) {
            return $result;
        }

        if ($this !== ($result = $this->request->get($key, $this))) {
            return $result;
        }

        return $default;
    }

    public function getSession()
    {
        return $this->session;
    }

    public function hasPreviousSession()
    {
        // the check for $this->session avoids malicious users trying to fake a session cookie with proper name
        return $this->hasSession() && $this->cookies->has($this->session->getName());
    }

    public function hasSession()
    {
        return null !== $this->session;
    }

    public function setSession(/*SessionInterface*/ $session)
    {
        $this->session = $session;
    }

    public function getClientIps()
    {
        $ip = $this->server->get('REMOTE_ADDR');

        if (!$this->isFromTrustedProxy()) {
            return array($ip);
        }

        $trustedValues = $this->getTrustedValues(self::HEADER_X_FORWARDED_FOR, $ip);
        return $trustedValues ? $trustedValues : array($ip);
    }

    public function getClientIp()
    {
        $ipAddresses = $this->getClientIps();

        return $ipAddresses[0];
    }

    public function getScriptName()
    {
        return $this->server->get('SCRIPT_NAME', $this->server->get('ORIG_SCRIPT_NAME', ''));
    }

    public function getPathInfo()
    {
        if (null === $this->pathInfo) {
            $this->pathInfo = $this->preparePathInfo();
        }

        return $this->pathInfo;
    }

    public function getBasePath()
    {
        if (null === $this->basePath) {
            $this->basePath = $this->prepareBasePath();
        }

        return $this->basePath;
    }

    public function getBaseUrl()
    {
        $trustedPrefix = '';

        // the proxy prefix must be prepended to any prefix being needed at the webserver level
        if ($this->isFromTrustedProxy() && $trustedPrefixValues = $this->getTrustedValues(self::HEADER_X_FORWARDED_PREFIX)) {
            $trustedPrefix = rtrim($trustedPrefixValues[0], '/');
        }

        return $trustedPrefix.$this->getBaseUrlReal();
    }

    private function getBaseUrlReal()
    {
        if (null === $this->baseUrl) {
            $this->baseUrl = $this->prepareBaseUrl();
        }

        return $this->baseUrl;
    }

    public function getScheme()
    {
        return $this->isSecure() ? 'https' : 'http';
    }

    public function getPort($onlyIfSet = false)
    {
        if ($this->isFromTrustedProxy() && $host = $this->getTrustedValues(self::HEADER_X_FORWARDED_PORT)) {
            $host = $host[0];
        } elseif ($this->isFromTrustedProxy() && !empty($host = $this->getTrustedValues(self::HEADER_X_FORWARDED_HOST))) {
            $host = $host[0];
        } elseif (empty($host = $this->headers->get('HOST'))) {
            return $this->server->get('SERVER_PORT');
        }

        if ('[' === $host[0]) {
            $pos = strpos($host, ':', strrpos($host, ']'));
        } else {
            $pos = strrpos($host, ':');
        }

        if (false !== $pos) {
            return (int) substr($host, $pos + 1);
        }

        return $onlyIfSet ? null : ('https' === $this->getScheme() ? 443 : 80);
    }

    public function getUser()
    {
        return $this->headers->get('PHP_AUTH_USER');
    }

    public function getPassword()
    {
        return $this->headers->get('PHP_AUTH_PW');
    }

    public function getUserInfo()
    {
        $userinfo = $this->getUser();

        $pass = $this->getPassword();
        if ('' != $pass) {
            $userinfo .= ":$pass";
        }

        return $userinfo;
    }

    public function getHttpHost()
    {
        $scheme = $this->getScheme();
        $port = $this->getPort();

        if (('http' == $scheme && 80 == $port) || ('https' == $scheme && 443 == $port)) {
            return $this->getHost();
        }

        return $this->getHost().':'.$port;
    }

    public function getRequestUri()
    {
        if (null === $this->requestUri) {
            $this->requestUri = $this->prepareRequestUri();
        }

        return $this->requestUri;
    }

    public function getSchemeAndHttpHost()
    {
        return $this->getScheme().'://'.$this->getHttpHost();
    }

    public function getUri($withQS = true)
    {
        if ($withQS) {
            if (null !== ($qs = $this->getQueryString())) {
                $qs = '?'.$qs;
            }
        } else {
             $qs = '';
        }

        return $this->getSchemeAndHttpHost().$this->getBaseUrl().$this->getPathInfo().$qs;
    }

    public function getUriForPath($path)
    {
        return $this->getSchemeAndHttpHost().$this->getBaseUrl().$path;
    }

    public function getRelativeUriForPath($path)
    {
        // be sure that we are dealing with an absolute path
        if (!isset($path[0]) || '/' !== $path[0]) {
            return $path;
        }

        if ($path === $basePath = $this->getPathInfo()) {
            return '';
        }

        $sourceDirs = explode('/', isset($basePath[0]) && '/' === $basePath[0] ? substr($basePath, 1) : $basePath);
        $targetDirs = explode('/', isset($path[0]) && '/' === $path[0] ? substr($path, 1) : $path);
        array_pop($sourceDirs);
        $targetFile = array_pop($targetDirs);

        foreach ($sourceDirs as $i => $dir) {
            if (isset($targetDirs[$i]) && $dir === $targetDirs[$i]) {
                unset($sourceDirs[$i], $targetDirs[$i]);
            } else {
                break;
            }
        }

        $targetDirs[] = $targetFile;
        $path = str_repeat('../', count($sourceDirs)).implode('/', $targetDirs);

        // A reference to the same base directory or an empty subdirectory must be prefixed with "./".
        // This also applies to a segment with a colon character (e.g., "file:colon") that cannot be used
        // as the first segment of a relative-path reference, as it would be mistaken for a scheme name
        // (see http://tools.ietf.org/html/rfc3986#section-4.2).
        return !isset($path[0]) || '/' === $path[0]
            || false !== ($colonPos = strpos($path, ':')) && ($colonPos < ($slashPos = strpos($path, '/')) || false === $slashPos)
            ? "./$path" : $path;
    }

    public function getQueryString()
    {
        $qs = self::normalizeQueryString($this->server->get('QUERY_STRING'));

        return '' === $qs ? null : $qs;
    }

    public function isSecure()
    {
        if ($this->isFromTrustedProxy() && $proto = $this->getTrustedValues(self::HEADER_X_FORWARDED_PROTO)) {
            return in_array(strtolower($proto[0]), array('https', 'on', 'ssl', '1'), true);
        }

        $https = $this->server->get('HTTPS');

        return !empty($https) && 'off' !== strtolower($https);
    }

    public function getHost()
    {
        if ($this->isFromTrustedProxy() && $host = $this->getTrustedValues(self::HEADER_X_FORWARDED_HOST)) {
            $host = $host[0];
        } elseif (empty($host = $this->headers->get('HOST'))) {
            if (empty($host = $this->server->get('SERVER_NAME'))) {
                $host = $this->server->get('SERVER_ADDR', '');
            }
        }

        // trim and remove port number from host
        // host is lowercase as per RFC 952/2181
        $host = strtolower(preg_replace('/:\d+$/', '', trim($host)));

        // as the host can come from the user (HTTP_HOST and depending on the configuration, SERVER_NAME too can come from the user)
        // check that it does not contain forbidden characters (see RFC 952 and RFC 2181)
        // use preg_replace() instead of preg_match() to prevent DoS attacks with long host names
        if ($host && '' !== preg_replace('/(?:^\[)?[a-zA-Z0-9-:\]_]+\.?/', '', $host)) {
            if (!$this->isHostValid) {
                return '';
            }
            $this->isHostValid = false;

            throw new /*SuspiciousOperation*/\Exception(sprintf('Invalid Host "%s".', $host));
        }

        if (count(self::$trustedHostPatterns) > 0) {
            // to avoid host header injection attacks, you should provide a list of trusted host patterns

            if (in_array($host, self::$trustedHosts)) {
                return $host;
            }

            foreach (self::$trustedHostPatterns as $pattern) {
                if (preg_match($pattern, $host)) {
                    self::$trustedHosts[] = $host;

                    return $host;
                }
            }

            if (!$this->isHostValid) {
                return '';
            }
            $this->isHostValid = false;

            throw new /*SuspiciousOperation*/\Exception(sprintf('Untrusted Host "%s".', $host));
        }

        return $host;
    }

    public function setMethod($method)
    {
        $this->method = null;
        $this->server->set('REQUEST_METHOD', $method);
    }

    public function getMethod($default = 'GET')
    {
        if (null !== $this->method) {
            return $this->method;
        }

        $this->method = strtoupper($this->server->get('REQUEST_METHOD', $default));

        if ('POST' !== $this->method) {
            return $this->method;
        }

        $method = $this->headers->get('X-HTTP-METHOD-OVERRIDE');

        if (!$method && self::$httpMethodParameterOverride) {
            $method = $this->request->get('_method', $this->query->get('_method', 'POST'));
        }

        if (!is_string($method)) {
            return $this->method;
        }

        $method = strtoupper($method);

        if (in_array($method, array('GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'PATCH', 'PURGE', 'TRACE'), true)) {
            return $this->method = $method;
        }

        if (!preg_match('/^[A-Z]++$/D', $method)) {
            throw new /*SuspiciousOperation*/\Exception('Invalid HTTP method override.');
        }

        return $this->method = $method;
    }

    public function getRealMethod()
    {
        return strtoupper($this->server->get('REQUEST_METHOD', 'GET'));
    }

    public function getMimeType($format)
    {
        if (null === self::$formats) {
            self::initializeFormats();
        }

        return isset(self::$formats[$format]) ? self::$formats[$format][0] : null;
    }

    public static function getMimeTypes($format)
    {
        if (null === self::$formats) {
            self::initializeFormats();
        }

        return isset(self::$formats[$format]) ? self::$formats[$format] : array();
    }

    public function getFormat($mimeType)
    {
        $canonicalMimeType = null;
        if ($mimeType && false !== ($pos = strpos($mimeType, ';'))) {
            $canonicalMimeType = trim(substr($mimeType, 0, $pos));
        }

        if (null === self::$formats) {
            self::initializeFormats();
        }

        foreach (self::$formats as $format => $mimeTypes) {
            if (in_array($mimeType, (array) $mimeTypes, true)) {
                return $format;
            }
            if (null !== $canonicalMimeType && in_array($canonicalMimeType, (array) $mimeTypes, true)) {
                return $format;
            }
        }

        return null;
    }

    public function setFormat($format, $mimeTypes)
    {
        if (null === self::$formats) {
            self::initializeFormats();
        }

        self::$formats[$format] = is_array($mimeTypes) ? $mimeTypes : array($mimeTypes);
    }

    public function getRequestFormat($default = 'html')
    {
        if (null === $this->format) {
            $this->format = $this->attributes->get('_format');
        }

        return null === $this->format ? $default : $this->format;
    }

    public function setRequestFormat($format)
    {
        $this->format = $format;
    }

    public function getContentTypeFormat()
    {
        return $this->getFormat($this->headers->get('CONTENT_TYPE', ''));
    }

    public function setDefaultLocale($locale)
    {
        $this->defaultLocale = $locale;

        if (null === $this->locale) {
            $this->setPhpDefaultLocale($locale);
        }
    }

    public function getDefaultLocale()
    {
        return $this->defaultLocale;
    }

    public function setLocale($locale)
    {
        $this->setPhpDefaultLocale($this->locale = $locale);
    }

    public function getLocale()
    {
        return null === $this->locale ? $this->defaultLocale : $this->locale;
    }

    public function isMethod($method)
    {
        return $this->getMethod() === strtoupper($method);
    }

    public function isMethodSafe()
    {
        return in_array($this->getMethod(), array('GET', 'HEAD', 'OPTIONS', 'TRACE'));
    }

    public function isMethodIdempotent()
    {
        return in_array($this->getMethod(), array('HEAD', 'GET', 'PUT', 'DELETE', 'TRACE', 'OPTIONS', 'PURGE'));
    }

    public function isMethodCacheable()
    {
        return in_array($this->getMethod(), array('GET', 'HEAD'));
    }

    public function getProtocolVersion()
    {
        if ($this->isFromTrustedProxy()) {
            preg_match('~^(HTTP/)?([1-9]\.[0-9]) ~', $this->headers->get('Via'), $matches);

            if ($matches) {
                return 'HTTP/'.$matches[2];
            }
        }

        return $this->server->get('SERVER_PROTOCOL');
    }

    public function getContent($asResource = false)
    {
        $currentContentIsResource = is_resource($this->content);

        if (true === $asResource) {
            if ($currentContentIsResource) {
                rewind($this->content);

                return $this->content;
            }

            // Content passed in parameter (test)
            if (is_string($this->content)) {
                $resource = fopen('php://temp', 'r+');
                fwrite($resource, $this->content);
                rewind($resource);

                return $resource;
            }

            $this->content = false;

            return fopen('php://input', 'rb');
        }

        if ($currentContentIsResource) {
            rewind($this->content);

            return stream_get_contents($this->content);
        }

        if (null === $this->content || false === $this->content) {
            $this->content = file_get_contents('php://input');
        }

        return $this->content;
    }

    public function getPayload()
    {
        if ($this->request->count()) {
            return clone $this->request;
        }

        if ('' === $content = $this->getContent()) {
            return new ParameterBag(array());
        }

        $content = json_decode($content, true, 512);

        if (!is_array($content)) {
            throw new \JsonException(sprintf('JSON content was expected to decode to an array, "%s" returned.', get_debug_type($content)));
        }

        return new ParameterBag($content);
    }

    public function toArray()
    {
        if ('' === $content = $this->getContent()) {
            throw new \JsonException('Request body is empty.');
        }

        $content = json_decode($content, true, 512);

        if (!is_array($content)) {
            throw new \JsonException(\sprintf('JSON content was expected to decode to an array, "%s" returned.', get_debug_type($content)));
        }

        return $content;
    }

    public function getETags()
    {
        return preg_split('/\s*,\s*/', $this->headers->get('if_none_match'), null, PREG_SPLIT_NO_EMPTY);
    }

    public function isNoCache()
    {
        return $this->headers->hasCacheControlDirective('no-cache') || 'no-cache' == $this->headers->get('Pragma');
    }

    public function getPreferredFormat($default = 'html')
    {
        if (!isset($this->preferredFormat) && null !== $preferredFormat = $this->getRequestFormat(null)) {
            $this->preferredFormat = $preferredFormat;
        }

        if ($this->preferredFormat) {
            return $this->preferredFormat;
        }

        foreach ($this->getAcceptableContentTypes() as $mimeType) {
            if ($this->preferredFormat = $this->getFormat($mimeType)) {
                return $this->preferredFormat;
            }
        }

        return $default;
    }

    public function getPreferredLanguage(/*array*/ $locales = null)
    {
        $preferredLanguages = $this->getLanguages();

        if (empty($locales)) {
            return isset($preferredLanguages[0]) ? $preferredLanguages[0] : null;
        }

        $locales = array_map(array($this, 'formatLocale'), $locales);
        if (empty($preferredLanguages)) {
            return $locales[0];
        }

        $combinations = array();
        foreach ($preferredLanguages as $pl) {
            $combinations = array_merge($combinations, $this->getLanguageCombinations($pl));
        }
        foreach ($combinations as $combination) {
            foreach ($locales as $locale) {
                if (0 === strpos($locale, $combination)) {
                    return $locale;
                }
            }
        }

        return $locales[0];
    }

    public function getLanguages()
    {
        if (null !== $this->languages) {
            return $this->languages;
        }

        $languages = HttpAcceptHeader::fromString($this->headers->get('Accept-Language'))->all();
        $this->languages = array();
        foreach ($languages as $acceptHeaderItem) {
            $lang = $acceptHeaderItem->getValue();
            $this->languages[] = self::formatLocale($lang);
        }
        $this->languages = array_unique($this->languages);

        return $this->languages;
    }

    private static function formatLocale($locale)
    {
        list($language, $script, $region) = self::getLanguageComponents($locale);

        return implode('_', array_filter(array($language, $script, $region)));
    }

    private static function getLanguageCombinations($locale)
    {
        list($language, $script, $region) = self::getLanguageComponents($locale);

        return array_unique(array(
            implode('_', array_filter(array($language, $script, $region))),
            implode('_', array_filter(array($language, $script))),
            implode('_', array_filter(array($language, $region))),
            $language,
        ));
    }

    private static function getLanguageComponents($locale)
    {
        $locale = str_replace('_', '-', strtolower($locale));
        $pattern = '/^([a-zA-Z]{2,3}|i-[a-zA-Z]{5,})(?:-([a-zA-Z]{4}))?(?:-([a-zA-Z]{2}))?(?:-(.+))?$/';
        if (!preg_match($pattern, $locale, $matches)) {
            return array($locale, null, null);
        }
        if (0 === strpos($matches[1], 'i-')) {
            // Language not listed in ISO 639 that are not variants
            // of any listed language, which can be registered with the
            // i-prefix, such as i-cherokee
            $matches[1] = substr($matches[1], 2);
        }

        return array(
            $matches[1],
            isset($matches[2]) ? ucfirst(strtolower($matches[2])) : null,
            isset($matches[3]) ? strtoupper($matches[3]) : null,
        );
    }

    public function getCharsets()
    {
        if (null !== $this->charsets) {
            return $this->charsets;
        }

        return $this->charsets = array_map('strval', array_keys(HttpAcceptHeader::fromString($this->headers->get('Accept-Charset'))->all()));
    }

    public function getEncodings()
    {
        if (null !== $this->encodings) {
            return $this->encodings;
        }

        return $this->encodings = array_map('strval', array_keys(HttpAcceptHeader::fromString($this->headers->get('Accept-Encoding'))->all()));
    }

    public function getAcceptableContentTypes()
    {
        if (null !== $this->acceptableContentTypes) {
            return $this->acceptableContentTypes;
        }

        return $this->acceptableContentTypes = array_map('strval', array_keys(HttpAcceptHeader::fromString($this->headers->get('Accept'))->all()));
    }

    public function isXmlHttpRequest()
    {
        return 'xmlhttprequest' == strtolower($this->headers->get('X-Requested-With', ''));
    }

    public function preferSafeContent(): bool
    {
        if (isset($this->isSafeContentPreferred)) {
            return $this->isSafeContentPreferred;
        }

        if (!$this->isSecure()) {
            // see https://tools.ietf.org/html/rfc8674#section-3
            return $this->isSafeContentPreferred = false;
        }

        return $this->isSafeContentPreferred = HttpAcceptHeader::fromString($this->headers->get('Prefer'))->has('safe');
    }

    protected function prepareRequestUri()
    {
        $requestUri = '';

        if ($this->isIisRewrite() && '' != $this->server->get('UNENCODED_URL')) {
            // IIS7 with URL Rewrite: make sure we get the unencoded URL (double slash problem)
            $requestUri = $this->server->get('UNENCODED_URL');
            $this->server->remove('UNENCODED_URL');
        } elseif ($this->server->has('REQUEST_URI')) {
            $requestUri = $this->server->get('REQUEST_URI');

            if ('' !== $requestUri && '/' === $requestUri[0]) {
                // To only use path and query remove the fragment.
                if (false !== $pos = strpos($requestUri, '#')) {
                    $requestUri = substr($requestUri, 0, $pos);
                }
            } else {
                // HTTP proxy reqs setup request URI with scheme and host [and port] + the URL path,
                // only use URL path.
                $uriComponents = parse_url($requestUri);

                if (isset($uriComponents['path'])) {
                    $requestUri = $uriComponents['path'];
                }

                if (isset($uriComponents['query'])) {
                    $requestUri .= '?'.$uriComponents['query'];
                }
            }
        } elseif ($this->server->has('ORIG_PATH_INFO')) {
            // IIS 5.0, PHP as CGI
            $requestUri = $this->server->get('ORIG_PATH_INFO');
            if ('' != $this->server->get('QUERY_STRING')) {
                $requestUri .= '?'.$this->server->get('QUERY_STRING');
            }
            $this->server->remove('ORIG_PATH_INFO');
        }

        // normalize the request URI to ease creating sub-requests from this request
        $this->server->set('REQUEST_URI', $requestUri);

        return $requestUri;
    }

    protected function prepareBaseUrl()
    {
        $filename = basename($this->server->get('SCRIPT_FILENAME', ''));

        if (basename($this->server->get('SCRIPT_NAME', '')) === $filename) {
            $baseUrl = $this->server->get('SCRIPT_NAME');
        } elseif (basename($this->server->get('PHP_SELF', '')) === $filename) {
            $baseUrl = $this->server->get('PHP_SELF');
        } elseif (basename($this->server->get('ORIG_SCRIPT_NAME', '')) === $filename) {
            $baseUrl = $this->server->get('ORIG_SCRIPT_NAME'); // 1and1 shared hosting compatibility
        } else {
            // Backtrack up the script_filename to find the portion matching
            // php_self
            $path = $this->server->get('PHP_SELF', '');
            $file = $this->server->get('SCRIPT_FILENAME', '');
            $segs = explode('/', trim($file, '/'));
            $segs = array_reverse($segs);
            $index = 0;
            $last = \count($segs);
            $baseUrl = '';
            do {
                $seg = $segs[$index];
                $baseUrl = '/'.$seg.$baseUrl;
                ++$index;
            } while ($last > $index && (false !== $pos = strpos($path, $baseUrl)) && 0 != $pos);
        }

        // Does the baseUrl have anything in common with the request_uri?
        $requestUri = $this->getRequestUri();
        if ('' !== $requestUri && '/' !== $requestUri[0]) {
            $requestUri = '/'.$requestUri;
        }

        if ($baseUrl && null !== $prefix = $this->getUrlencodedPrefix($requestUri, $baseUrl)) {
            // full $baseUrl matches
            return $prefix;
        }

        if ($baseUrl && null !== $prefix = $this->getUrlencodedPrefix($requestUri, rtrim(dirname($baseUrl), '/'.DIRECTORY_SEPARATOR).'/')) {
            // directory portion of $baseUrl matches
            return rtrim($prefix, '/'.DIRECTORY_SEPARATOR);
        }

        $truncatedRequestUri = $requestUri;
        if (false !== $pos = strpos($requestUri, '?')) {
            $truncatedRequestUri = substr($requestUri, 0, $pos);
        }

        $basename = basename(isset($baseUrl) ? $baseUrl : '');
        if (!$basename || !strpos(rawurldecode($truncatedRequestUri), $basename)) {
            // no match whatsoever; set it blank
            return '';
        }

        // If using mod_rewrite or ISAPI_Rewrite strip the script filename
        // out of baseUrl. $pos !== 0 makes sure it is not matching a value
        // from PATH_INFO or QUERY_STRING
        if (strlen($requestUri) >= strlen($baseUrl) && (false !== $pos = strpos($requestUri, $baseUrl)) && 0 !== $pos) {
            $baseUrl = substr($requestUri, 0, $pos + strlen($baseUrl));
        }

        return rtrim($baseUrl, '/'.DIRECTORY_SEPARATOR);
    }

    protected function prepareBasePath()
    {
        $baseUrl = $this->getBaseUrl();
        if (!$baseUrl) {
            return '';
        }

        $filename = basename($this->server->get('SCRIPT_FILENAME'));
        if (basename($baseUrl) === $filename) {
            $basePath = \dirname($baseUrl);
        } else {
            $basePath = $baseUrl;
        }

        if ('\\' === DIRECTORY_SEPARATOR) {
            $basePath = str_replace('\\', '/', $basePath);
        }

        return rtrim($basePath, '/');
    }

    protected function preparePathInfo()
    {
        if (null === ($requestUri = $this->getRequestUri())) {
            return '/';
        }

        // Remove the query string from REQUEST_URI
        if (false !== $pos = strpos($requestUri, '?')) {
            $requestUri = substr($requestUri, 0, $pos);
        }
        if ('' !== $requestUri && '/' !== $requestUri[0]) {
            $requestUri = '/'.$requestUri;
        }

        if (null === ($baseUrl = $this->getBaseUrlReal())) {
            return $requestUri;
        }

        $pathInfo = substr($requestUri, strlen($baseUrl));
        if ('' === $pathInfo) {
            // If substr() returns false then PATH_INFO is set to an empty string
            return '/';
        }

        return $pathInfo;
    }

    protected static function initializeFormats()
    {
        self::$formats = array(
            'html' => array('text/html', 'application/xhtml+xml'),
            'txt' => array('text/plain'),
            'js' => array('application/javascript', 'application/x-javascript', 'text/javascript'),
            'css' => array('text/css'),
            'json' => array('application/json', 'application/x-json'),
            'jsonld' => array('application/ld+json'),
            'xml' => array('text/xml', 'application/xml', 'application/x-xml'),
            'rdf' => array('application/rdf+xml'),
            'atom' => array('application/atom+xml'),
            'rss' => array('application/rss+xml'),
            'form' => array('application/x-www-form-urlencoded', 'multipart/form-data'),
        );
    }

    private function setPhpDefaultLocale(/*string*/ $locale)
    {
        // if either the class Locale doesn't exist, or an exception is thrown when
        // setting the default locale, the intl module is not installed, and
        // the call can be ignored:
        try {
            if (class_exists('Locale', false)) {
                \Locale::setDefault($locale);
            }
        } catch (\Exception $e) {
        }
    }

    private function getUrlencodedPrefix(/*string*/ $string, /*string*/ $prefix)
    {
        if ($this->isIisRewrite()) {
            // ISS with UrlRewriteModule might report SCRIPT_NAME/PHP_SELF with wrong case
            // see https://github.com/php/php-src/issues/11981
            if (0 !== stripos(rawurldecode($string), $prefix)) {
                return null;
            }
        } elseif (false === strpos(rawurldecode($string), $prefix)) {
            return null;
        }

        $len = strlen($prefix);

        if (preg_match(sprintf('#^(%%[[:xdigit:]]{2}|.){%d}#', $len), $string, $match)) {
            return $match[0];
        }

        return null;
    }

    private static function createRequestFromFactory(/*array*/ $query = array(), /*array*/ $request = array(), /*array*/ $attributes = array(), /*array*/ $cookies = array(), /*array*/ $files = array(), /*array*/ $server = array(), $content = null)
    {
        if (self::$requestFactory) {
            $request = call_user_func(self::$requestFactory, $query, $request, $attributes, $cookies, $files, $server, $content);

            if (!$request instanceof self) {
                throw new \LogicException('The HttpRequest factory must return an instance of HttpRequest.');
            }

            return $request;
        }

        return new self($query, $request, $attributes, $cookies, $files, $server, $content);
    }

    public function isFromTrustedProxy()
    {
        return self::$trustedProxies && HttpIpUtils::checkIp($this->server->get('REMOTE_ADDR'), self::$trustedProxies);
    }

    private function getTrustedValues($type, $ip = null)
    {
        $cacheKey = $type."\0".((self::$trustedHeaderSet & $type) ? $this->headers->get(self::TRUSTED_HEADERS[$type]) : '');
        $cacheKey .= "\0".$ip."\0".$this->headers->get(self::TRUSTED_HEADERS[self::HEADER_FORWARDED]);

        if (isset($this->trustedValuesCache[$cacheKey])) {
            return $this->trustedValuesCache[$cacheKey];
        }

        $clientValues = array();
        $forwardedValues = array();

        if ((self::$trustedHeaderSet & $type) && $this->headers->has(self::TRUSTED_HEADERS[$type])) {
            $arr = explode(',', $this->headers->get(self::TRUSTED_HEADERS[$type]));
            foreach ($arr as $v) {
                $clientValues[] = (self::HEADER_X_FORWARDED_PORT === $type ? '0.0.0.0:' : '').trim($v);
            }
        }

        if ((self::$trustedHeaderSet & self::HEADER_FORWARDED) && (isset(self::FORWARDED_PARAMS[$type])) && $this->headers->has(self::TRUSTED_HEADERS[self::HEADER_FORWARDED])) {
            $forwarded = $this->headers->get(self::TRUSTED_HEADERS[self::HEADER_FORWARDED]);
            $parts = HttpHeaderUtils::split($forwarded, ',;=');
            $param = self::FORWARDED_PARAMS[$type];
            foreach ($parts as $subParts) {
                $v = HttpHeaderUtils::combine($subParts)[$param];
                $v = isset($v) ? $v : null;
                if (null === $v) {
                    continue;
                }
                if (self::HEADER_X_FORWARDED_PORT === $type) {
                    if (']' === substr($v, -1, 1) || false === $v = strrchr($v, ':')) {
                        $v = $this->isSecure() ? ':443' : ':80';
                    }
                    $v = '0.0.0.0'.$v;
                }
                $forwardedValues[] = $v;
            }
        }

        if (null !== $ip) {
            $clientValues = $this->normalizeAndFilterClientIps($clientValues, $ip);
            $forwardedValues = $this->normalizeAndFilterClientIps($forwardedValues, $ip);
        }

        if ($forwardedValues === $clientValues || empty($clientValues)) {
            return $this->trustedValuesCache[$cacheKey] = $forwardedValues;
        }

        if (empty($forwardedValues)) {
            return $this->trustedValuesCache[$cacheKey] = $clientValues;
        }

        if (!$this->isForwardedValid) {
            return $this->trustedValuesCache[$cacheKey] = null !== $ip ? array('0.0.0.0', $ip) : array();
        }
        $this->isForwardedValid = false;

        throw new /*ConflictingHeaders*/\Exception(sprintf('The request has both a trusted "%s" header and a trusted "%s" header, conflicting with each other. You should either configure your proxy to remove one of them, or configure your project to distrust the offending one.', self::TRUSTED_HEADERS[self::HEADER_FORWARDED], self::TRUSTED_HEADERS[$type]));
    }

    private function normalizeAndFilterClientIps(/*array*/ $clientIps, $ip)
    {
        if (empty($clientIps)) {
            return array();
        }
        $clientIps[] = $ip; // Complete the IP chain with the IP the request actually came from
        $firstTrustedIp = null;

        foreach ($clientIps as $key => $clientIp) {
            if (strpos($clientIp, '.')) {
                // Strip :port from IPv4 addresses. This is allowed in Forwarded
                // and may occur in X-Forwarded-For.
                $i = strpos($clientIp, ':');
                if ($i) {
                    $clientIps[$key] = $clientIp = substr($clientIp, 0, $i);
                }
            } elseif (0 === strpos($clientIp, '[')) {
                // Strip brackets and :port from IPv6 addresses.
                $i = strpos($clientIp, ']', 1);
                $clientIps[$key] = $clientIp = substr($clientIp, 1, $i - 1);
            }

            if (!filter_var($clientIp, FILTER_VALIDATE_IP)) {
                unset($clientIps[$key]);

                continue;
            }

            if (HttpIpUtils::checkIp($clientIp, self::$trustedProxies)) {
                unset($clientIps[$key]);

                // Fallback to this when the client IP falls into the range of trusted proxies
                $firstTrustedIp = isset($firstTrustedIp) ? $firstTrustedIp : $clientIp;
            }
        }

        // Now the IP chain contains only untrusted proxies and the client IP
        return $clientIps ? array_reverse($clientIps) : array($firstTrustedIp);
    }

    private function isIisRewrite()
    {
        if (1 === $this->server->getInt('IIS_WasUrlRewritten')) {
            $this->isIisRewrite = true;
            $this->server->remove('IIS_WasUrlRewritten');
        }

        return $this->isIisRewrite;
    }
}

class HttpCookie
{
    protected $name;
    protected $value;
    protected $domain;
    protected $expire;
    protected $path;
    protected $secure;
    protected $httpOnly;
    private $partitioned;
    private $raw;
    private $sameSite;
    private $secureDefault = false;

    const SAMESITE_NONE = 'none';
    const SAMESITE_LAX = 'lax';
    const SAMESITE_STRICT = 'strict';

    const RESERVED_CHARS_LIST = "=,; \t\r\n\v\f";
    const RESERVED_CHARS_FROM = array('=', ',', ';', ' ', "\t", "\r", "\n", "\v", "\f");
    const RESERVED_CHARS_TO = array('%3D', '%2C', '%3B', '%20', '%09', '%0D', '%0A', '%0B', '%0C');

    public static function fromString($cookie, $decode = false)
    {
        $data = array(
            'expires' => 0,
            'path' => '/',
            'domain' => null,
            'secure' => false,
            'httponly' => false,
            'raw' => !$decode,
            'samesite' => null,
            'partitioned' => false,
        );
        $parts = HttpHeaderUtils::split($cookie, ';=');
        $part = array_shift($parts);

        $name = $decode ? urldecode($part[0]) : $part[0];
        $value = isset($part[1]) ? ($decode ? urldecode($part[1]) : $part[1]) : null;

        $data = array_merge($data, HttpHeaderUtils::combine($parts));
        $data['expires'] = self::expiresTimestamp($data['expires']);

        if (isset($data['max-age']) && ($data['max-age'] > 0 || $data['expires'] > time())) {
            $data['expires'] = time() + (int) $data['max-age'];
        }

        return new self($name, $value, $data['expires'], $data['path'], $data['domain'], $data['secure'], $data['httponly'], $data['raw'], $data['samesite'], $data['partitioned']);
    }

    public static function create($name, $value = null, $expire = 0, $path = '/', $domain = null, $secure = null, $httpOnly = true, $raw = false, $sameSite = 'lax', $partitioned = false): self
    {
        return new self($name, $value, $expire, $path, $domain, $secure, $httpOnly, $raw, $sameSite, $partitioned);
    }

    public function __construct(/*string*/ $name, /*string*/ $value = null, $expire = 0, /*?string*/ $path = '/', /*string*/ $domain = null, /*bool*/ $secure = false, /*bool*/ $httpOnly = true, /*bool*/ $raw = false, /*string*/ $sameSite = 'lax', /*bool*/ $partitioned = false)
    {
        // from PHP source code
        if ($raw && false !== strpbrk($name, self::RESERVED_CHARS_LIST)) {
            throw new \InvalidArgumentException(\sprintf('The cookie name "%s" contains invalid characters.', $name));
        }

        if (!$name) {
            throw new \InvalidArgumentException('The cookie name cannot be empty.');
        }

        $this->name = $name;
        $this->value = $value;
        $this->expire = self::expiresTimestamp($expire);
        $this->path = empty($path) ? '/' : $path;
        $this->domain = $domain;
        $this->sameSite = self::formatSameSite($sameSite);
        $this->secure = $secure;
        $this->httpOnly = $httpOnly;
        $this->raw = $raw;
        $this->partitioned = $partitioned;
    }

    public function withValue($value)
    {
        $cookie = clone $this;
        $cookie->value = $value;

        return $cookie;
    }

    public function withDomain($domain)
    {
        $cookie = clone $this;
        $cookie->domain = $domain;

        return $cookie;
    }

    public function withExpires($expire = 0)
    {
        $cookie = clone $this;
        $cookie->expire = self::expiresTimestamp($expire);

        return $cookie;
    }

    private static function expiresTimestamp($expire = 0)
    {
        // convert expiration time to a Unix timestamp
        if ($expire instanceof \DateTimeInterface) {
            $expire = $expire->format('U');
        } elseif (!is_numeric($expire)) {
            $expire = strtotime($expire);

            if (false === $expire) {
                throw new \InvalidArgumentException('The cookie expiration time is not valid.');
            }
        }

        return 0 < $expire ? (int) $expire : 0;
    }

    public function withPath($path)
    {
        $cookie = clone $this;
        $cookie->path = '' === $path ? '/' : $path;

        return $cookie;
    }

    public function withSecure($secure = true)
    {
        $cookie = clone $this;
        $cookie->secure = $secure;

        return $cookie;
    }

    public function withHttpOnly($httpOnly = true)
    {
        $cookie = clone $this;
        $cookie->httpOnly = $httpOnly;

        return $cookie;
    }

    public function withRaw($raw = true)
    {
        if ($raw && false !== strpbrk($this->name, self::RESERVED_CHARS_LIST)) {
            throw new \InvalidArgumentException(\sprintf('The cookie name "%s" contains invalid characters.', $this->name));
        }

        $cookie = clone $this;
        $cookie->raw = $raw;

        return $cookie;
    }

    public function withSameSite($sameSite)
    {
        $cookie = clone $this;
        $cookie->sameSite = self::formatSameSite($sameSite);

        return $cookie;
    }

    private static function formatSameSite($sameSite)
    {
        if ('' === $sameSite) {
            $sameSite = null;
        } elseif (null !== $sameSite) {
            $sameSite = strtolower($sameSite);
        }

        if (!in_array($sameSite, array(self::SAMESITE_LAX, self::SAMESITE_STRICT, self::SAMESITE_NONE, null), true)) {
            throw new \InvalidArgumentException('The "sameSite" parameter value is not valid.');
        }

        return $sameSite;
    }

    public function withPartitioned($partitioned = true)
    {
        $cookie = clone $this;
        $cookie->partitioned = $partitioned;

        return $cookie;
    }

    public function __toString()
    {
        if ($this->isRaw()) {
            $str = $this->getName();
        } else {
            $str = str_replace(self::RESERVED_CHARS_FROM, self::RESERVED_CHARS_TO, $this->getName());
        }

        $str .= '=';

        if ('' === (string) $this->getValue()) {
            $str .= 'deleted; expires='.gmdate('D, d M Y H:i:s T', time() - 31536001).'; Max-Age=0';
        } else {
            $str .= $this->isRaw() ? $this->getValue() : rawurlencode($this->getValue());

            if (0 !== $this->getExpiresTime()) {
                $str .= '; expires='.gmdate('D, d M Y H:i:s T', $this->getExpiresTime()).'; Max-Age='.$this->getMaxAge();
            }
        }

        if ($this->getPath()) {
            $str .= '; path='.$this->getPath();
        }

        if ($this->getDomain()) {
            $str .= '; domain='.$this->getDomain();
        }

        if ($this->isSecure()) {
            $str .= '; secure';
        }

        if ($this->isHttpOnly()) {
            $str .= '; httponly';
        }

        if (null !== $this->getSameSite()) {
            $str .= '; samesite='.$this->getSameSite();
        }

        if ($this->isPartitioned()) {
            $str .= '; partitioned';
        }

        return $str;
    }

    public function getName()
    {
        return $this->name;
    }

    public function getValue()
    {
        return $this->value;
    }

    public function getDomain()
    {
        return $this->domain;
    }

    public function getExpiresTime()
    {
        return $this->expire;
    }

    public function getMaxAge()
    {
        $maxAge = $this->expire - time();

        return max(0, $maxAge);
    }

    public function getPath()
    {
        return $this->path;
    }

    public function isSecure()
    {
        return isset($this->secure) ? $this->secure : $this->secureDefault;
    }

    public function isHttpOnly()
    {
        return $this->httpOnly;
    }

    public function isCleared()
    {
        return 0 !== $this->expire && $this->expire < time();
    }

    public function isRaw()
    {
        return $this->raw;
    }

    public function isPartitioned()
    {
        return $this->partitioned;
    }

    public function getSameSite()
    {
        return $this->sameSite;
    }

    public function setSecureDefault($default)
    {
        $this->secureDefault = $default;
    }
}

class HttpHeaderBag implements \IteratorAggregate, \Countable
{
    const UPPER = '_ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const LOWER = '-abcdefghijklmnopqrstuvwxyz';

    protected $headers = array();
    protected $cacheControl = array();

    public function __construct(/*array*/ $headers = array())
    {
        foreach ($headers as $key => $values) {
            $this->set($key, $values);
        }
    }

    public function __toString()
    {
        if (empty($headers = $this->all())) {
            return '';
        }

        ksort($headers);
        $max = max(array_map('strlen', array_keys($headers))) + 1;
        $content = '';
        foreach ($headers as $name => $values) {
            $name = ucwords($name, '-');
            foreach ($values as $value) {
                $content .= sprintf("%-{$max}s %s\r\n", $name.':', $value);
            }
        }

        return $content;
    }

    public function all($key = null)
    {
        if (null !== $key) {
            $key = strtr($key, self::UPPER, self::LOWER);
            return isset($this->headers[$key]) ? $this->headers[$key] : array();
        }

        return $this->headers;
    }

    public function keys()
    {
        return array_keys($this->all());
    }

    public function replace(/*array*/ $headers = array())
    {
        $this->headers = array();
        $this->add($headers);
    }

    public function add(/*array*/ $headers)
    {
        foreach ($headers as $key => $values) {
            $this->set($key, $values);
        }
    }

    public function get($key, $default = null, $first = true)
    {
        $headers = $this->all($key);

        if (empty($headers)) {
            return $first ? $default : array($default);
        }

        if (null === $headers[0]) {
            return $first ? null : array();
        }

        return $first ? $headers[0] : $headers;
    }

    public function set($key, $values, $replace = true)
    {
        $key = strtr($key, self::UPPER, self::LOWER);

        if (is_array($values)) {
            $values = array_values($values);

            if (true === $replace || !isset($this->headers[$key])) {
                $this->headers[$key] = $values;
            } else {
                $this->headers[$key] = array_merge($this->headers[$key], $values);
            }
        } else {
            if (true === $replace || !isset($this->headers[$key])) {
                $this->headers[$key] = array($values);
            } else {
                $this->headers[$key][] = $values;
            }
        }

        if ('cache-control' === $key) {
            $this->cacheControl = $this->parseCacheControl(implode(', ', $this->headers[$key]));
        }
    }

    public function has($key)
    {
        $key = strtr($key, self::UPPER, self::LOWER);
        return array_key_exists($key, $this->all());
    }

    public function contains($key, $value)
    {
        return in_array($value, $this->get($key, null, false), true);
    }

    public function remove($key)
    {
        $key = strtr($key, self::UPPER, self::LOWER);

        unset($this->headers[$key]);

        if ('cache-control' === $key) {
            $this->cacheControl = array();
        }
    }

    public function getDate($key, /*\DateTime*/ $default = null)
    {
        if (null === $value = $this->get($key)) {
            return null !== $default ? \DateTimeImmutable::createFromInterface($default) : null;
        }

        if (false === $date = \DateTimeImmutable::createFromFormat(DATE_RFC2822, $value)) {
            throw new \RuntimeException(\sprintf('The "%s" HTTP header is not parseable (%s).', $key, $value));
        }

        return $date;
    }

    public function addCacheControlDirective($key, $value = true)
    {
        $this->cacheControl[$key] = $value;

        $this->set('Cache-Control', $this->getCacheControlHeader());
    }

    public function hasCacheControlDirective($key)
    {
        return array_key_exists($key, $this->cacheControl);
    }

    public function getCacheControlDirective($key)
    {
        return array_key_exists($key, $this->cacheControl) ? $this->cacheControl[$key] : null;
    }

    public function removeCacheControlDirective($key)
    {
        unset($this->cacheControl[$key]);

        $this->set('Cache-Control', $this->getCacheControlHeader());
    }

    #[\ReturnTypeWillChange]
    public function getIterator()
    {
        return new \ArrayIterator($this->headers);
    }

    #[\ReturnTypeWillChange]
    public function count()
    {
        return count($this->headers);
    }

    protected function getCacheControlHeader()
    {
        ksort($this->cacheControl);

        return HttpHeaderUtils::toString($this->cacheControl, ',');
    }

    protected function parseCacheControl($header)
    {
        $parts = HttpHeaderUtils::split($header, ',=');

        return HttpHeaderUtils::combine($parts);
    }
}

class HttpResponseHeaderBag extends HttpHeaderBag
{
    const COOKIES_FLAT = 'flat';
    const COOKIES_ARRAY = 'array';

    const DISPOSITION_ATTACHMENT = 'attachment';
    const DISPOSITION_INLINE = 'inline';

    protected $computedCacheControl = array();
    protected $cookies = array();
    protected $headerNames = array();

    public function __construct(/*array*/ $headers = array())
    {
        parent::__construct($headers);

        if (!isset($this->headers['cache-control'])) {
            $this->set('Cache-Control', '');
        }

        /* RFC2616 - 14.18 says all Responses need to have a Date */
        if (!isset($this->headers['date'])) {
            $this->initDate();
        }
    }

    public function allPreserveCase()
    {
        $headers = array();
        foreach ($this->all() as $name => $value) {
            $headers[isset($this->headerNames[$name]) ? $this->headerNames[$name] : $name] = $value;
        }

        return $headers;
    }

    public function allPreserveCaseWithoutCookies()
    {
        $headers = $this->allPreserveCase();
        if (isset($this->headerNames['set-cookie'])) {
            unset($headers[$this->headerNames['set-cookie']]);
        }

        return $headers;
    }

    public function replace(/*array*/ $headers = array())
    {
        $this->headerNames = array();

        parent::replace($headers);

        if (!isset($this->headers['cache-control'])) {
            $this->set('Cache-Control', '');
        }

        if (!isset($this->headers['date'])) {
            $this->initDate();
        }
    }

    public function all($key = null)
    {
        $headers = parent::all();

        if (null !== $key) {
            $key = strtr($key, self::UPPER, self::LOWER);

            return 'set-cookie' !== $key ? (isset($headers[$key]) ? $headers[$key] : array()) : array_map('strval', $this->getCookies());
        }

        foreach ($this->getCookies() as $cookie) {
            $headers['set-cookie'][] = (string) $cookie;
        }

        return $headers;
    }

    public function set($key, $values, $replace = true)
    {
        $uniqueKey = strtr($key, self::UPPER, self::LOWER);

        if ('set-cookie' === $uniqueKey) {
            if ($replace) {
                $this->cookies = array();
            }
            foreach ((array) $values as $cookie) {
                $this->setCookie(HttpCookie::fromString($cookie));
            }
            $this->headerNames[$uniqueKey] = $key;

            return;
        }

        $this->headerNames[$uniqueKey] = $key;

        parent::set($key, $values, $replace);

        // ensure the cache-control header has sensible defaults
        if (in_array($uniqueKey, array('cache-control', 'etag', 'last-modified', 'expires'), true) && '' !== $computed = $this->computeCacheControlValue()) {
            $this->headers['cache-control'] = array($computed);
            $this->headerNames['cache-control'] = 'Cache-Control';
            $this->computedCacheControl = $this->parseCacheControl($computed);
        }
    }

    public function remove($key)
    {
        $uniqueKey = strtr($key, self::UPPER, self::LOWER);
        unset($this->headerNames[$uniqueKey]);

        if ('set-cookie' === $uniqueKey) {
            $this->cookies = array();

            return;
        }

        parent::remove($key);

        if ('cache-control' === $uniqueKey) {
            $this->computedCacheControl = array();
        }

        if ('date' === $uniqueKey) {
            $this->initDate();
        }
    }

    public function hasCacheControlDirective($key)
    {
        return array_key_exists($key, $this->computedCacheControl);
    }

    public function getCacheControlDirective($key)
    {
        return array_key_exists($key, $this->computedCacheControl) ? $this->computedCacheControl[$key] : null;
    }

    public function setCookie(/*HttpCookie*/ $cookie)
    {
        if (!isset($this->cookies[$cookie->getDomain()])) $this->cookies[$cookie->getDomain()] = array();
        if (!isset($this->cookies[$cookie->getDomain()][$cookie->getPath()])) $this->cookies[$cookie->getDomain()][$cookie->getPath()] = array();
        $this->cookies[$cookie->getDomain()][$cookie->getPath()][$cookie->getName()] = $cookie;
        $this->headerNames['set-cookie'] = 'Set-Cookie';
    }

    public function removeCookie($name, $path = '/', $domain = null)
    {
        $path = isset($path) ? $path : '/';

        unset($this->cookies[$domain][$path][$name]);

        if (empty($this->cookies[$domain][$path])) {
            unset($this->cookies[$domain][$path]);

            if (empty($this->cookies[$domain])) {
                unset($this->cookies[$domain]);
            }
        }

        if (empty($this->cookies)) {
            unset($this->headerNames['set-cookie']);
        }
    }

    public function getCookies($format = self::COOKIES_FLAT)
    {
        if (!in_array($format, array(self::COOKIES_FLAT, self::COOKIES_ARRAY))) {
            throw new \InvalidArgumentException(sprintf('Format "%s" invalid (%s).', $format, implode(', ', array(self::COOKIES_FLAT, self::COOKIES_ARRAY))));
        }

        if (self::COOKIES_ARRAY === $format) {
            return $this->cookies;
        }

        $flattenedCookies = array();
        foreach ($this->cookies as $path) {
            foreach ($path as $cookies) {
                foreach ($cookies as $cookie) {
                    $flattenedCookies[] = $cookie;
                }
            }
        }

        return $flattenedCookies;
    }

    public function clearCookie($name, $path = '/', $domain = null, $secure = false, $httpOnly = true, $sameSite = null /* , $partitioned = false */)
    {
        $partitioned = 6 < \func_num_args() ? func_get_arg(6) : false;

        $this->setCookie(new HttpCookie($name, null, 1, $path, $domain, $secure, $httpOnly, false, $sameSite, $partitioned));
    }

    public function makeDisposition($disposition, $filename, $filenameFallback = '')
    {
        return HttpHeaderUtils::makeDisposition($disposition, $filename, $filenameFallback);
    }

    protected function computeCacheControlValue()
    {
        if (!$this->cacheControl) {
            if ($this->has('Last-Modified') || $this->has('Expires')) {
                return 'private, must-revalidate'; // allows for heuristic expiration (RFC 7234 Section 4.2.2) in the case of "Last-Modified"
            }

            // conservative by default
            return 'no-cache, private';
        }

        $header = $this->getCacheControlHeader();
        if (isset($this->cacheControl['public']) || isset($this->cacheControl['private'])) {
            return $header;
        }

        // public if s-maxage is defined, private otherwise
        if (!isset($this->cacheControl['s-maxage'])) {
            return $header.', private';
        }

        return $header;
    }

    private function initDate()
    {
        $this->set('Date', gmdate('D, d M Y H:i:s').' GMT');
    }
}

class HttpResponse
{
    const HTTP_CONTINUE = 100;
    const HTTP_SWITCHING_PROTOCOLS = 101;
    const HTTP_PROCESSING = 102;            // RFC2518
    const HTTP_EARLY_HINTS = 103;           // RFC8297
    const HTTP_OK = 200;
    const HTTP_CREATED = 201;
    const HTTP_ACCEPTED = 202;
    const HTTP_NON_AUTHORITATIVE_INFORMATION = 203;
    const HTTP_NO_CONTENT = 204;
    const HTTP_RESET_CONTENT = 205;
    const HTTP_PARTIAL_CONTENT = 206;
    const HTTP_MULTI_STATUS = 207;          // RFC4918
    const HTTP_ALREADY_REPORTED = 208;      // RFC5842
    const HTTP_IM_USED = 226;               // RFC3229
    const HTTP_MULTIPLE_CHOICES = 300;
    const HTTP_MOVED_PERMANENTLY = 301;
    const HTTP_FOUND = 302;
    const HTTP_SEE_OTHER = 303;
    const HTTP_NOT_MODIFIED = 304;
    const HTTP_USE_PROXY = 305;
    const HTTP_RESERVED = 306;
    const HTTP_TEMPORARY_REDIRECT = 307;
    const HTTP_PERMANENTLY_REDIRECT = 308;  // RFC7238
    const HTTP_BAD_REQUEST = 400;
    const HTTP_UNAUTHORIZED = 401;
    const HTTP_PAYMENT_REQUIRED = 402;
    const HTTP_FORBIDDEN = 403;
    const HTTP_NOT_FOUND = 404;
    const HTTP_METHOD_NOT_ALLOWED = 405;
    const HTTP_NOT_ACCEPTABLE = 406;
    const HTTP_PROXY_AUTHENTICATION_REQUIRED = 407;
    const HTTP_REQUEST_TIMEOUT = 408;
    const HTTP_CONFLICT = 409;
    const HTTP_GONE = 410;
    const HTTP_LENGTH_REQUIRED = 411;
    const HTTP_PRECONDITION_FAILED = 412;
    const HTTP_REQUEST_ENTITY_TOO_LARGE = 413;
    const HTTP_REQUEST_URI_TOO_LONG = 414;
    const HTTP_UNSUPPORTED_MEDIA_TYPE = 415;
    const HTTP_REQUESTED_RANGE_NOT_SATISFIABLE = 416;
    const HTTP_EXPECTATION_FAILED = 417;
    const HTTP_I_AM_A_TEAPOT = 418;                                               // RFC2324
    const HTTP_MISDIRECTED_REQUEST = 421;                                         // RFC7540
    const HTTP_UNPROCESSABLE_ENTITY = 422;                                        // RFC4918
    const HTTP_LOCKED = 423;                                                      // RFC4918
    const HTTP_FAILED_DEPENDENCY = 424;                                           // RFC4918
    const HTTP_TOO_EARLY = 425;                                                   // RFC-ietf-httpbis-replay-04
    const HTTP_UPGRADE_REQUIRED = 426;                                            // RFC2817
    const HTTP_PRECONDITION_REQUIRED = 428;                                       // RFC6585
    const HTTP_TOO_MANY_REQUESTS = 429;                                           // RFC6585
    const HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE = 431;                             // RFC6585
    const HTTP_UNAVAILABLE_FOR_LEGAL_REASONS = 451;                               // RFC7725
    const HTTP_INTERNAL_SERVER_ERROR = 500;
    const HTTP_NOT_IMPLEMENTED = 501;
    const HTTP_BAD_GATEWAY = 502;
    const HTTP_SERVICE_UNAVAILABLE = 503;
    const HTTP_GATEWAY_TIMEOUT = 504;
    const HTTP_VERSION_NOT_SUPPORTED = 505;
    const HTTP_VARIANT_ALSO_NEGOTIATES_EXPERIMENTAL = 506;                        // RFC2295
    const HTTP_INSUFFICIENT_STORAGE = 507;                                        // RFC4918
    const HTTP_LOOP_DETECTED = 508;                                               // RFC5842
    const HTTP_NOT_EXTENDED = 510;                                                // RFC2774
    const HTTP_NETWORK_AUTHENTICATION_REQUIRED = 511;                             // RFC6585

    /**
     * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control
     */
    const HTTP_RESPONSE_CACHE_CONTROL_DIRECTIVES = array(
        'must_revalidate' => false,
        'no_cache' => false,
        'no_store' => false,
        'no_transform' => false,
        'public' => false,
        'private' => false,
        'proxy_revalidate' => false,
        'max_age' => true,
        's_maxage' => true,
        'stale_if_error' => true,         // RFC5861
        'stale_while_revalidate' => true, // RFC5861
        'immutable' => false,
        'last_modified' => true,
        'etag' => true,
    );

    protected static $trustXSendfileTypeHeader = false;

    public $headers;

    protected $content;
    protected $version;
    protected $statusCode;
    protected $statusText;
    protected $charset = null;
    protected $file = null;
    protected $maxlen = -1;
    protected $offset = 0;
    protected $chunkSize = 16 * 1024;
    protected $_deleteFileAfterSend = false;
    protected $targetUrl = null;
    protected $callback = null;
    protected $streamed = false;
    private $headersSent = false;
    private $canceled = false;
    private $sentHeaders;

    public static $statusTexts = array(
        100 => 'Continue',
        101 => 'Switching Protocols',
        102 => 'Processing',            // RFC2518
        103 => 'Early Hints',
        200 => 'OK',
        201 => 'Created',
        202 => 'Accepted',
        203 => 'Non-Authoritative Information',
        204 => 'No Content',
        205 => 'Reset Content',
        206 => 'Partial Content',
        207 => 'Multi-Status',          // RFC4918
        208 => 'Already Reported',      // RFC5842
        226 => 'IM Used',               // RFC3229
        300 => 'Multiple Choices',
        301 => 'Moved Permanently',
        302 => 'Found',
        303 => 'See Other',
        304 => 'Not Modified',
        305 => 'Use Proxy',
        307 => 'Temporary Redirect',
        308 => 'Permanent Redirect',    // RFC7238
        400 => 'Bad Request',
        401 => 'Unauthorized',
        402 => 'Payment Required',
        403 => 'Forbidden',
        404 => 'Not Found',
        405 => 'Method Not Allowed',
        406 => 'Not Acceptable',
        407 => 'Proxy Authentication Required',
        408 => 'Request Timeout',
        409 => 'Conflict',
        410 => 'Gone',
        411 => 'Length Required',
        412 => 'Precondition Failed',
        413 => 'Content Too Large',                                           // RFC-ietf-httpbis-semantics
        414 => 'URI Too Long',
        415 => 'Unsupported Media Type',
        416 => 'Range Not Satisfiable',
        417 => 'Expectation Failed',
        418 => 'I\'m a teapot',                                               // RFC2324
        421 => 'Misdirected Request',                                         // RFC7540
        422 => 'Unprocessable Content',                                       // RFC-ietf-httpbis-semantics
        423 => 'Locked',                                                      // RFC4918
        424 => 'Failed Dependency',                                           // RFC4918
        425 => 'Too Early',                                                   // RFC-ietf-httpbis-replay-04
        426 => 'Upgrade Required',                                            // RFC2817
        428 => 'Precondition Required',                                       // RFC6585
        429 => 'Too Many Requests',                                           // RFC6585
        431 => 'Request Header Fields Too Large',                             // RFC6585
        451 => 'Unavailable For Legal Reasons',                               // RFC7725
        500 => 'Internal Server Error',
        501 => 'Not Implemented',
        502 => 'Bad Gateway',
        503 => 'Service Unavailable',
        504 => 'Gateway Timeout',
        505 => 'HTTP Version Not Supported',
        506 => 'Variant Also Negotiates',                                     // RFC2295
        507 => 'Insufficient Storage',                                        // RFC4918
        508 => 'Loop Detected',                                               // RFC5842
        510 => 'Not Extended',                                                // RFC2774
        511 => 'Network Authentication Required',                             // RFC6585
                             // RFC6585
    );

    public function __construct($content = '', /*int*/ $status = 200, /*array*/ $headers = array())
    {
        $this->headers = new HttpResponseHeaderBag($headers);
        $this->setContent($content);
        $this->setStatusCode((int)$status);
        $this->setProtocolVersion('1.0');

        $this->streamed = false;
        $this->headersSent = false;
        $this->sentHeaders = array();
    }

    public function __toString()
    {
        return
            sprintf('HTTP/%s %s %s', $this->version, $this->statusCode, $this->statusText)."\r\n".
            $this->headers."\r\n".
            $this->getContent();
    }

    public function __clone()
    {
        $this->headers = clone $this->headers;
    }

    private function _prepare(/*HttpRequest*/ $request)
    {
        $headers = $this->headers;

        if ($this->isInformational() || $this->isEmpty()) {
            $this->setContent(null);
            $headers->remove('Content-Type');
            $headers->remove('Content-Length');
            // prevent PHP from sending the Content-Type header based on default_mimetype
            ini_set('default_mimetype', '');
        } else {
            // Content-type based on the Request
            if (!$headers->has('Content-Type')) {
                $format = $request->getRequestFormat(null);
                if (null !== $format && $mimeType = $request->getMimeType($format)) {
                    $headers->set('Content-Type', $mimeType);
                }
            }

            // Fix Content-Type
            $charset = !empty($this->charset) ? $this->charset : 'UTF-8';
            if (!$headers->has('Content-Type')) {
                $headers->set('Content-Type', 'text/html; charset='.$charset);
                // adapted from CakePHP, Http\Response class
            } elseif ((0 === stripos($headers->get('Content-Type'), 'text/') || in_array(strtolower($headers->get('Content-Type')), array('application/javascript', 'application/json', 'application/xml', 'application/rss+xml'))) && false === stripos($headers->get('Content-Type'), 'charset')) {
                // add the charset
                $headers->set('Content-Type', $headers->get('Content-Type').'; charset='.$charset);
            }

            // Fix Content-Length
            if ($headers->has('Transfer-Encoding')) {
                $headers->remove('Content-Length');
            }

            if ($request->isMethod('HEAD')) {
                // cf. RFC2616 14.13
                $length = $headers->get('Content-Length');
                $this->setContent(null);
                if ($length) {
                    $headers->set('Content-Length', $length);
                }
            }
        }

        // Fix protocol
        if ('HTTP/1.0' != $request->server->get('SERVER_PROTOCOL')) {
            $this->setProtocolVersion('1.1');
        }

        // Check if we need to send extra expire info headers
        if ('1.0' == $this->getProtocolVersion() && false !== strpos($this->headers->get('Cache-Control', ''), 'no-cache')) {
            $this->headers->set('pragma', 'no-cache');
            $this->headers->set('expires', -1);
        }

        $this->ensureIEOverSSLCompatibility($request);

        if ($request->isSecure()) {
            foreach ($headers->getCookies() as $cookie) {
                $cookie->setSecureDefault(true);
            }
        }
        return $this;
    }

    public function prepare(/*HttpRequest*/ $request)
    {
        if ($this->canceled) {
            return $this;
        }

        if ($this->file) {
            if ($this->isInformational() || $this->isEmpty()) {
                $this->_prepare($request);

                $this->maxlen = 0;

                return $this;
            }
            if (!$this->headers->has('Content-Type')) {
                $file_type = mime_content_type($this->file);
                if (empty($file_type)) $file_type = 'application/octet-stream';
                $this->headers->set('Content-Type', $file_type);
            }

            $this->_prepare($request);

            $this->offset = 0;
            $this->maxlen = -1;

            if (false === $fileSize = filesize($this->file)) {
                return $this;
            }
            $this->headers->remove('Transfer-Encoding');
            $this->headers->set('Content-Length', $fileSize);

            if (!$this->headers->has('Accept-Ranges')) {
                // Only accept ranges on safe HTTP methods
                $this->headers->set('Accept-Ranges', $request->isMethodSafe() ? 'bytes' : 'none');
            }

            if (self::$trustXSendfileTypeHeader && $request->headers->has('X-Sendfile-Type')) {
                // Use X-Sendfile, do not send any content.
                $type = $request->headers->get('X-Sendfile-Type');
                $path = realpath($this->file);
                // Fall back to scheme://path for stream wrapped locations.
                if (false === $path) {
                    $path = $this->file;
                }
                if ('x-accel-redirect' === strtolower($type)) {
                    // Do X-Accel-Mapping substitutions.
                    // @link https://github.com/rack/rack/blob/main/lib/rack/sendfile.rb
                    // @link https://mattbrictson.com/blog/accelerated-rails-downloads
                    if (!$request->headers->has('X-Accel-Mapping')) {
                        throw new \LogicException('The "X-Accel-Mapping" header must be set when "X-Sendfile-Type" is set to "X-Accel-Redirect".');
                    }
                    $parts = HttpHeaderUtils::split($request->headers->get('X-Accel-Mapping'), ',=');
                    foreach ($parts as $part) {
                        list($pathPrefix, $location) = $part;
                        if (0 === strpos($path, $pathPrefix)) {
                            $path = $location.substr($path, strlen($pathPrefix));
                            // Only set X-Accel-Redirect header if a valid URI can be produced
                            // as nginx does not serve arbitrary file paths.
                            $this->headers->set($type, rawurlencode($path));
                            $this->maxlen = 0;
                            break;
                        }
                    }
                } else {
                    $this->headers->set($type, $path);
                    $this->maxlen = 0;
                }
            } elseif ($request->headers->has('Range') && $request->isMethod('GET')) {
                // Process the range headers.
                if (!$request->headers->has('If-Range') || $this->hasValidIfRangeHeader($request->headers->get('If-Range'))) {
                    $range = $request->headers->get('Range');

                    if (0 === strpos($range, 'bytes=')) {
                        list($start, $end) = explode('-', substr($range, 6), 2) + [1 => 0];

                        $end = ('' === $end) ? $fileSize - 1 : (int) $end;

                        if ('' === $start) {
                            $start = $fileSize - $end;
                            $end = $fileSize - 1;
                        } else {
                            $start = (int) $start;
                        }

                        if ($start <= $end) {
                            $end = min($end, $fileSize - 1);
                            if ($start < 0 || $start > $end) {
                                $this->setStatusCode(416);
                                $this->headers->set('Content-Range', sprintf('bytes */%s', $fileSize));
                            } elseif ($end - $start < $fileSize - 1) {
                                $this->maxlen = $end < $fileSize ? $end - $start + 1 : -1;
                                $this->offset = $start;

                                $this->setStatusCode(206);
                                $this->headers->set('Content-Range', sprintf('bytes %s-%s/%s', $start, $end, $fileSize));
                                $this->headers->set('Content-Length', $end - $start + 1);
                            }
                        }
                    }
                }
            }

            if ($request->isMethod('HEAD')) {
                $this->maxlen = 0;
            }
        } else {
            $this->_prepare($request);
        }
        return $this;
    }

    public function cancel($bool = true)
    {
        $this->canceled = (bool)$bool;
        return $this;
    }

    public function sendHeaders($statusCode = null)
    {
        // headers have already been sent by the developer
        if ($this->headersSent || headers_sent()) {
            return $this;
        }

        if ($statusCode < 100 || $statusCode >= 200) {
            $this->headersSent = true;
        }

        $informationalResponse = $statusCode >= 100 && $statusCode < 200;
        if ($informationalResponse && !function_exists('headers_send')) {
            // skip informational responses if not supported by the SAPI
            return $this;
        }

        // headers
        foreach ($this->headers->allPreserveCaseWithoutCookies() as $name => $values) {
            // As recommended by RFC 8297, PHP automatically copies headers from previous 103 responses, we need to deal with that if headers changed
            $previousValues = isset($this->sentHeaders[$name]) ? $this->sentHeaders[$name] : null;
            if ($previousValues === $values) {
                // Header already sent in a previous response, it will be automatically copied in this response by PHP
                continue;
            }

            $replace = 0 === strcasecmp($name, 'Content-Type');

            if (null !== $previousValues && array_diff($previousValues, $values)) {
                header_remove($name);
                $previousValues = null;
            }

            $newValues = null === $previousValues ? $values : array_diff($values, $previousValues);

            foreach ($newValues as $value) {
                header($name.': '.$value, $replace, $this->statusCode);
            }

            if ($informationalResponse) {
                $this->sentHeaders[$name] = $values;
            }
        }

        // cookies
        foreach ($this->headers->getCookies() as $cookie) {
            header('Set-Cookie: '.$cookie, false, $this->statusCode);
        }

        if ($informationalResponse) {
            headers_send($statusCode);

            return $this;
        }

        if (!$statusCode) $statusCode = $this->statusCode;

        // status
        header(sprintf('HTTP/%s %s %s', $this->version, $statusCode, $this->statusText), true, $statusCode);

        return $this;
    }

    public function sendContent()
    {
        if ($this->callback) {
            if ($this->streamed) {
                return $this;
            }

            $this->streamed = true;

            call_user_func($this->callback);

        } elseif ($this->file) {
            try {
                if (!$this->isSuccessful()) {
                    return $this;
                }

                if (0 == $this->maxlen) {
                    return $this;
                }

                //$out = fopen('php://output', 'wb');
                //$file = fopen($this->file, 'rb');
                //stream_copy_to_stream($file, $out, $this->maxlen, $this->offset);
                $out = fopen('php://output', 'w');
                $file = fopen($this->file, 'r');

                ignore_user_abort(true);

                if (0 !== $this->offset) {
                    fseek($file, $this->offset);
                }

                $length = $this->maxlen;
                while ($length && !feof($file)) {
                    $read = $length > $this->chunkSize || 0 > $length ? $this->chunkSize : $length;

                    if (false === $data = fread($file, $read)) {
                        break;
                    }
                    while ('' !== $data) {
                        $read = fwrite($out, $data);
                        if (false === $read || connection_aborted()) {
                            break 2;
                        }
                        if (0 < $length) {
                            $length -= $read;
                        }
                        $data = substr($data, $read);
                    }
                }

                fclose($out);
                fclose($file);
            } finally {
                if ($this->_deleteFileAfterSend) {
                    unlink($this->file);
                }
            }

        } else {
            echo $this->content;
        }

        return $this;
    }

    public function send($flush = true)
    {
        if ($this->canceled) return $this;

        $this->sendHeaders();
        $this->sendContent();

        if (!$flush) {
            return $this;
        }

        if (function_exists('fastcgi_finish_request')) {
            fastcgi_finish_request();
        } elseif (function_exists('litespeed_finish_request')) {
            litespeed_finish_request();
        } elseif (!in_array(PHP_SAPI, array('cli', 'phpdbg', 'embed'), true)) {
            self::closeOutputBuffers(0, true);
            flush();
        }

        return $this;
    }

    public function setContent($content)
    {
        $this->content = (string) (isset($content) ? $content : '');

        return $this;
    }

    public function getContent()
    {
        return $this->content;
    }

    public function setChunks($chunks)
    {
        $this->callback = static function () use ($chunks) {
            foreach ($chunks as $chunk) {
                echo $chunk;
                @ob_flush();
                flush();
            }
        };

        return $this;
    }

    public function setCallback($callback)
    {
        $this->callback = !empty($callback) && is_callable($callback) ? $callback : null;

        return $this;
    }

    public function getCallback()
    {
        return $this->callback;
    }

    public function setTargetUrl($url, $statusCode = 302)
    {
        if (empty($url)) {
            throw new \InvalidArgumentException('Cannot redirect to an empty URL.');
        }

        $this->targetUrl = $url;

        $this->setStatusCode((int)$statusCode);

        if (301 == $this->getStatusCode() && $this->headers->has('cache-control')) {
            $this->headers->remove('cache-control');
        }

        $this->setContent(
            sprintf('<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8" />
        <meta http-equiv="refresh" content="0;url=\'%1$s\'" />

        <title>Redirecting to %1$s</title>
    </head>
    <body>
        Redirecting to <a href="%1$s">%1$s</a>.
    </body>
</html>', htmlspecialchars($url, ENT_QUOTES, 'UTF-8')));

        $this->headers->set('Location', $url);
        $this->headers->set('Content-Type', 'text/html; charset=utf-8');

        return $this;
    }

    public function getTargetUrl()
    {
        return $this->targetUrl;
    }

    public function setFile($file, $contentDisposition = null, $autoEtag = false, $autoLastModified = true)
    {
        if ($file && !is_readable($file)) {
            throw new /*File*/\Exception('File must be readable.');
        }

        if ($file) {
            $this->file = $file;

            if ($autoEtag) {
                $this->setAutoEtag();
            }

            if ($autoLastModified) {
                $this->setAutoLastModified();
            }

            if ($contentDisposition) {
                $this->setContentDisposition($contentDisposition);
            }
        } elseif ($this->file) {
            $this->file = null;

            $this->headers->remove('Etag');

            $this->headers->remove('Last-Modified');

            $this->headers->remove('Content-Disposition');
        }

        return $this;
    }

    public function getFile()
    {
        return $this->file;
    }


    public function setChunkSize($chunkSize)
    {
        if ($chunkSize < 1) {
            throw new \InvalidArgumentException('The chunk size of a BinaryFileResponse cannot be less than 1.');
        }

        $this->chunkSize = $chunkSize;

        return $this;
    }

    public function setAutoLastModified()
    {
        $this->setLastModified(\DateTime::createFromFormat('U', filemtime($this->file)));

        return $this;
    }

    public function setAutoEtag()
    {
        $this->setEtag(base64_encode(hash_file('sha256', $this->file, true)));

        return $this;
    }

    public function setContentDisposition($disposition, $filename = '', $filenameFallback = '')
    {
        if ('' === $filename) {
            $filename = basename($this->file);
        }

        if ('' === $filenameFallback && (!preg_match('/^[\x20-\x7e]*$/', $filename) || false !== strpos($filename, '%'))) {
            $enc = mb_detect_encoding($filename, null, true);
            $encoding = $enc ? $enc : '8bit';

            for ($i = 0, $filenameLength = mb_strlen($filename, $encoding); $i < $filenameLength; ++$i) {
                $char = mb_substr($filename, $i, 1, $encoding);

                if ('%' === $char || ord($char) < 32 || ord($char) > 126) {
                    $filenameFallback .= '_';
                } else {
                    $filenameFallback .= $char;
                }
            }
        }

        $dispositionHeader = $this->headers->makeDisposition($disposition, $filename, $filenameFallback);
        $this->headers->set('Content-Disposition', $dispositionHeader);

        return $this;
    }

    public static function enableXSendfileTypeHeader($enable = true)
    {
        self::$trustXSendfileTypeHeader = (bool)$enable;
    }

    public function deleteFileAfterSend($shouldDelete = true)
    {
        $this->_deleteFileAfterSend = (bool)$shouldDelete;
        return $this;
    }

    private function hasValidIfRangeHeader($header)
    {
        if ($this->getEtag() === $header) {
            return true;
        }

        if (null === $lastModified = $this->getLastModified()) {
            return false;
        }

        return $lastModified->format('D, d M Y H:i:s').' GMT' === $header;
    }

    public function setProtocolVersion(/*string*/ $version)
    {
        $this->version = $version;

        return $this;
    }

    public function getProtocolVersion()/*: string*/
    {
        return $this->version;
    }

    public function setStatusCode(/*int*/ $code, $text = null)
    {
        $this->statusCode = (int)$code;
        if ($this->isInvalid()) {
            throw new \InvalidArgumentException(sprintf('The HTTP status code "%s" is not valid.', $code));
        }

        if (null === $text) {
            $this->statusText = isset(self::$statusTexts[$code]) ? self::$statusTexts[$code] : 'unknown status';

            return $this;
        }

        if (false === $text) {
            $this->statusText = '';

            return $this;
        }

        $this->statusText = $text;

        return $this;
    }

    public function getStatusCode()/*: int*/
    {
        return $this->statusCode;
    }

    public function setCharset(/*string*/ $charset)
    {
        $this->charset = $charset;

        return $this;
    }

    public function getCharset()/*: ?string*/
    {
        return $this->charset;
    }

    public function isCacheable()/*: bool*/
    {
        if (!in_array($this->statusCode, array(200, 203, 300, 301, 302, 404, 410))) {
            return false;
        }

        if ($this->headers->hasCacheControlDirective('no-store') || $this->headers->getCacheControlDirective('private')) {
            return false;
        }

        return $this->isValidateable() || $this->isFresh();
    }

    public function isFresh()/*: bool*/
    {
        return $this->getTtl() > 0;
    }

    public function isValidateable()/*: bool*/
    {
        return $this->headers->has('Last-Modified') || $this->headers->has('ETag');
    }

    public function setPrivate()
    {
        $this->headers->removeCacheControlDirective('public');
        $this->headers->addCacheControlDirective('private');

        return $this;
    }

    public function setPublic()
    {
        $this->headers->addCacheControlDirective('public');
        $this->headers->removeCacheControlDirective('private');

        return $this;
    }

    public function setImmutable(/*bool*/ $immutable = true)
    {
        if ($immutable) {
            $this->headers->addCacheControlDirective('immutable');
        } else {
            $this->headers->removeCacheControlDirective('immutable');
        }

        return $this;
    }

    public function isImmutable()/*: bool*/
    {
        return $this->headers->hasCacheControlDirective('immutable');
    }

    public function mustRevalidate()/*: bool*/
    {
        return $this->headers->hasCacheControlDirective('must-revalidate') || $this->headers->hasCacheControlDirective('proxy-revalidate');
    }

    public function getDate()/*: ?\DateTimeInterface*/
    {
        return $this->headers->getDate('Date');
    }

    public function setDate(/*\DateTimeInterface*/ $date)
    {
        if ($date instanceof \DateTime) {
            $date = \DateTimeImmutable::createFromMutable($date);
        }

        $date = $date->setTimezone(new \DateTimeZone('UTC'));
        $this->headers->set('Date', $date->format('D, d M Y H:i:s').' GMT');

        return $this;
    }

    public function getAge()/*: int*/
    {
        if (null !== $age = $this->headers->get('Age')) {
            return (int) $age;
        }

        return max(time() - $this->getDate()->format('U'), 0);
    }

    public function expire()
    {
        if ($this->isFresh()) {
            $this->headers->set('Age', $this->getMaxAge());
            $this->headers->remove('Expires');
        }

        return $this;
    }

    public function getExpires()/*: ?\DateTimeInterface*/
    {
        try {
            return $this->headers->getDate('Expires');
        } catch (\RuntimeException $e) {
            // according to RFC 2616 invalid date formats (e.g. "0" and "-1") must be treated as in the past
            return \DateTime::createFromFormat('U', time() - 172800);
        }
    }

    public function setExpires(/*\DateTimeInterface*/ $date = null)
    {
        if (null === $date) {
            $this->headers->remove('Expires');

            return $this;
        }

        if ($date instanceof \DateTime) {
            $date = \DateTimeImmutable::createFromMutable($date);
        }

        $date = $date->setTimezone(new \DateTimeZone('UTC'));
        $this->headers->set('Expires', $date->format('D, d M Y H:i:s').' GMT');

        return $this;
    }

    public function getMaxAge()/*: ?int*/
    {
        if ($this->headers->hasCacheControlDirective('s-maxage')) {
            return (int) $this->headers->getCacheControlDirective('s-maxage');
        }

        if ($this->headers->hasCacheControlDirective('max-age')) {
            return (int) $this->headers->getCacheControlDirective('max-age');
        }

        if (null !== $expires = $this->getExpires()) {
            $maxAge = (int) $expires->format('U') - (int) $this->getDate()->format('U');

            return max($maxAge, 0);
        }

        return null;
    }

    public function setMaxAge(/*int*/ $value)
    {
        $this->headers->addCacheControlDirective('max-age', $value);

        return $this;
    }

    public function setStaleIfError(/*int*/ $value)
    {
        $this->headers->addCacheControlDirective('stale-if-error', (int)$value);

        return $this;
    }

    public function setStaleWhileRevalidate(/*int*/ $value)
    {
        $this->headers->addCacheControlDirective('stale-while-revalidate', (int)$value);

        return $this;
    }
    public function setSharedMaxAge(/*int*/ $value)
    {
        $this->setPublic();
        $this->headers->addCacheControlDirective('s-maxage', (int)$value);

        return $this;
    }

    public function getTtl()/*: ?int*/
    {
        $maxAge = $this->getMaxAge();

        return null !== $maxAge ? max($maxAge - $this->getAge(), 0) : null;
    }

    public function setTtl(/*int*/ $seconds)
    {
        $this->setSharedMaxAge($this->getAge() + (int)$seconds);

        return $this;
    }

    public function setClientTtl(/*int*/ $seconds)
    {
        $this->setMaxAge($this->getAge() + (int)$seconds);

        return $this;
    }

    public function getLastModified()/*: ?\DateTimeInterface*/
    {
        return $this->headers->getDate('Last-Modified');
    }

    public function setLastModified(/*\DateTimeInterface*/ $date = null)
    {
        if (null === $date) {
            $this->headers->remove('Last-Modified');

            return $this;
        }

        if ($date instanceof \DateTime) {
            $date = \DateTimeImmutable::createFromMutable($date);
        }

        $date = $date->setTimezone(new \DateTimeZone('UTC'));
        $this->headers->set('Last-Modified', $date->format('D, d M Y H:i:s').' GMT');

        return $this;
    }

    public function getEtag()/*: ?string*/
    {
        return $this->headers->get('ETag');
    }

    public function setEtag(/*string*/ $etag = null, /*bool*/ $weak = false)
    {
        if (null === $etag) {
            $this->headers->remove('Etag');
        } else {
            if (0 !== strpos($etag, '"')) {
                $etag = '"'.$etag.'"';
            }

            $this->headers->set('ETag', (true === $weak ? 'W/' : '').$etag);
        }

        return $this;
    }

    public function setCache(/*array*/ $options)
    {
        if ($diff = array_diff(array_keys($options), array(self::HTTP_RESPONSE_CACHE_CONTROL_DIRECTIVES))) {
            throw new \InvalidArgumentException(sprintf('HttpResponse does not support the following options: "%s".', implode('", "', array_values($diff))));
        }

        if (isset($options['etag'])) {
            $this->setEtag($options['etag']);
        }

        if (isset($options['last_modified'])) {
            $this->setLastModified($options['last_modified']);
        }

        if (isset($options['max_age'])) {
            $this->setMaxAge($options['max_age']);
        }

        if (isset($options['s_maxage'])) {
            $this->setSharedMaxAge($options['s_maxage']);
        }

        if (isset($options['stale_while_revalidate'])) {
            $this->setStaleWhileRevalidate($options['stale_while_revalidate']);
        }

        if (isset($options['stale_if_error'])) {
            $this->setStaleIfError($options['stale_if_error']);
        }

        foreach (self::HTTP_RESPONSE_CACHE_CONTROL_DIRECTIVES as $directive => $hasValue) {
            if (!$hasValue && isset($options[$directive])) {
                if ($options[$directive]) {
                    $this->headers->addCacheControlDirective(str_replace('_', '-', $directive));
                } else {
                    $this->headers->removeCacheControlDirective(str_replace('_', '-', $directive));
                }
            }
        }

        if (isset($options['public'])) {
            if ($options['public']) {
                $this->setPublic();
            } else {
                $this->setPrivate();
            }
        }

        if (isset($options['private'])) {
            if ($options['private']) {
                $this->setPrivate();
            } else {
                $this->setPublic();
            }
        }

        if (isset($options['immutable'])) {
            $this->setImmutable((bool) $options['immutable']);
        }

        return $this;
    }

    public function setNotModified()
    {
        $this->setStatusCode(304);
        $this->setContent(null);

        // remove headers that MUST NOT be included with 304 Not Modified responses
        $arr = array('Allow', 'Content-Encoding', 'Content-Language', 'Content-Length', 'Content-MD5', 'Content-Type', 'Last-Modified');
        foreach ($arr as $header) {
            $this->headers->remove($header);
        }

        return $this;
    }

    public function hasVary()/*: bool*/
    {
        return null !== $this->headers->get('Vary');
    }

    public function getVary()/*: array*/
    {
        if (empty($vary = $this->headers->all('Vary'))) {
            return array();
        }

        $ret = array();
        foreach ($vary as $item) {
            $ret = array_merge($ret, preg_split('/[\s,]+/', $item));
        }

        return $ret;
    }

    public function setVary($headers, /*bool*/ $replace = true)
    {
        $this->headers->set('Vary', $headers, $replace);

        return $this;
    }

    public function isNotModified(/*Request*/ $request)/*: bool*/
    {
        if (!$request->isMethodCacheable()) {
            return false;
        }

        $notModified = false;
        $lastModified = $this->headers->get('Last-Modified');
        $modifiedSince = $request->headers->get('If-Modified-Since');

        if (($ifNoneMatchEtags = $request->getETags()) && (null !== $etag = $this->getEtag())) {
            if (0 == strncmp($etag, 'W/', 2)) {
                $etag = substr($etag, 2);
            }

            // Use weak comparison as per https://tools.ietf.org/html/rfc7232#section-3.2.
            foreach ($ifNoneMatchEtags as $ifNoneMatchEtag) {
                if (0 == strncmp($ifNoneMatchEtag, 'W/', 2)) {
                    $ifNoneMatchEtag = substr($ifNoneMatchEtag, 2);
                }

                if ($ifNoneMatchEtag === $etag || '*' === $ifNoneMatchEtag) {
                    $notModified = true;
                    break;
                }
            }
        }
        // Only do If-Modified-Since date comparison when If-None-Match is not present as per https://tools.ietf.org/html/rfc7232#section-3.3.
        elseif ($modifiedSince && $lastModified) {
            $notModified = strtotime($modifiedSince) >= strtotime($lastModified);
        }

        if ($notModified) {
            $this->setNotModified();
        }

        return $notModified;
    }

    public function isInvalid()/*: bool*/
    {
        return $this->statusCode < 100 || $this->statusCode >= 600;
    }

    public function isInformational()/*: bool*/
    {
        return $this->statusCode >= 100 && $this->statusCode < 200;
    }

    public function isSuccessful()/*: bool*/
    {
        return $this->statusCode >= 200 && $this->statusCode < 300;
    }

    public function isRedirection()/*: bool*/
    {
        return $this->statusCode >= 300 && $this->statusCode < 400;
    }

    public function isClientError()/*: bool*/
    {
        return $this->statusCode >= 400 && $this->statusCode < 500;
    }

    public function isServerError()/*: bool*/
    {
        return $this->statusCode >= 500 && $this->statusCode < 600;
    }

    public function isOk()/*: bool*/
    {
        return 200 == $this->statusCode;
    }

    public function isForbidden()/*: bool*/
    {
        return 403 == $this->statusCode;
    }

    public function isNotFound()/*: bool*/
    {
        return 404 == $this->statusCode;
    }

    public function isRedirect(/*string*/ $location = null)/*: bool*/
    {
        return in_array($this->statusCode, array(201, 301, 302, 303, 307, 308)) && (null === $location ? true : $location == $this->headers->get('Location'));
    }

    public function isEmpty()/*: bool*/
    {
        return in_array($this->statusCode, array(204, 304));
    }

    public static function closeOutputBuffers(/*int*/ $targetLevel, /*bool*/ $flush)
    {
        $status = ob_get_status(true);
        $level = count($status);
        $flags = PHP_OUTPUT_HANDLER_REMOVABLE | ($flush ? PHP_OUTPUT_HANDLER_FLUSHABLE : PHP_OUTPUT_HANDLER_CLEANABLE);

        while ($level-- > $targetLevel && ($s = $status[$level]) && (!isset($s['del']) ? !isset($s['flags']) || ($s['flags'] & $flags) === $flags : $s['del'])) {
            if ($flush) {
                ob_end_flush();
            } else {
                ob_end_clean();
            }
        }
    }

    public function setContentSafe(/*bool*/ $safe = true)
    {
        if ($safe) {
            $this->headers->set('Preference-Applied', 'safe');
        } elseif ('safe' === $this->headers->get('Preference-Applied')) {
            $this->headers->remove('Preference-Applied');
        }

        $this->setVary('Prefer', false);
    }

    protected function ensureIEOverSSLCompatibility(/*Request*/ $request)
    {
        $disposition = $this->headers->get('Content-Disposition');
        if (is_string($disposition) && false !== stripos($disposition, 'attachment') && 1 == preg_match('/MSIE (.*?);/i', $request->server->get('HTTP_USER_AGENT'), $match) && true === $request->isSecure()) {
            if ((int) preg_replace('/(MSIE )(.*?);/', '$2', $match[0]) < 9) {
                $this->headers->remove('Cache-Control');
            }
        }
    }
}

if (!interface_exists('SessionHandlerInterface', false)) {
// since PHP 5.4+
interface SessionHandlerInterface
{
    /* Methods */
    public function close( /*void*/ ) /*: bool*/;
    public function destroy( /*string*/ $session_id ) /*: bool*/;
    public function gc( /*int*/ $maxlifetime ) /*: int*/;
    public function open( /*string*/ $save_path, /*string*/ $session_name ) /*: bool*/;
    public function read( /*string*/ $session_id ) /*: string*/;
    public function write( /*string*/ $session_id, /*string*/ $session_data ) /*: bool*/;
}
}

// adapted from CakePHP
class HttpSession implements SessionHandlerInterface
{
    protected $_handler = null;
    protected $_storage = 'native';
    protected $_started = false;
    protected $_lifetime = 0;
    protected $_isCLI = false;
    protected $_name = '';
    protected $sessionName = '';

    public static function create($config = array())
    {
        return new self($config);
    }

    public function __construct($config = array())
    {
        $this->_handler = isset($config['handler']) && is_object($config['handler']) ? $config['handler'] : null;

        $this->_storage = $this->_handler ? 'custom' : 'native';

        $ini = isset($config['ini']) ? (array)$config['ini'] : array();

        if (!isset($ini['session.cookie_secure']) && $this->isSsl() && ini_get('session.cookie_secure') != 1) {
            $ini['session.cookie_secure'] = 1;
        }

        if ( 'custom' === $this->_storage && !isset($ini['session.save_handler']) ) {
            $ini['session.save_handler'] = 'user';
        }

        // In PHP7.2.0+ session.save_handler can't be set to user by the user.
        // https://github.com/php/php-src/commit/a93a51c3bf4ea1638ce0adc4a899cb93531b9f0d
        if (isset($ini['session.save_handler']) && 'user'===$ini['session.save_handler'] && version_compare(PHP_VERSION, '7.2.0', '>=')) {
            unset($ini['session.save_handler']);
        }

        if (!isset($ini['session.use_strict_mode']) && ini_get('session.use_strict_mode') != 1) {
            $ini['session.use_strict_mode'] = 1;
        }

        if (!isset($ini['session.cookie_httponly']) && ini_get('session.cookie_httponly') != 1) {
            $ini['session.cookie_httponly'] = 1;
        }

        if (isset($config['timeout'])) {
            $ini['session.gc_maxlifetime'] = (int)$config['timeout'];
        }

        if (!empty($config['cookie'])) {
            $ini['session.name'] = $config['cookie'];
        }

        if (!isset($ini['session.cookie_path'])) {
            $cookiePath = empty($config['cookiePath']) ? '/' : $config['cookiePath'];
            $ini['session.cookie_path'] = $cookiePath;
        }

        if (!empty($ini) && is_array($ini)) {
            $this->options($ini);
        }

        if ( $this->_handler ) {
            $this->setHandler($this);
        }

        $this->_name = ini_get('session.name');
        $this->_lifetime = (int)ini_get('session.gc_maxlifetime');
        $this->_isCLI = $this->isCli();

        if (version_compare(PHP_VERSION, '5.4.0', '>=')) {
            session_register_shutdown();
        } else {
            register_shutdown_function('session_write_close');
        }
    }

    public function isCli()
    {
        return (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg');
    }

    public function isSsl()
    {
        return (!empty($_SERVER['HTTPS']) && 'off' !== strtolower($_SERVER['HTTPS'])) || (isset($_SERVER['SERVER_PORT']) && ('443' == $_SERVER['SERVER_PORT'])) ? true : false;
    }

    protected function setHandler($handler = null)
    {
        if (empty($handler)) {
            $handler = $this;
        }

        if (!($handler instanceof SessionHandlerInterface)) {
            // notify user that session handler given is invalid..
            throw new \RuntimeException('HttpSession Handler "'.get_class($handler).'" does not implement SessionHandlerInterface!');
        }

        if (!headers_sent() && session_status() !== \PHP_SESSION_ACTIVE) {

            if (version_compare(PHP_VERSION, '5.4.0', '>=')) {

                session_set_save_handler($handler, false);

            } else {

                session_set_save_handler(array($handler, 'open'), array($handler, 'close'), array($handler, 'read'), array($handler, 'write'), array($handler, 'destroy'), array($handler, 'gc'));

            }

        }
    }

    public function options($options)
    {
        if (session_status() === \PHP_SESSION_ACTIVE || headers_sent()) {
            return;
        }

        foreach ($options as $setting => $value) {
            if (ini_set($setting, (string)$value) === false) {
                throw new \RuntimeException(
                    sprintf('Unable to configure the session, setting %s failed.', $setting)
                );
            }
        }
    }

    public function get($key, $default = null)
    {
        return array_key_exists($key, $_SESSION) ? $_SESSION[$key] : $default;
    }

    public function set($key, $val)
    {
        $_SESSION[$key] = $val;
    }

    public function has($key)
    {
        return array_key_exists($key, $_SESSION);
    }

    public function start()
    {
        if ($this->_started) {
            return true;
        }

        if ($this->_isCLI) {
            $_SESSION = array();
            $this->id('cli');

            return $this->_started = true;
        }

        if (session_status() === \PHP_SESSION_ACTIVE) {
            throw new \RuntimeException('HttpSession was already started');
        }

        if (ini_get('session.use_cookies') && headers_sent($file, $line)) {
            return false;
        }

        if (!session_start()) {
            throw new \RuntimeException('Could not start the session');
        }

        $this->_started = true;

        return $this->_started;
    }

    public function started()
    {
        return $this->_started || session_status() === \PHP_SESSION_ACTIVE;
    }

    public function id($id = null)
    {
        if ($id !== null && !headers_sent()) {
            session_id($id);
        }

        return session_id();
    }

    public function getId()
    {
        return $this->id();
    }

    public function getName()
    {
        return $this->_name;
    }

    public function sessionDestroy()
    {
        if ($this->_hasSession() && !$this->started()) {
            $this->start();
        }

        if (!$this->_isCLI && session_status() === \PHP_SESSION_ACTIVE) {
            session_destroy();
        }

        $_SESSION = array();
        $this->_started = false;
    }

    public function clear($renew = false)
    {
        $_SESSION = array();
        if ($renew) {
            $this->renew();
        }
    }

    protected function _hasSession()
    {
        return !ini_get('session.use_cookies')
            || isset($_COOKIE[session_name()])
            || $this->_isCLI
            || (ini_get('session.use_trans_sid') && isset($_GET[session_name()]));
    }

    public function renew()
    {
        if (!$this->_hasSession() || $this->_isCLI) {
            return;
        }

        $this->start();
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params['path'],
            $params['domain'],
            $params['secure'],
            $params['httponly']
        );

        if (session_id()) {
            session_regenerate_id(true);
        }
    }

    // SessionHandlerInterface methods here ..
    // ..
    #[\ReturnTypeWillChange]
    public function open($savePath, $name)
    {
        $this->sessionName = $name;

        if (!headers_sent() && !ini_get('session.cache_limiter') && '0' !== ini_get('session.cache_limiter')) {
            header(sprintf('Cache-Control: max-age=%d, private, must-revalidate', 60 * (int) ini_get('session.cache_expire')));
        }
        if ('custom' == $this->_storage)
            $ret = (bool)$this->_handler->open($savePath, $name);
        else
            $ret = true;
        return $ret;
    }

    #[\ReturnTypeWillChange]
    public function close()
    {
        if ('custom' == $this->_storage)
            $ret = (bool)$this->_handler->close();
        else
            $ret = true;
        return $ret;
    }

    #[\ReturnTypeWillChange]
    public function read($id)
    {
        if ('custom' == $this->_storage) {
            $ret = $this->_handler->read($id);
        }

        if (empty($ret)) {
            return '';
        }

        return $ret;
    }

    #[\ReturnTypeWillChange]
    public function write($id, $data)
    {
        if (!$id) {
            return false;
        }

        $ret = false;
        if ('custom' == $this->_storage) {
            $ret = (bool)$this->_handler->write($id, $data, $this->_lifetime);
        }
        return $ret;
    }

    #[\ReturnTypeWillChange]
    public function destroy($id)
    {
        if (!headers_sent() && ini_get('session.use_cookies')) {
            if (!$this->sessionName) {
                throw new \LogicException(sprintf('HttpSession name cannot be empty, did you forget to call "parent::open()" in "%s"?.', get_class($this)));
            }
            $sessionCookie = sprintf(' %s=', urlencode($this->sessionName));
            $sessionCookieWithId = sprintf('%s%s;', $sessionCookie, urlencode($sessionId));
            $sessionCookieFound = false;
            $otherCookies = array();
            foreach (headers_list() as $h) {
                if (0 !== stripos($h, 'Set-Cookie:')) {
                    continue;
                }
                if (11 == strpos($h, $sessionCookie, 11)) {
                    $sessionCookieFound = true;

                    if (11 != strpos($h, $sessionCookieWithId, 11)) {
                        $otherCookies[] = $h;
                    }
                } else {
                    $otherCookies[] = $h;
                }
            }
            if ($sessionCookieFound) {
                header_remove('Set-Cookie');
                foreach ($otherCookies as $h) {
                    header($h, false);
                }
            } else {
                setcookie($this->sessionName, '', 0, ini_get('session.cookie_path'), ini_get('session.cookie_domain'), ini_get('session.cookie_secure'), ini_get('session.cookie_httponly'));
            }
        }

        if ('custom' == $this->_storage) {
            $ret = (bool)$this->_handler->destroy($id);
        }
        return true;
    }

    #[\ReturnTypeWillChange]
    public function gc($maxlifetime)
    {
        if ('custom' == $this->_storage) {
            $ret = (bool)$this->_handler->gc($maxlifetime);
        }
        return true;
    }
}