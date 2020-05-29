<?php
/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

//namespace Symfony\Component\HttpFoundation;

/**
 * Represents a cookie.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
class HttpCookie
{
    protected $name;
    protected $value;
    protected $domain;
    protected $expire;
    protected $path;
    protected $secure;
    protected $httpOnly;
    private $raw;
    private $sameSite;

    const SAMESITE_LAX = 'lax';
    const SAMESITE_STRICT = 'strict';

    /**
     * Creates cookie from raw header string.
     *
     * @param string $cookie
     * @param bool   $decode
     *
     * @return static
     */
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
        );
        foreach (explode(';', $cookie) as $part) {
            if (false === strpos($part, '=')) {
                $key = trim($part);
                $value = true;
            } else {
                list($key, $value) = explode('=', trim($part), 2);
                $key = trim($key);
                $value = trim($value);
            }
            if (!isset($data['name'])) {
                $data['name'] = $decode ? urldecode($key) : $key;
                $data['value'] = true === $value ? null : ($decode ? urldecode($value) : $value);
                continue;
            }
            switch ($key = strtolower($key)) {
                case 'name':
                case 'value':
                    break;
                case 'max-age':
                    $data['expires'] = time() + (int) $value;
                    break;
                default:
                    $data[$key] = $value;
                    break;
            }
        }

        return new self($data['name'], $data['value'], $data['expires'], $data['path'], $data['domain'], $data['secure'], $data['httponly'], $data['raw'], $data['samesite']);
    }

    
    /**
     * @param string                        $name     The name of the cookie
     * @param string|null                   $value    The value of the cookie
     * @param int|string|\DateTimeInterface $expire   The time the cookie expires
     * @param string                        $path     The path on the server in which the cookie will be available on
     * @param string|null                   $domain   The domain that the cookie is available to
     * @param bool                          $secure   Whether the cookie should only be transmitted over a secure HTTPS connection from the client
     * @param bool                          $httpOnly Whether the cookie will be made accessible only through the HTTP protocol
     * @param bool                          $raw      Whether the cookie value should be sent with no url encoding
     * @param string|null                   $sameSite Whether the cookie will be available for cross-site requests
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(/*string*/ $name, /*string*/ $value = null, $expire = 0, /*?string*/ $path = '/', /*string*/ $domain = null, /*bool*/ $secure = false, /*bool*/ $httpOnly = true, /*bool*/ $raw = false, /*string*/ $sameSite = null)
    {
        // from PHP source code
        if (preg_match("/[=,; \t\r\n\013\014]/", $name)) {
            throw new \InvalidArgumentException(sprintf('The cookie name "%s" contains invalid characters.', $name));
        }

        if (empty($name)) {
            throw new \InvalidArgumentException('The cookie name cannot be empty.');
        }

        // convert expiration time to a Unix timestamp
        if ($expire instanceof \DateTimeInterface) {
            $expire = $expire->format('U');
        } elseif (!is_numeric($expire)) {
            $expire = strtotime($expire);

            if (false === $expire) {
                throw new \InvalidArgumentException('The cookie expiration time is not valid.');
            }
        }

        $this->name = $name;
        $this->value = $value;
        $this->domain = $domain;
        $this->expire = 0 < $expire ? (int) $expire : 0;
        $this->path = empty($path) ? '/' : $path;
        $this->secure = $secure;
        $this->httpOnly = $httpOnly;
        $this->raw = $raw;

        if (null !== $sameSite) {
            $sameSite = strtolower($sameSite);
        }

        if (!in_array($sameSite, array(self::SAMESITE_LAX, self::SAMESITE_STRICT, null), true)) {
            throw new \InvalidArgumentException('The "sameSite" parameter value is not valid.');
        }

        $this->sameSite = $sameSite;
    }

    /**
     * Returns the cookie as a string.
     *
     * @return string The cookie
     */
    public function __toString()
    {
        $str = ($this->isRaw() ? $this->getName() : urlencode($this->getName())).'=';

        if ('' === (string) $this->getValue()) {
            $str .= 'deleted; expires='.gmdate('D, d-M-Y H:i:s T', time() - 31536001).'; max-age=-31536001';
        } else {
            $str .= $this->isRaw() ? $this->getValue() : rawurlencode($this->getValue());

            if (0 !== $this->getExpiresTime()) {
                $str .= '; expires='.gmdate('D, d-M-Y H:i:s T', $this->getExpiresTime()).'; max-age='.$this->getMaxAge();
            }
        }

        if ($this->getPath()) {
            $str .= '; path='.$this->getPath();
        }

        if ($this->getDomain()) {
            $str .= '; domain='.$this->getDomain();
        }

        if (true === $this->isSecure()) {
            $str .= '; secure';
        }

        if (true === $this->isHttpOnly()) {
            $str .= '; httponly';
        }

        if (null !== $this->getSameSite()) {
            $str .= '; samesite='.$this->getSameSite();
        }

        return $str;
    }

    /**
     * Gets the name of the cookie.
     *
     * @return string
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * Gets the value of the cookie.
     *
     * @return string|null
     */
    public function getValue()
    {
        return $this->value;
    }

    /**
     * Gets the domain that the cookie is available to.
     *
     * @return string|null
     */
    public function getDomain()
    {
        return $this->domain;
    }

    /**
     * Gets the time the cookie expires.
     *
     * @return int
     */
    public function getExpiresTime()
    {
        return $this->expire;
    }

    /**
     * Gets the max-age attribute.
     *
     * @return int
     */
    public function getMaxAge()
    {
        return 0 !== $this->expire ? $this->expire - time() : 0;
    }

    /**
     * Gets the path on the server in which the cookie will be available on.
     *
     * @return string
     */
    public function getPath()
    {
        return $this->path;
    }

    /**
     * Checks whether the cookie should only be transmitted over a secure HTTPS connection from the client.
     *
     * @return bool
     */
    public function isSecure()
    {
        return $this->secure;
    }

    /**
     * Checks whether the cookie will be made accessible only through the HTTP protocol.
     *
     * @return bool
     */
    public function isHttpOnly()
    {
        return $this->httpOnly;
    }

    /**
     * Whether this cookie is about to be cleared.
     *
     * @return bool
     */
    public function isCleared()
    {
        return $this->expire < time();
    }

    /**
     * Checks if the cookie value should be sent with no url encoding.
     *
     * @return bool
     */
    public function isRaw()
    {
        return $this->raw;
    }

    /**
     * Gets the SameSite attribute.
     *
     * @return string|null
     */
    public function getSameSite()
    {
        return $this->sameSite;
    }
}


/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

//namespace Symfony\Component\HttpFoundation;

/**
 * HeaderBag is a container for HTTP headers.
 *
 * @author Fabien Potencier <fabien@symfony.com>
 */
class HttpHeaderBag implements \IteratorAggregate, \Countable
{
    protected $headers = array();
    protected $cacheControl = array();

    /**
     * @param array $headers An array of HTTP headers
     */
    public function __construct(/*array*/ $headers = array())
    {
        foreach ($headers as $key => $values) {
            $this->set($key, $values);
        }
    }

    /**
     * Returns the headers as a string.
     *
     * @return string The headers
     */
    public function __toString()
    {
        if (!$headers = $this->all()) {
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

    /**
     * Returns the headers.
     *
     * @return array An array of headers
     */
    public function all()
    {
        return $this->headers;
    }

    /**
     * Returns the parameter keys.
     *
     * @return array An array of parameter keys
     */
    public function keys()
    {
        return array_keys($this->all());
    }

    /**
     * Replaces the current HTTP headers by a new set.
     *
     * @param array $headers An array of HTTP headers
     */
    public function replace(/*array*/ $headers = array())
    {
        $this->headers = array();
        $this->add($headers);
    }

    /**
     * Adds new headers the current HTTP headers set.
     *
     * @param array $headers An array of HTTP headers
     */
    public function add(/*array*/ $headers)
    {
        foreach ($headers as $key => $values) {
            $this->set($key, $values);
        }
    }

    /**
     * Returns a header value by name.
     *
     * @param string          $key     The header name
     * @param string|string[] $default The default value
     * @param bool            $first   Whether to return the first value or all header values
     *
     * @return string|string[] The first header value or default value if $first is true, an array of values otherwise
     */
    public function get($key, $default = null, $first = true)
    {
        $key = str_replace('_', '-', strtolower($key));
        $headers = $this->all();

        if (!array_key_exists($key, $headers)) {
            if (null === $default) {
                return $first ? null : array();
            }

            return $first ? $default : array($default);
        }

        if ($first) {
            return \count($headers[$key]) ? $headers[$key][0] : $default;
        }

        return $headers[$key];
    }

    /**
     * Sets a header by name.
     *
     * @param string          $key     The key
     * @param string|string[] $values  The value or an array of values
     * @param bool            $replace Whether to replace the actual value or not (true by default)
     */
    public function set($key, $values, $replace = true)
    {
        $key = str_replace('_', '-', strtolower($key));

        if (\is_array($values)) {
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

    /**
     * Returns true if the HTTP header is defined.
     *
     * @param string $key The HTTP header
     *
     * @return bool true if the parameter exists, false otherwise
     */
    public function has($key)
    {
        return array_key_exists(str_replace('_', '-', strtolower($key)), $this->all());
    }

    /**
     * Returns true if the given HTTP header contains the given value.
     *
     * @param string $key   The HTTP header name
     * @param string $value The HTTP value
     *
     * @return bool true if the value is contained in the header, false otherwise
     */
    public function contains($key, $value)
    {
        return in_array($value, $this->get($key, null, false));
    }

    /**
     * Removes a header.
     *
     * @param string $key The HTTP header name
     */
    public function remove($key)
    {
        $key = str_replace('_', '-', strtolower($key));

        unset($this->headers[$key]);

        if ('cache-control' === $key) {
            $this->cacheControl = array();
        }
    }

    /**
     * Returns the HTTP header value converted to a date.
     *
     * @param string    $key     The parameter key
     * @param \DateTime $default The default value
     *
     * @return null|\DateTime The parsed DateTime or the default value if the header does not exist
     *
     * @throws \RuntimeException When the HTTP header is not parseable
     */
    public function getDate($key, /*\DateTime*/ $default = null)
    {
        if (null === $value = $this->get($key)) {
            return $default;
        }

        if (false === $date = \DateTime::createFromFormat(DATE_RFC2822, $value)) {
            throw new \RuntimeException(sprintf('The %s HTTP header is not parseable (%s).', $key, $value));
        }

        return $date;
    }

    /**
     * Adds a custom Cache-Control directive.
     *
     * @param string $key   The Cache-Control directive name
     * @param mixed  $value The Cache-Control directive value
     */
    public function addCacheControlDirective($key, $value = true)
    {
        $this->cacheControl[$key] = $value;

        $this->set('Cache-Control', $this->getCacheControlHeader());
    }

    /**
     * Returns true if the Cache-Control directive is defined.
     *
     * @param string $key The Cache-Control directive
     *
     * @return bool true if the directive exists, false otherwise
     */
    public function hasCacheControlDirective($key)
    {
        return array_key_exists($key, $this->cacheControl);
    }

    /**
     * Returns a Cache-Control directive value by name.
     *
     * @param string $key The directive name
     *
     * @return mixed|null The directive value if defined, null otherwise
     */
    public function getCacheControlDirective($key)
    {
        return array_key_exists($key, $this->cacheControl) ? $this->cacheControl[$key] : null;
    }

    /**
     * Removes a Cache-Control directive.
     *
     * @param string $key The Cache-Control directive
     */
    public function removeCacheControlDirective($key)
    {
        unset($this->cacheControl[$key]);

        $this->set('Cache-Control', $this->getCacheControlHeader());
    }

    /**
     * Returns an iterator for headers.
     *
     * @return \ArrayIterator An \ArrayIterator instance
     */
    public function getIterator()
    {
        return new \ArrayIterator($this->headers);
    }

    /**
     * Returns the number of headers.
     *
     * @return int The number of headers
     */
    public function count()
    {
        return count($this->headers);
    }

    protected function getCacheControlHeader()
    {
        $parts = array();
        ksort($this->cacheControl);
        foreach ($this->cacheControl as $key => $value) {
            if (true === $value) {
                $parts[] = $key;
            } else {
                if (preg_match('#[^a-zA-Z0-9._-]#', $value)) {
                    $value = '"'.$value.'"';
                }

                $parts[] = "$key=$value";
            }
        }

        return implode(', ', $parts);
    }

    /**
     * Parses a Cache-Control HTTP header.
     *
     * @param string $header The value of the Cache-Control HTTP header
     *
     * @return array An array representing the attribute values
     */
    protected function parseCacheControl($header)
    {
        $cacheControl = array();
        preg_match_all('#([a-zA-Z][a-zA-Z_-]*)\s*(?:=(?:"([^"]*)"|([^ \t",;]*)))?#', $header, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $cacheControl[strtolower($match[1])] = isset($match[3]) ? $match[3] : (isset($match[2]) ? $match[2] : true);
        }

        return $cacheControl;
    }
}


/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

//namespace Symfony\Component\HttpFoundation;

/**
 * ResponseHeaderBag is a container for Response HTTP headers.
 *
 * @author Fabien Potencier <fabien@symfony.com>
 */
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

    /**
     * Returns the headers, with original capitalizations.
     *
     * @return array An array of headers
     */
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

    /**
     * {@inheritdoc}
     */
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

    /**
     * {@inheritdoc}
     */
    public function all()
    {
        $headers = parent::all();
        foreach ($this->getCookies() as $cookie) {
            $headers['set-cookie'][] = (string) $cookie;
        }

        return $headers;
    }

    /**
     * {@inheritdoc}
     */
    public function set($key, $values, $replace = true)
    {
        $uniqueKey = str_replace('_', '-', strtolower($key));

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
        if (\in_array($uniqueKey, array('cache-control', 'etag', 'last-modified', 'expires'), true)) {
            $computed = $this->computeCacheControlValue();
            $this->headers['cache-control'] = array($computed);
            $this->headerNames['cache-control'] = 'Cache-Control';
            $this->computedCacheControl = $this->parseCacheControl($computed);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function remove($key)
    {
        $uniqueKey = str_replace('_', '-', strtolower($key));
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

    /**
     * {@inheritdoc}
     */
    public function hasCacheControlDirective($key)
    {
        return array_key_exists($key, $this->computedCacheControl);
    }

    /**
     * {@inheritdoc}
     */
    public function getCacheControlDirective($key)
    {
        return array_key_exists($key, $this->computedCacheControl) ? $this->computedCacheControl[$key] : null;
    }

    public function setCookie(/*HttpCookie*/ $cookie)
    {
        $this->cookies[$cookie->getDomain()][$cookie->getPath()][$cookie->getName()] = $cookie;
        $this->headerNames['set-cookie'] = 'Set-HttpCookie';
    }

    /**
     * Removes a cookie from the array, but does not unset it in the browser.
     *
     * @param string $name
     * @param string $path
     * @param string $domain
     */
    public function removeCookie($name, $path = '/', $domain = null)
    {
        if (null === $path) {
            $path = '/';
        }

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

    /**
     * Returns an array with all cookies.
     *
     * @param string $format
     *
     * @return array
     *
     * @throws \InvalidArgumentException When the $format is invalid
     */
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

    /**
     * Clears a cookie in the browser.
     *
     * @param string $name
     * @param string $path
     * @param string $domain
     * @param bool   $secure
     * @param bool   $httpOnly
     */
    public function clearCookie($name, $path = '/', $domain = null, $secure = false, $httpOnly = true)
    {
        $this->setCookie(new HttpCookie($name, null, 1, $path, $domain, $secure, $httpOnly));
    }

    /**
     * Generates a HTTP Content-Disposition field-value.
     *
     * @param string $disposition      One of "inline" or "attachment"
     * @param string $filename         A unicode string
     * @param string $filenameFallback A string containing only ASCII characters that
     *                                 is semantically equivalent to $filename. If the filename is already ASCII,
     *                                 it can be omitted, or just copied from $filename
     *
     * @return string A string suitable for use as a Content-Disposition field-value
     *
     * @throws \InvalidArgumentException
     *
     * @see RFC 6266
     */
    public function makeDisposition($disposition, $filename, $filenameFallback = '')
    {
        if (!in_array($disposition, array(self::DISPOSITION_ATTACHMENT, self::DISPOSITION_INLINE))) {
            throw new \InvalidArgumentException(sprintf('The disposition must be either "%s" or "%s".', self::DISPOSITION_ATTACHMENT, self::DISPOSITION_INLINE));
        }

        if ('' == $filenameFallback) {
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

        $output = sprintf('%s; filename="%s"', $disposition, str_replace('"', '\\"', $filenameFallback));

        if ($filename !== $filenameFallback) {
            $output .= sprintf("; filename*=utf-8''%s", rawurlencode($filename));
        }

        return $output;
    }

    /**
     * Returns the calculated value of the cache-control header.
     *
     * This considers several other headers and calculates or modifies the
     * cache-control header to a sensible, conservative value.
     *
     * @return string
     */
    protected function computeCacheControlValue()
    {
        if (!$this->cacheControl && !$this->has('ETag') && !$this->has('Last-Modified') && !$this->has('Expires')) {
            return 'no-cache, private';
        }

        if (!$this->cacheControl) {
            // conservative by default
            return 'private, must-revalidate';
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
        $now = \DateTime::createFromFormat('U', time());
        $now->setTimezone(new \DateTimeZone('UTC'));
        $this->set('Date', $now->format('D, d M Y H:i:s').' GMT');
    }
}


/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

//namespace Symfony\Component\HttpFoundation;

/**
 * Response represents an HTTP response.
 *
 * @author Fabien Potencier <fabien@symfony.com>
 */
class HttpResponse
{
    const HTTP_CONTINUE = 100;
    const HTTP_SWITCHING_PROTOCOLS = 101;
    const HTTP_PROCESSING = 102;            // RFC2518
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
    const HTTP_RESERVED_FOR_WEBDAV_ADVANCED_COLLECTIONS_EXPIRED_PROPOSAL = 425;   // RFC2817
    const HTTP_UPGRADE_REQUIRED = 426;                                            // RFC2817
    const HTTP_PRECONDITION_REQUIRED = 428;                                       // RFC6585
    const HTTP_TOO_MANY_REQUESTS = 429;                                           // RFC6585
    const HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE = 431;                             // RFC6585
    const HTTP_UNAVAILABLE_FOR_LEGAL_REASONS = 451;
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
     * @var \Symfony\Component\HttpFoundation\HttpResponseHeaderBag
     */
    public $headers;

    /**
     * @var string
     */
    protected $content;
    protected $file = null;
    protected $maxlen;
    protected $offset;
    protected $_deleteFileAfterSend = false;
    protected $targetUrl = null;
    protected $callback = null;
    protected $streamed;
    private $headersSent;

    /**
     * @var string
     */
    protected $version;

    /**
     * @var int
     */
    protected $statusCode;

    /**
     * @var string
     */
    protected $statusText;

    /**
     * @var string
     */
    protected $charset;

    /**
     * Status codes translation table.
     *
     * The list of codes is complete according to the
     * {@link http://www.iana.org/assignments/http-status-codes/ Hypertext Transfer Protocol (HTTP) Status Code Registry}
     * (last updated 2016-03-01).
     *
     * Unless otherwise noted, the status code is defined in RFC2616.
     *
     * @var array
     */
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
        413 => 'Payload Too Large',
        414 => 'URI Too Long',
        415 => 'Unsupported Media Type',
        416 => 'Range Not Satisfiable',
        417 => 'Expectation Failed',
        418 => 'I\'m a teapot',                                               // RFC2324
        421 => 'Misdirected Request',                                         // RFC7540
        422 => 'Unprocessable Entity',                                        // RFC4918
        423 => 'Locked',                                                      // RFC4918
        424 => 'Failed Dependency',                                           // RFC4918
        425 => 'Reserved for WebDAV advanced collections expired proposal',   // RFC2817
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
    );

    /**
     * @throws \InvalidArgumentException When the HTTP status code is not valid
     */
    public function __construct($content = '', /*int*/ $status = 200, /*array*/ $headers = array())
    {
        $this->headers = new HttpResponseHeaderBag($headers);
        $this->setContent($content);
        $this->setStatusCode($status);
        $this->setProtocolVersion('1.0');
        
        $this->streamed = false;
        $this->headersSent = false;
    }

    /**
     * Factory method for chainability.
     *
     * Example:
     *
     *     return HttpResponse::create($body, 200)
     *         ->setSharedMaxAge(300);
     *
     * @param mixed $content The response content, see setContent()
     * @param int   $status  The response status code
     * @param array $headers An array of response headers
     *
     * @return static
     */
    public static function create($content = '', $status = 200, $headers = array())
    {
        return new self($content, $status, $headers);
    }

    /**
     * Returns the HttpResponse as an HTTP string.
     *
     * The string representation of the HttpResponse is the same as the
     * one that will be sent to the client only if the prepare() method
     * has been called before.
     *
     * @return string The HttpResponse as an HTTP string
     *
     * @see prepare()
     */
    public function __toString()
    {
        return
            sprintf('HTTP/%s %s %s', $this->version, $this->statusCode, $this->statusText)."\r\n".
            $this->headers."\r\n".
            $this->getContent();
    }

    /**
     * Clones the current HttpResponse instance.
     */
    public function __clone()
    {
        $this->headers = clone $this->headers;
    }

    /**
     * Prepares the HttpResponse before it is sent to the client.
     *
     * This method tweaks the HttpResponse to ensure that it is
     * compliant with RFC 2616. Most of the changes are based on
     * the Request that is "associated" with this HttpResponse.
     *
     * @return $this
     */
    public function prepare(/*Request*/ $request)
    {
        if ( $this->file ) {
            if (!$this->headers->has('Content-Type')) {
                $file_type = mime_content_type( $this->file );
                if ( empty($file_type) ) $file_type = 'application/octet-stream';
                $this->headers->set('Content-Type', $file_type);
            }

            if ('HTTP/1.0' !== $request->server->get('SERVER_PROTOCOL')) {
                $this->setProtocolVersion('1.1');
            }

            $this->ensureIEOverSSLCompatibility($request);

            $this->offset = 0;
            $this->maxlen = -1;

            if (false === $fileSize = filesize($this->file)) {
                return $this;
            }
            $this->headers->set('Content-Length', $fileSize);

            if (!$this->headers->has('Accept-Ranges')) {
                // Only accept ranges on safe HTTP methods
                $this->headers->set('Accept-Ranges', $request->isMethodSafe(false) ? 'bytes' : 'none');
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
                    // @link http://wiki.nginx.org/X-accel#X-Accel-Redirect
                    foreach (explode(',', $request->headers->get('X-Accel-Mapping', '')) as $mapping) {
                        $mapping = explode('=', $mapping, 2);

                        if (2 === count($mapping)) {
                            $pathPrefix = trim($mapping[0]);
                            $location = trim($mapping[1]);

                            if (substr($path, 0, strlen($pathPrefix)) === $pathPrefix) {
                                $path = $location.substr($path, strlen($pathPrefix));
                                break;
                            }
                        }
                    }
                }
                $this->headers->set($type, $path);
                $this->maxlen = 0;
            } elseif ($request->headers->has('Range')) {
                // Process the range headers.
                if (!$request->headers->has('If-Range') || $this->hasValidIfRangeHeader($request->headers->get('If-Range'))) {
                    $range = $request->headers->get('Range');

                    list($start, $end) = explode('-', substr($range, 6), 2) + array(0);

                    $end = ('' === $end) ? $fileSize - 1 : (int) $end;

                    if ('' === $start) {
                        $start = $fileSize - $end;
                        $end = $fileSize - 1;
                    } else {
                        $start = (int) $start;
                    }

                    if ($start <= $end) {
                        if ($start < 0 || $end > $fileSize - 1) {
                            $this->setStatusCode(416);
                            $this->headers->set('Content-Range', sprintf('bytes */%s', $fileSize));
                        } elseif (0 !== $start || $end !== $fileSize - 1) {
                            $this->maxlen = $end < $fileSize ? $end - $start + 1 : -1;
                            $this->offset = $start;

                            $this->setStatusCode(206);
                            $this->headers->set('Content-Range', sprintf('bytes %s-%s/%s', $start, $end, $fileSize));
                            $this->headers->set('Content-Length', $end - $start + 1);
                        }
                    }
                }
            }
            return $this;
        }
        
        $headers = $this->headers;

        if ($this->isInformational() || $this->isEmpty()) {
            $this->setContent(null);
            $headers->remove('Content-Type');
            $headers->remove('Content-Length');
        } else {
            // Content-type based on the Request
            if (!$headers->has('Content-Type')) {
                $format = $request->getRequestFormat();
                if (null !== $format && $mimeType = $request->getMimeType($format)) {
                    $headers->set('Content-Type', $mimeType);
                }
            }

            // Fix Content-Type
            $charset = $this->charset ? $this->charset : 'UTF-8';
            if (!$headers->has('Content-Type')) {
                $headers->set('Content-Type', 'text/html; charset='.$charset);
                // adapted from CakePHP, Http\HttpResponse class
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
        if ('1.0' == $this->getProtocolVersion() && false !== strpos($this->headers->get('Cache-Control'), 'no-cache')) {
            $this->headers->set('pragma', 'no-cache');
            $this->headers->set('expires', -1);
        }

        $this->ensureIEOverSSLCompatibility($request);

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
    
    /**
     * Sends HTTP headers.
     *
     * @return $this
     */
    public function sendHeaders()
    {
        // headers have already been sent by the developer
        if ($this->headersSent || headers_sent()) {
            return $this;
        }

        $this->headersSent = true;
        
        // headers
        foreach ($this->headers->allPreserveCaseWithoutCookies() as $name => $values) {
            foreach ($values as $value) {
                header($name.': '.$value, false, $this->statusCode);
            }
        }

        // status
        header(sprintf('HTTP/%s %s %s', $this->version, $this->statusCode, $this->statusText), true, $this->statusCode);

        // cookies
        foreach ($this->headers->getCookies() as $cookie) {
            if ($cookie->isRaw()) {
                setrawcookie($cookie->getName(), $cookie->getValue(), $cookie->getExpiresTime(), $cookie->getPath(), $cookie->getDomain(), $cookie->isSecure(), $cookie->isHttpOnly());
            } else {
                setcookie($cookie->getName(), $cookie->getValue(), $cookie->getExpiresTime(), $cookie->getPath(), $cookie->getDomain(), $cookie->isSecure(), $cookie->isHttpOnly());
            }
        }

        return $this;
    }

    /**
     * Sends content for the current web response.
     *
     * @return $this
     */
    public function sendContent()
    {
        if ( $this->callback ) {
            if ($this->streamed) {
                return $this;
            }

            $this->streamed = true;

            call_user_func($this->callback);
                
        } elseif ( $this->file ) {
            if (!$this->isSuccessful()) {
                echo $this->content;
                return $this;
            }
            
            if (0 === $this->maxlen) {
                return $this;
            }
            
            $out = fopen('php://output', 'wb');
            $file = fopen($this->file, 'rb');

            stream_copy_to_stream($file, $out, $this->maxlen, $this->offset);

            fclose($out);
            fclose($file);
            
            if ($this->_deleteFileAfterSend) {
                unlink($this->file);
            }
            
        } else {
            echo $this->content;
        }

        return $this;
    }

    /**
     * Sends HTTP headers and content.
     *
     * @return $this
     */
    public function send()
    {
        $this->sendHeaders();
        $this->sendContent();

        if (function_exists('fastcgi_finish_request')) {
            fastcgi_finish_request();
        } elseif (!\in_array(PHP_SAPI, array('cli', 'phpdbg'), true)) {
            self::closeOutputBuffers(0, true);
        }

        return $this;
    }

    /**
     * Sets the response content.
     *
     * Valid types are strings, numbers, null, and objects that implement a __toString() method.
     *
     * @param mixed $content Content that can be cast to string
     *
     * @return $this
     *
     * @throws \UnexpectedValueException
     */
    public function setContent($content)
    {
        if (null !== $content && !is_string($content) && !is_numeric($content) && !is_callable(array($content, '__toString'))) {
            throw new \UnexpectedValueException(sprintf('The HttpResponse content must be a string or object implementing __toString(), "%s" given.', gettype($content)));
        }

        $this->content = (string) $content;

        return $this;
    }

    public function setFile($file, $contentDisposition = null, $autoEtag = false, $autoLastModified = true)
    {
        if (!is_readable($file)) {
            throw new /*File*/\Exception('File must be readable.');
        }

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

        return $this;
    }

    /**
     * Gets the file.
     *
     * @return File The file to stream
     */
    public function getFile()
    {
        return $this->file;
    }
    

    public function deleteFileAfterSend($shouldDelete=true)
    {
        $this->_deleteFileAfterSend = (bool)$shouldDelete;
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
    
    /**
     * Automatically sets the Last-Modified header according the file modification date.
     */
    public function setAutoLastModified()
    {
        $this->setLastModified(\DateTime::createFromFormat('U', filemtime($this->file)));

        return $this;
    }

    /**
     * Automatically sets the ETag header according to the checksum of the file.
     */
    public function setAutoEtag()
    {
        $this->setEtag(base64_encode(hash_file('sha256', $this->file, true)));

        return $this;
    }

		/**
     * Sets the Content-Disposition header with the given filename.
     *
     * @param string $disposition      HttpResponseHeaderBag::DISPOSITION_INLINE or HttpResponseHeaderBag::DISPOSITION_ATTACHMENT
     * @param string $filename         Optionally use this UTF-8 encoded filename instead of the real name of the file
     * @param string $filenameFallback A fallback filename, containing only ASCII characters. Defaults to an automatically encoded filename
     *
     * @return $this
     */
    public function setContentDisposition($disposition, $filename = '', $filenameFallback = '')
    {
        if ('' === $filename) {
            $filename = basename($this->file);
        }

        if ('' === $filenameFallback && (!preg_match('/^[\x20-\x7e]*$/', $filename) || false !== strpos($filename, '%'))) {
            $encoding = mb_detect_encoding($filename, null, true) ?: '8bit';

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

    /**
     * Returns the target URL.
     *
     * @return string target URL
     */
    public function getTargetUrl()
    {
        return $this->targetUrl;
    }

    /**
     * Sets the redirect target of this response.
     *
     * @param string $url The URL to redirect to
     *
     * @return $this
     *
     * @throws \InvalidArgumentException
     */
    public function setTargetUrl($url, $statusCode=302)
    {
        if (empty($url)) {
            throw new \InvalidArgumentException('Cannot redirect to an empty URL.');
        }

        $this->targetUrl = $url;
        
        $this->setStatusCode( (int)$statusCode );

        if (301 == $this->getStatusCode() && $this->headers->has('cache-control')) {
            $this->headers->remove('cache-control');
        }

        $this->setContent(
            sprintf('<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8" />
        <meta http-equiv="refresh" content="0;url=%1$s" />

        <title>Redirecting to %1$s</title>
    </head>
    <body>
        Redirecting to <a href="%1$s">%1$s</a>.
    </body>
</html>', htmlspecialchars($url, ENT_QUOTES, 'UTF-8')));

        $this->headers->set('Location', $url);

        return $this;
    }
		
    /**
     * Gets the current response content.
     *
     * @return string Content
     */
    public function getContent()
    {
        return $this->content;
    }

    /**
     * Sets the HTTP protocol version (1.0 or 1.1).
     *
     * @return $this
     *
     * @final
     */
    public function setProtocolVersion(/*string*/ $version)
    {
        $this->version = $version;

        return $this;
    }

    /**
     * Gets the HTTP protocol version.
     *
     * @final
     */
    public function getProtocolVersion()/*: string*/
    {
        return $this->version;
    }

    /**
     * Sets the response status code.
     *
     * If the status text is null it will be automatically populated for the known
     * status codes and left empty otherwise.
     *
     * @return $this
     *
     * @throws \InvalidArgumentException When the HTTP status code is not valid
     *
     * @final
     */
    public function setStatusCode(/*int*/ $code, $text = null)
    {
        $this->statusCode = $code;
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

    /**
     * Retrieves the status code for the current web response.
     *
     * @final
     */
    public function getStatusCode()/*: int*/
    {
        return $this->statusCode;
    }

    /**
     * Sets the response charset.
     *
     * @return $this
     *
     * @final
     */
    public function setCharset(/*string*/ $charset)
    {
        $this->charset = $charset;

        return $this;
    }

    /**
     * Retrieves the response charset.
     *
     * @final
     */
    public function getCharset()/*: ?string*/
    {
        return $this->charset;
    }

    /**
     * Returns true if the response is worth caching under any circumstance.
     *
     * Responses marked "private" with an explicit Cache-Control directive are
     * considered uncacheable.
     *
     * Responses with neither a freshness lifetime (Expires, max-age) nor cache
     * validator (Last-Modified, ETag) are considered uncacheable.
     *
     * @final
     */
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

    /**
     * Returns true if the response is "fresh".
     *
     * Fresh responses may be served from cache without any interaction with the
     * origin. A response is considered fresh when it includes a Cache-Control/max-age
     * indicator or Expires header and the calculated age is less than the freshness lifetime.
     *
     * @final
     */
    public function isFresh()/*: bool*/
    {
        return $this->getTtl() > 0;
    }

    /**
     * Returns true if the response includes headers that can be used to validate
     * the response with the origin server using a conditional GET request.
     *
     * @final
     */
    public function isValidateable()/*: bool*/
    {
        return $this->headers->has('Last-Modified') || $this->headers->has('ETag');
    }

    /**
     * Marks the response as "private".
     *
     * It makes the response ineligible for serving other clients.
     *
     * @return $this
     *
     * @final
     */
    public function setPrivate()
    {
        $this->headers->removeCacheControlDirective('public');
        $this->headers->addCacheControlDirective('private');

        return $this;
    }

    /**
     * Marks the response as "public".
     *
     * It makes the response eligible for serving other clients.
     *
     * @return $this
     *
     * @final
     */
    public function setPublic()
    {
        $this->headers->addCacheControlDirective('public');
        $this->headers->removeCacheControlDirective('private');

        return $this;
    }

    /**
     * Marks the response as "immutable".
     *
     * @return $this
     *
     * @final
     */
    public function setImmutable(/*bool*/ $immutable = true)
    {
        if ($immutable) {
            $this->headers->addCacheControlDirective('immutable');
        } else {
            $this->headers->removeCacheControlDirective('immutable');
        }

        return $this;
    }

    /**
     * Returns true if the response is marked as "immutable".
     *
     * @final
     */
    public function isImmutable()/*: bool*/
    {
        return $this->headers->hasCacheControlDirective('immutable');
    }

    /**
     * Returns true if the response must be revalidated by caches.
     *
     * This method indicates that the response must not be served stale by a
     * cache in any circumstance without first revalidating with the origin.
     * When present, the TTL of the response should not be overridden to be
     * greater than the value provided by the origin.
     *
     * @final
     */
    public function mustRevalidate()/*: bool*/
    {
        return $this->headers->hasCacheControlDirective('must-revalidate') || $this->headers->hasCacheControlDirective('proxy-revalidate');
    }

    /**
     * Returns the Date header as a DateTime instance.
     *
     * @throws \RuntimeException When the header is not parseable
     *
     * @final
     */
    public function getDate()/*: ?\DateTimeInterface*/
    {
        return $this->headers->getDate('Date');
    }

    /**
     * Sets the Date header.
     *
     * @return $this
     *
     * @final
     */
    public function setDate(/*\DateTimeInterface*/ $date)
    {
        if ($date instanceof \DateTime) {
            $date = \DateTimeImmutable::createFromMutable($date);
        }

        $date = $date->setTimezone(new \DateTimeZone('UTC'));
        $this->headers->set('Date', $date->format('D, d M Y H:i:s').' GMT');

        return $this;
    }

    /**
     * Returns the age of the response in seconds.
     *
     * @final
     */
    public function getAge()/*: int*/
    {
        if (null !== $age = $this->headers->get('Age')) {
            return (int) $age;
        }

        return max(time() - $this->getDate()->format('U'), 0);
    }

    /**
     * Marks the response stale by setting the Age header to be equal to the maximum age of the response.
     *
     * @return $this
     */
    public function expire()
    {
        if ($this->isFresh()) {
            $this->headers->set('Age', $this->getMaxAge());
        }

        return $this;
    }

    /**
     * Returns the value of the Expires header as a DateTime instance.
     *
     * @final
     */
    public function getExpires()/*: ?\DateTimeInterface*/
    {
        try {
            return $this->headers->getDate('Expires');
        } catch (\RuntimeException $e) {
            // according to RFC 2616 invalid date formats (e.g. "0" and "-1") must be treated as in the past
            return \DateTime::createFromFormat('U', time() - 172800);
        }
    }

    /**
     * Sets the Expires HTTP header with a DateTime instance.
     *
     * Passing null as value will remove the header.
     *
     * @return $this
     *
     * @final
     */
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

    /**
     * Returns the number of seconds after the time specified in the response's Date
     * header when the response should no longer be considered fresh.
     *
     * First, it checks for a s-maxage directive, then a max-age directive, and then it falls
     * back on an expires header. It returns null when no maximum age can be established.
     *
     * @final
     */
    public function getMaxAge()/*: ?int*/
    {
        if ($this->headers->hasCacheControlDirective('s-maxage')) {
            return (int) $this->headers->getCacheControlDirective('s-maxage');
        }

        if ($this->headers->hasCacheControlDirective('max-age')) {
            return (int) $this->headers->getCacheControlDirective('max-age');
        }

        if (null !== $this->getExpires()) {
            return (int) ($this->getExpires()->format('U') - $this->getDate()->format('U'));
        }

        return null;
    }

    /**
     * Sets the number of seconds after which the response should no longer be considered fresh.
     *
     * This methods sets the Cache-Control max-age directive.
     *
     * @return $this
     *
     * @final
     */
    public function setMaxAge(/*int*/ $value)
    {
        $this->headers->addCacheControlDirective('max-age', $value);

        return $this;
    }

    /**
     * Sets the number of seconds after which the response should no longer be considered fresh by shared caches.
     *
     * This methods sets the Cache-Control s-maxage directive.
     *
     * @return $this
     *
     * @final
     */
    public function setSharedMaxAge(/*int*/ $value)
    {
        $this->setPublic();
        $this->headers->addCacheControlDirective('s-maxage', $value);

        return $this;
    }

    /**
     * Returns the response's time-to-live in seconds.
     *
     * It returns null when no freshness information is present in the response.
     *
     * When the responses TTL is <= 0, the response may not be served from cache without first
     * revalidating with the origin.
     *
     * @final
     */
    public function getTtl()/*: ?int*/
    {
        $maxAge = $this->getMaxAge();

        return null !== $maxAge ? $maxAge - $this->getAge() : null;
    }

    /**
     * Sets the response's time-to-live for shared caches in seconds.
     *
     * This method adjusts the Cache-Control/s-maxage directive.
     *
     * @return $this
     *
     * @final
     */
    public function setTtl(/*int*/ $seconds)
    {
        $this->setSharedMaxAge($this->getAge() + $seconds);

        return $this;
    }

    /**
     * Sets the response's time-to-live for private/client caches in seconds.
     *
     * This method adjusts the Cache-Control/max-age directive.
     *
     * @return $this
     *
     * @final
     */
    public function setClientTtl(/*int*/ $seconds)
    {
        $this->setMaxAge($this->getAge() + $seconds);

        return $this;
    }

    /**
     * Returns the Last-Modified HTTP header as a DateTime instance.
     *
     * @throws \RuntimeException When the HTTP header is not parseable
     *
     * @final
     */
    public function getLastModified()/*: ?\DateTimeInterface*/
    {
        return $this->headers->getDate('Last-Modified');
    }

    /**
     * Sets the Last-Modified HTTP header with a DateTime instance.
     *
     * Passing null as value will remove the header.
     *
     * @return $this
     *
     * @final
     */
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

    /**
     * Returns the literal value of the ETag HTTP header.
     *
     * @final
     */
    public function getEtag()/*: ?string*/
    {
        return $this->headers->get('ETag');
    }

    /**
     * Sets the ETag value.
     *
     * @param string|null $etag The ETag unique identifier or null to remove the header
     * @param bool        $weak Whether you want a weak ETag or not
     *
     * @return $this
     *
     * @final
     */
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

    /**
     * Sets the response's cache headers (validation and/or expiration).
     *
     * Available options are: etag, last_modified, max_age, s_maxage, private, public and immutable.
     *
     * @return $this
     *
     * @throws \InvalidArgumentException
     *
     * @final
     */
    public function setCache(/*array*/ $options)
    {
        if ($diff = array_diff(array_keys($options), array('etag', 'last_modified', 'max_age', 's_maxage', 'private', 'public', 'immutable'))) {
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

    /**
     * Modifies the response so that it conforms to the rules defined for a 304 status code.
     *
     * This sets the status, removes the body, and discards any headers
     * that MUST NOT be included in 304 responses.
     *
     * @return $this
     *
     * @see http://tools.ietf.org/html/rfc2616#section-10.3.5
     *
     * @final
     */
    public function setNotModified()
    {
        $this->setStatusCode(304);
        $this->setContent(null);

        // remove headers that MUST NOT be included with 304 Not Modified responses
        foreach (array('Allow', 'Content-Encoding', 'Content-Language', 'Content-Length', 'Content-MD5', 'Content-Type', 'Last-Modified') as $header) {
            $this->headers->remove($header);
        }

        return $this;
    }

    /**
     * Returns true if the response includes a Vary header.
     *
     * @final
     */
    public function hasVary()/*: bool*/
    {
        return null !== $this->headers->get('Vary');
    }

    /**
     * Returns an array of header names given in the Vary header.
     *
     * @final
     */
    public function getVary()/*: array*/
    {
        if (!$vary = $this->headers->get('Vary', null, false)) {
            return array();
        }

        $ret = array();
        foreach ($vary as $item) {
            $ret = array_merge($ret, preg_split('/[\s,]+/', $item));
        }

        return $ret;
    }

    /**
     * Sets the Vary header.
     *
     * @param string|array $headers
     * @param bool         $replace Whether to replace the actual value or not (true by default)
     *
     * @return $this
     *
     * @final
     */
    public function setVary($headers, /*bool*/ $replace = true)
    {
        $this->headers->set('Vary', $headers, $replace);

        return $this;
    }

    /**
     * Determines if the HttpResponse validators (ETag, Last-Modified) match
     * a conditional value specified in the Request.
     *
     * If the HttpResponse is not modified, it sets the status code to 304 and
     * removes the actual content by calling the setNotModified() method.
     *
     * @return bool true if the HttpResponse validators match the Request, false otherwise
     *
     * @final
     */
    public function isNotModified(/*Request*/ $request)/*: bool*/
    {
        if (!$request->isMethodCacheable()) {
            return false;
        }

        $notModified = false;
        $lastModified = $this->headers->get('Last-Modified');
        $modifiedSince = $request->headers->get('If-Modified-Since');

        if ($etags = $request->getETags()) {
            $notModified = in_array($this->getEtag(), $etags) || in_array('*', $etags);
        }

        if ($modifiedSince && $lastModified) {
            $notModified = strtotime($modifiedSince) >= strtotime($lastModified) && (!$etags || $notModified);
        }

        if ($notModified) {
            $this->setNotModified();
        }

        return $notModified;
    }

    /**
     * Is response invalid?
     *
     * @see http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
     *
     * @final
     */
    public function isInvalid()/*: bool*/
    {
        return $this->statusCode < 100 || $this->statusCode >= 600;
    }

    /**
     * Is response informative?
     *
     * @final
     */
    public function isInformational()/*: bool*/
    {
        return $this->statusCode >= 100 && $this->statusCode < 200;
    }

    /**
     * Is response successful?
     *
     * @final
     */
    public function isSuccessful()/*: bool*/
    {
        return $this->statusCode >= 200 && $this->statusCode < 300;
    }

    /**
     * Is the response a redirect?
     *
     * @final
     */
    public function isRedirection()/*: bool*/
    {
        return $this->statusCode >= 300 && $this->statusCode < 400;
    }

    /**
     * Is there a client error?
     *
     * @final
     */
    public function isClientError()/*: bool*/
    {
        return $this->statusCode >= 400 && $this->statusCode < 500;
    }

    /**
     * Was there a server side error?
     *
     * @final
     */
    public function isServerError()/*: bool*/
    {
        return $this->statusCode >= 500 && $this->statusCode < 600;
    }

    /**
     * Is the response OK?
     *
     * @final
     */
    public function isOk()/*: bool*/
    {
        return 200 === $this->statusCode;
    }

    /**
     * Is the response forbidden?
     *
     * @final
     */
    public function isForbidden()/*: bool*/
    {
        return 403 === $this->statusCode;
    }

    /**
     * Is the response a not found error?
     *
     * @final
     */
    public function isNotFound()/*: bool*/
    {
        return 404 === $this->statusCode;
    }

    /**
     * Is the response a redirect of some form?
     *
     * @final
     */
    public function isRedirect(/*string*/ $location = null)/*: bool*/
    {
        return in_array($this->statusCode, array(201, 301, 302, 303, 307, 308)) && (null === $location ?: $location == $this->headers->get('Location'));
    }

    /**
     * Is the response empty?
     *
     * @final
     */
    public function isEmpty()/*: bool*/
    {
        return in_array($this->statusCode, array(204, 304));
    }

    /**
     * Cleans or flushes output buffers up to target level.
     *
     * Resulting level can be greater than target level if a non-removable buffer has been encountered.
     *
     * @final
     */
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

    /**
     * Checks if we need to remove Cache-Control for SSL encrypted downloads when using IE < 9.
     *
     * @see http://support.microsoft.com/kb/323308
     *
     * @final
     */
    protected function ensureIEOverSSLCompatibility(/*Request*/ $request)
    {
        if (false !== stripos($this->headers->get('Content-Disposition'), 'attachment') && 1 == preg_match('/MSIE (.*?);/i', $request->server->get('HTTP_USER_AGENT'), $match) && true === $request->isSecure()) {
            if ((int) preg_replace('/(MSIE )(.*?);/', '$2', $match[0]) < 9) {
                $this->headers->remove('Cache-Control');
            }
        }
    }
}
