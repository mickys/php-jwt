<?php

namespace MiladRahimi\Jwt\Cryptography\Keys;

use MiladRahimi\Jwt\Exceptions\InvalidKeyException;
use Throwable;

/**
 * Class RsaPublicKey
 *
 * @package MiladRahimi\Jwt\Cryptography\Keys
 */
class RsaPublicKey
{
    /**
     * @var resource    Key file resource handler
     */
    private $resource;

    /**
     * PublicKey constructor.
     *
     * @param string $filePath
     * @throws InvalidKeyException
     */
    public function __construct(string $filePath, $contents = null)
    {
        try {

            $pcontents = null;
            if($contents !== null) {
                $pcontents = $contents;
            } else {
                $pcontents = file_get_contents(realpath($filePath));
            }
            $this->resource = openssl_pkey_get_public($pcontents);

            if (empty($this->resource)) {
                throw new InvalidKeyException();
            }
        } catch (InvalidKeyException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new InvalidKeyException('Failed to read the key.', 0, $e);
        }
    }

    /**
     * @return resource
     */
    public function getResource()
    {
        return $this->resource;
    }

    /**
     * Close key resource
     */
    public function close()
    {
        unset($this->resource);
    }
}
