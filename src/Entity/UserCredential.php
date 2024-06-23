<?php

declare(strict_types=1);

namespace Platine\Webauthn\Entity;

use JsonSerializable;
use Platine\Webauthn\Helper\ByteBuffer;

/**
 * @class UserCredential
 * @package Platine\Webauthn\Entity
 */
class UserCredential implements JsonSerializable
{
    /**
     * The type
     * @var string
     */
    protected string $type = 'public-key';

    /**
     * The id
     * @var ByteBuffer
     */
    protected ByteBuffer $id;

    /**
     * The supported transport to use
     * @var array<string>
     */
    protected array $transports = [];

    /**
     * Create new instance
     * @param ByteBuffer|string $id
     * @param array<string> $transports
     */
    public function __construct($id, array $transports = [])
    {
        if (is_string($id)) {
            $id = new ByteBuffer($id);
        }

        $this->id = $id;
        $this->transports = $transports;
    }


    /**
     *
     * @return string
     */
    public function getType(): string
    {
        return $this->type;
    }

    /**
     *
     * @param ByteBuffer|string $id
     * @return $this
     */
    public function setId($id): self
    {
        if (is_string($id)) {
            $id = new ByteBuffer($id);
        }

        $this->id = $id;
        return $this;
    }

    /**
     *
     * @param array<string> $transports
     * @return $this
     */
    public function setTransports(array $transports): self
    {
        $this->transports = $transports;
        return $this;
    }


    /**
     *
     * @return ByteBuffer
     */
    public function getId(): ByteBuffer
    {
        return $this->id;
    }

    /**
     *
     * @return array<string>
     */
    public function getTransports(): array
    {
        return $this->transports;
    }

    /**
    * {@inheritdoc}
    * @return mixed
    */
    public function jsonSerialize()
    {
        return get_object_vars($this);
    }
}
