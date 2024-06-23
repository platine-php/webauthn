<?php

declare(strict_types=1);

namespace Platine\Webauthn\Entity;

use JsonSerializable;
use Platine\Webauthn\Helper\ByteBuffer;

/**
 * @class UserInfo
 * @package Platine\Webauthn\Entity
 */
class UserInfo implements JsonSerializable
{
    /**
     * The id
     * @var ByteBuffer
     */
    protected ByteBuffer $id;

    /**
     * The user name
     * @var string
     */
    protected string $name;

    /**
     * The user display name
     * @var string
     */
    protected string $displayName;

    /**
     *
     * @param ByteBuffer|string $id
     * @param string $name
     * @param string $displayName
     */
    public function __construct($id, string $name, string $displayName)
    {
        if (is_string($id)) {
            $id = new ByteBuffer($id);
        }

        $this->id = $id;
        $this->name = $name;
        $this->displayName = $displayName;
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
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     *
     * @return string
     */
    public function getDisplayName(): string
    {
        return $this->displayName;
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
     * @param string $name
     * @return $this
     */
    public function setName(string $name): self
    {
        $this->name = $name;
        return $this;
    }

    /**
     *
     * @param string $displayName
     * @return $this
     */
    public function setDisplayName(string $displayName): self
    {
        $this->displayName = $displayName;
        return $this;
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
