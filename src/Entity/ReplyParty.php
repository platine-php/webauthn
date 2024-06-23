<?php

declare(strict_types=1);

namespace Platine\Webauthn\Entity;

use JsonSerializable;

/**
 * @class ReplyParty
 * @package Platine\Webauthn\Entity
 */
class ReplyParty implements JsonSerializable
{
    /**
     * The reply party id
     * @var string
     */
    protected string $id;

    /**
     * The reply party name
     * @var string
     */
    protected string $name;

    /**
     * The reply party logo base64 image format
     * @var string
     */
    protected string $logo = '';

    /**
     * Create new instance
     * @param string $id
     * @param string $name
     * @param string $logo
     */
    public function __construct(string $id, string $name, string $logo = '')
    {
        $this->id = $id;
        $this->name = $name;
        $this->logo = $logo;
    }

    /**
     *
     * @return string
     */
    public function getId(): string
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
    public function getLogo(): string
    {
        return $this->logo;
    }

    /**
     *
     * @param string $id
     * @return $this
     */
    public function setId(string $id): self
    {
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
     * @param string $logo
     * @return $this
     */
    public function setLogo(string $logo): self
    {
        $this->logo = $logo;
        return $this;
    }

    /**
     * Return the hashed id
     * @return string
     */
    public function getHashId(): string
    {
        return hash('sha256', $this->id, true);
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
