<?php

declare(strict_types=1);

namespace Platine\Webauthn\Entity;

use JsonSerializable;

/**
 * @class PublicKeyCredentialParam
 * @package Platine\Webauthn\Entity
 */
class PublicKeyCredentialParam implements JsonSerializable
{
    /**
     * The type
     * @var string
     */
    protected string $type = 'public-key';

    /**
     * The algorithm
     * @var int
     */
    protected int $alg;

    /**
     * Create new instance
     * @param int $alg
     */
    public function __construct(int $alg)
    {
        $this->alg = $alg;
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
     * @return int
     */
    public function getAlg(): int
    {
        return $this->alg;
    }

    /**
     *
     * @param int $alg
     * @return $this
     */
    public function setAlg(int $alg): self
    {
        $this->alg = $alg;
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
