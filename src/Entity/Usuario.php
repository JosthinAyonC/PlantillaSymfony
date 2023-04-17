<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Usuario
 *
 * @ORM\Table(name="usuario", uniqueConstraints={@ORM\UniqueConstraint(name="usuario_correo_key", columns={"correo"})})
 * @ORM\Entity
 * @ORM\Entity(repositoryClass="App\Repository\UsuarioRepository")
 */
class Usuario  implements UserInterface, PasswordAuthenticatedUserInterface
{
    /**
     * @var int
     *
     * @ORM\Column(name="id_usuario", type="integer", nullable=false)
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="SEQUENCE")
     * @ORM\SequenceGenerator(sequenceName="usuario_id_usuario_seq", allocationSize=1, initialValue=1)
     */
    private $idUsuario;

    /**
     * @var string|null
     *
     * @ORM\Column(name="nombre", type="string", length=100, nullable=true)
     */
    private $nombre;

    /**
     * @var string|null
     *
     * @ORM\Column(name="apellido", type="string", length=100, nullable=true)
     */
    private $apellido;

    /**
     * @var string|null
     *
     * @ORM\Column(name="correo", type="string", length=100, nullable=true)
     */
    private $correo;

    /**
     * @var string|null
     *
     * @ORM\Column(name="clave", type="string", length=100, nullable=true)
     */
    private $clave;

    /**
     * @var array|null
     *
     * @ORM\Column(name="roles", type="json", nullable=true)
     */
    private $roles;

    /**
     * @var string|null
     *
     * @ORM\Column(name="estado", type="string", length=1, nullable=true)
     */
    private $estado;

    public function getIdUsuario(): ?int
    {
        return $this->idUsuario;
    }

    public function getNombre(): ?string
    {
        return $this->nombre;
    }

    public function setNombre(?string $nombre): self
    {
        $this->nombre = $nombre;

        return $this;
    }

    public function getApellido(): ?string
    {
        return $this->apellido;
    }

    public function setApellido(?string $apellido): self
    {
        $this->apellido = $apellido;

        return $this;
    }

    public function getCorreo(): ?string
    {
        return $this->correo;
    }

    public function setCorreo(?string $correo): self
    {
        $this->correo = $correo;

        return $this;
    }

    public function getClave(): ?string
    {
        return $this->clave;
    }

    public function setClave(?string $clave): self
    {
        $this->clave = $clave;

        return $this;
    }

    public function setRoles(?array $roles): self
    {
        $this->roles = $roles;

        return $this;
    }

    public function getEstado(): ?string
    {
        return $this->estado;
    }

    public function setEstado(?string $estado): self
    {
        $this->estado = $estado;

        return $this;
    }

    /** 
     * @see PasswordAuthenticatedUserInterface 
     */
    public function getPassword(): string
    {
        return $this->clave;
    }

    /** 
     * Returning a salt is only needed, if you are not using a modern 
     * hashing algorithm (e.g. bcrypt or sodium) in your security.yaml. 
     * 
     * @see UserInterface 
     */
    public function getSalt(): ?string
    {
        return null;
    }

    /** 
     * @see UserInterface 
     */
    public function eraseCredentials()
    {
        // If you store any temporary, sensitive data on the user, clear it  here 
        // $this->plainPassword = null; 
    }

    /** 
     * A visual identifier that represents this user. 
     * 
     * @see UserInterface 
     */
    public function getUserIdentifier(): string
    {
        return (string) $this->correo;
    }

    /** 
     * @see UserInterface 
     */
    public function getRoles(): array
    {
        $roles = $this->roles;
        if (empty($roles)) {
            $roles = ['ROLE_UNDEFINED'];
        } else {
            foreach ($this->roles as $role) {
                $roles[] = $role;
            }
        }
        return array_unique($roles);
    }
}
