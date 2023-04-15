<?php

namespace App\Controller;

use App\Entity\Usuario;
use App\Form\UsuarioType;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;

#[Route('/usuario')]
class UsuarioController extends AbstractController
{
    #[Route('/', name: 'app_usuario_index', methods: ['GET'])]
    public function index(EntityManagerInterface $entityManager): Response
    {
        if ($this->isGranted('ROLE_ADMIN')) {
            $usuarios = $entityManager
                ->getRepository(Usuario::class)
                ->findBy(['estado' => 'A']);

            return $this->render('usuario/index.html.twig', [
                'usuarios' => $usuarios,
            ]);
        } else {
            return $this->render('usuario/accesDenied.html.twig');
        }
    }

    #[Route('/new', name: 'app_usuario_new', methods: ['GET', 'POST'])]
    public function new(Request $request, EntityManagerInterface $entityManager, UserPasswordHasherInterface $userPasswordHasher): Response
    {

        $usuario = new Usuario();
        $form = $this->createForm(UsuarioType::class, $usuario);
        $form->handleRequest($request);

        if ($this->isGranted('ROLE_ADMIN')) {
            if ($form->isSubmitted() && $form->isValid()) {
                $usuario->setClave(
                    $userPasswordHasher->hashPassword(
                        $usuario,
                        $form->get('clave')->getData()
                    )
                );
                $roles = $form->get('roles')->getData();
                $usuario->setRoles([$roles]);
                $usuario->setEstado("A");

                $entityManager->persist($usuario);
                $entityManager->flush();

                return $this->redirectToRoute('app_usuario_index', [], Response::HTTP_SEE_OTHER);
            }
            return $this->renderForm('usuario/new.html.twig', [
                'usuario' => $usuario,
                'form' => $form,
            ]);
        } else {
            return $this->render('usuario/accesDenied.html.twig');
        }
    }

    #[Route('/{idUsuario}', name: 'app_usuario_show', methods: ['GET'])]
    public function show(Usuario $usuario): Response
    {
        if (!$usuario->getEstado() === 'A') {
            return $this->render('usuario/404.html.twig');
        } else {
            return $this->render('usuario/show.html.twig', [
                'usuario' => $usuario,
            ]);
        }
    }

    #[Route('/{idUsuario}/edit', name: 'app_usuario_edit', methods: ['GET', 'POST'])]
    public function edit(Request $request, Usuario $usuario, EntityManagerInterface $entityManager): Response
    {
        if ($this->isGranted('ROLE_ADMIN')) {

            $form = $this->createForm(UsuarioType::class, $usuario);
            $form->handleRequest($request);

            if ($form->isSubmitted() && $form->isValid()) {
                $roles = $form->get('roles')->getData();
                $usuario->setRoles([$roles]);
                $entityManager->flush();

                return $this->redirectToRoute('app_usuario_index', [], Response::HTTP_SEE_OTHER);
            }

            return $this->renderForm('usuario/edit.html.twig', [
                'usuario' => $usuario,
                'form' => $form,
            ]);
        } else {
            return $this->render('usuario/accesDenied.html.twig');
        }
    }

    #[Route('/{idUsuario}', name: 'app_usuario_delete', methods: ['POST'])]
    public function delete(Request $request, Usuario $usuario, EntityManagerInterface $entityManager): Response
    {
        if ($this->isGranted('ROLE_ADMIN')) {
            if ($this->isCsrfTokenValid('delete' . $usuario->getIdUsuario(), $request->request->get('_token'))) {
                $usuario->setEstado("I");
                $entityManager->flush();
            }

            return $this->redirectToRoute('app_usuario_index', [], Response::HTTP_SEE_OTHER);
        } else {
            return $this->render('usuario/accesDenied.html.twig');
        }
    }
}
