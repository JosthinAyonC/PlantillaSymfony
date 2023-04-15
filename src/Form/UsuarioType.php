<?php

namespace App\Form;

use App\Entity\Usuario;

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\NotBlank;

class UsuarioType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('correo', EmailType::class,[
                'label'=>'Email',
                'attr' =>[
                    'class'=>'form-control',
                    'id' => 'floatingInput',
                    'placeholder' => 'Correo'
                ]
            ])
            ->add('nombre', TextType::class,[
                'label'=>'Nombre',
                'attr' =>[
                    'class'=>'form-control',
                    'id' => 'floatingInput',
                    'placeholder' => 'Nombre'
                ]
            ])
            ->add('apellido', TextType::class,[
                'label'=>'Apellido',
                'attr' =>[
                    'class'=>'form-control',
                    'id' => 'floatingInput',
                    'placeholder' => 'Apellido'
                ]
            ])
            ->add('plainPassword', PasswordType::class, [
                // instead of being set onto the object directly,
                // this is read and encoded in the controller
                'mapped' => false,
                'attr' => [
                    'autocomplete' => 'new-password',
                    'name' => 'passord',
                    'class'=>'form-control',
                    'id' => 'floatingPassord',
                    'placeholder' => 'Pasword'
                    ],
                'constraints' => [
                    new NotBlank([
                        'message' => 'Please enter a password',
                    ]),
                    new Length([
                        'min' => 6,
                        'minMessage' => 'Your password should be at least {{ limit }} characters',
                        // max length allowed by Symfony for security reasons
                        'max' => 4096,
                    ]),
                ],
            ])
            ->add('roles', ChoiceType::class, [
                'mapped' => false,
                'choices' => [
                    'ROLE_ADMIN' => 'ROLE_ADMIN',
                    'ROLE_ORGANIZADOR' => 'ROLE_ORGANIZADOR',                    
                ], 'attr' => ['class' => 'form-select'],
                'constraints' => [
                    new NotBlank(['message' => 'Seleccione al menos un rol.']),
                ]])

        ;
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'data_class' => Usuario::class,
        ]);
    }
}
