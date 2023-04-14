DROP TABLE IF EXISTS usuario;
create table usuario(
id_usuario serial,
nombre varchar(100),
apellido varchar(100),
correo varchar(100) unique,
clave varchar(100),
roles json,
estado varchar(1),
constraint pk_usuario primary key (id_usuario)
);


INSERT INTO usuario(
nombre, apellido, correo, clave, roles, estado)
VALUES
(
'Josthin', 'Ayon', 'oswayon9@hotmail.com',
'$2y$13$yE9EI8TQZ04C9HWWmcpWOuLQbm8l/zAHa2SKr.EpkyQLhengUBMuS',
'["ROLE_ADMIN"]', 'A' 
);
