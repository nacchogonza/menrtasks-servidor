const Usuario = require('../models/Usuario');
const bcryptjs = require('bcryptjs');
const { validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');

exports.crearUsuario = async (req, res) => {

    //Revisar si hay errores
    const errores = validationResult(req);
    if ( !errores.isEmpty() ) {
        res.status(400).json({ errores: errores.array() })
    }

    // extraer email y password
    const { email, password } = req.body;
    
    try {
        // Revisar que el usuario registrado sea unico
        let usuario = await Usuario.findOne({ email })

        if (usuario) {
            return res.status(400).json({ msg: 'El usuario ya existe' });
        }

        // crea el nuevo usuario
        usuario = new Usuario(req.body);

        // Hashear password
        const salt = await bcryptjs.genSalt(10);
        usuario.password= await bcryptjs.hash(password, salt);

        // guardar usuario
        await usuario.save();

        // Crear el JWT
        const payload = {
            usuario: {
                id: usuario.id
            }
        }

        // Firmar el JWT
        jwt.sign(payload, process.env.SECRETA, {
            expiresIn: 3600 // una hora de duracion del token
        }, (error, token) => {
            if (error) throw error;

            // Mensaje de confirmación
            res.json({ token });

        });

        
    } catch (error) {
        console.log(error);
        res.status(400).send('Hubo un error al crear el usuario');
    }
}