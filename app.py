from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
from datetime import datetime, timedelta
import jwt
import bcrypt
from functools import wraps
import os
from flask import request
from werkzeug.utils import secure_filename
import base64

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  # Ajusta los orígenes según sea necesario

# Configuración de la conexión a la base de datos
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'paso_db'
}

# Decorador para proteger las rutas con autenticación JWT
def token_required(f):
    @wraps(f)  # Usamos wraps para preservar la información de la función original
    def decorator(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]  # Obtener el token del encabezado

        if not token:
            return jsonify({'message': 'Token es necesario'}), 403

        try:
            # Decodificar el token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['user_id']  # Obtener el user_id del token
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'El token ha expirado'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token inválido'}), 403

        return f(current_user, *args, **kwargs)
    return decorator

# Ruta para registrar usuarios
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json

        # Validar campos requeridos
        required_fields = ['usuario', 'correo', 'contraseña', 'APaterno', 'AMaterno', 'fecha_nacimiento', 'sexo']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({'error': f'Campos faltantes: {", ".join(missing_fields)}'}), 400

        # Calcular edad a partir de la fecha de nacimiento
        birthdate = datetime.strptime(data['fecha_nacimiento'], '%Y-%m-%d')
        today = datetime.today()
        age = today.year - birthdate.year - ((today.month, today.day) < (birthdate.month, birthdate.day))

        if age < 18:
            return jsonify({'error': 'El usuario debe ser mayor de 18 años.'}), 400

        # Encriptar la contraseña
        hashed_password = bcrypt.hashpw(data['contraseña'].encode('utf-8'), bcrypt.gensalt())

        # Conectar a la base de datos
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Verificar si el correo ya está registrado
        query_check_email = "SELECT id FROM usuarios WHERE correo = %s"
        cursor.execute(query_check_email, (data['correo'],))
        if cursor.fetchone():
            return jsonify({'error': 'El correo ya está registrado.'}), 400

        # Insertar nuevo usuario en la base de datos
        query_insert_user = """
            INSERT INTO usuarios (usuario, correo, contraseña, apaterno, amaterno, fecha_nacimiento, edad, sexo)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query_insert_user, (
            data['usuario'],
            data['correo'],
            hashed_password.decode('utf-8'),  # Guardar la contraseña encriptada como string
            data['APaterno'],
            data['AMaterno'],
            data['fecha_nacimiento'],
            age,
            data['sexo']
        ))
        user_id = cursor.lastrowid  # Obtener el ID del usuario recién creado

        # Crear un perfil asociado al usuario
        query_insert_profile = """
            INSERT INTO profiles (user_id, username, bio, travels, orders, image_url)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query_insert_profile, (
            user_id,
            data['usuario'],
            '',  # Bio vacío por defecto
            0,   # Viajes iniciales
            0,   # Órdenes iniciales
            'https://via.placeholder.com/100'  # URL de imagen por defecto
        ))
        connection.commit()

        return jsonify({'message': 'Usuario y perfil registrados exitosamente.'}), 201
    except mysql.connector.Error as db_err:
        return jsonify({'error': f'Error en la base de datos: {str(db_err)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Error en el servidor: {str(e)}'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        correo = data['email']
        password = data['password']

        # Conectar a la base de datos
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Verificar si el correo existe
        query_check_user = "SELECT id, correo, contraseña FROM usuarios WHERE correo = %s"
        cursor.execute(query_check_user, (correo,))
        user = cursor.fetchone()

        if not user:
            return jsonify({'error': 'Correo o contraseña incorrectos.'}), 400

        # Verificar la contraseña
        if not bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
            return jsonify({'error': 'Correo o contraseña incorrectos.'}), 400

        # Asegurarse de que la clave secreta sea una cadena de texto
        if not isinstance(app.config['SECRET_KEY'], str):
            app.config['SECRET_KEY'] = '137950'  # O usa os.urandom(24)

        # Generar un token JWT para el usuario
        token = jwt.encode(
            {
                'user_id': user[0],
                'exp': datetime.utcnow() + timedelta(days=1)  # Expiración del token en 1 hora
            },
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )

        return jsonify({'message': 'Login exitoso', 'token': token}), 200

    except Exception as e:
        return jsonify({'error': f'Error en el servidor: {str(e)}'}), 500
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'connection' in locals(): connection.close()
        
# Ruta para registrar un viaje
@app.route('/registrarViaje', methods=['POST'])
@token_required
def registrar_viaje(current_user):
    data = request.json
    try:
        # Validación de los datos recibidos
        required_fields = ['departureCity', 'destination', 'arrivalDate', 'returnDate', 'coldContainers', 'hotContainers']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({'error': f'Campos faltantes: {", ".join(missing_fields)}'}), 400

        # Conectar a la base de datos
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Registrar el viaje
        query_insert_trip = """
            INSERT INTO viajes (usuario_id, departure_city, destination, arrival_date, return_date, cold_containers, hot_containers, comments)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
        """
        cursor.execute(query_insert_trip, (
            current_user,
            data['departureCity'],
            data['destination'],
            data['arrivalDate'],
            data['returnDate'],
            data['coldContainers'],
            data['hotContainers'],
            data.get('comments', '')
        ))

        return jsonify({'message': 'Viaje registrado exitosamente.'}), 201
    except mysql.connector.Error as db_err:
        return jsonify({'error': f'Error en la base de datos: {str(db_err)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Error al registrar el viaje: {str(e)}'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()
            
@app.route('/viajes/recientes', methods=['GET'])
def get_recent_trips():
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        query = """
            SELECT id, departure_city AS ciudad_salida, destination AS ciudad_destino,
                   arrival_date AS fecha_salida, return_date AS fecha_regreso
            FROM viajes
            ORDER BY arrival_date DESC
            LIMIT 10;
        """
        cursor.execute(query)
        trips = cursor.fetchall()
        return jsonify({'trips': trips}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        connection.close()

@app.route('/viajes', methods=['GET'])
def get_filtered_trips():
    try:
        destination = request.args.get('destination')  # Ciudad de destino
        arrival_date = request.args.get('arrival_date')  # Fecha de llegada

        query_conditions = []
        params = []

        if destination:
            query_conditions.append("destination = %s")
            params.append(destination)

        if arrival_date:
            query_conditions.append("arrival_date = %s")
            params.append(arrival_date)

        query_condition = " AND ".join(query_conditions)
        query = f"""
            SELECT id, departure_city AS ciudad_salida, destination AS ciudad_destino,
                   arrival_date AS fecha_salida, return_date AS fecha_regreso
            FROM viajes
            {f'WHERE {query_condition}' if query_condition else ''}
            ORDER BY arrival_date;
        """

        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, params)
        trips = cursor.fetchall()

        return jsonify({'trips': trips}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        connection.close()


@app.route('/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # Consultar el número de viajes y pedidos
        query_travels_count = "SELECT COUNT(*) AS travel_count FROM viajes WHERE usuario_id = %s"
        cursor.execute(query_travels_count, (current_user,))
        travel_count = cursor.fetchone()['travel_count']

        query_orders_count = "SELECT COUNT(*) AS order_count FROM pedidos WHERE usuario_id = %s"
        cursor.execute(query_orders_count, (current_user,))
        order_count = cursor.fetchone()['order_count']

        # Consultar el perfil y la imagen
        query_get_profile = """
            SELECT username, bio, image_url 
            FROM profiles 
            WHERE user_id = %s 
        """
        cursor.execute(query_get_profile, (current_user,))
        profile = cursor.fetchone()

        if not profile:
            return jsonify({'error': 'Perfil no encontrado.'}), 404

        # Crear el diccionario del perfil
        profile_data = {
            'user_id': current_user,
            'username': profile['username'],
            'bio': profile['bio'],
            'travelCount': travel_count,
            'orderCount': order_count,
            'image_url': profile['image_url']
        }

        # Consultar solo tarjetas activas relacionadas al usuario
        query_get_cards = """
            SELECT id, nombre_en_tarjeta, numero_enmascarado, fecha_expiracion, tipo_tarjeta 
            FROM tarjetas 
            WHERE usuario_id = %s AND estado = 'activo'
        """
        cursor.execute(query_get_cards, (current_user,))
        cards = cursor.fetchall()

        # Añadir las tarjetas al resultado del perfil
        profile_data['cards'] = cards

        return jsonify(profile_data), 200

    except mysql.connector.Error as db_err:
        return jsonify({'error': f'Error en la base de datos: {str(db_err)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Error en el servidor: {str(e)}'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


@app.route('/update-profile-image', methods=['PUT'])
@token_required
def update_profile_image(current_user):
    try:
        # Extraer el JSON del cuerpo de la solicitud
        data = request.get_json()
        new_image_url = data.get('imageUrl')

        if not new_image_url:
            return jsonify({'error': 'Falta la URL de la nueva imagen.'}), 400

        # Conectar a la base de datos
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Actualizar la URL de la imagen en el perfil del usuario
        query_update_image = """
            UPDATE profiles
            SET image_url = %s
            WHERE user_id = %s
        """
        cursor.execute(query_update_image, (new_image_url, current_user))
        connection.commit()

        return jsonify({'message': 'Imagen actualizada exitosamente.'}), 200

    except mysql.connector.Error as db_err:
        return jsonify({'error': f'Error en la base de datos: {str(db_err)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Error en el servidor: {str(e)}'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

@app.route('/viaje/detalle/<int:trip_id>', methods=['GET'])
@token_required  # Asegúrate de que solo usuarios autenticados puedan acceder a esta ruta
def get_trip_details(current_user, trip_id):
    try:
        # Conectar a la base de datos
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # Consultar los detalles del viaje y la información del conductor
        query_trip_details = """
            SELECT 
                v.id,
                v.departure_city AS ciudad_salida,
                v.destination AS ciudad_destino,
                v.arrival_date AS fecha_salida,
                v.return_date AS fecha_regreso,
                p.username AS conductor_nombre,
                p.travels AS viajes_realizados,
                p.rating AS calificacion,
                p.rating_count AS cantidad_calificaciones,
                p.image_url AS conductor_imagen,
                v.comments AS comentarios,  
                v.hot_containers AS contenedor_caliente,  
                v.cold_containers AS contenedor_frio  
            FROM viajes v
            JOIN profiles p ON v.usuario_id = p.user_id
            WHERE v.id = %s
        """
        cursor.execute(query_trip_details, (trip_id,))
        trip_details = cursor.fetchone()

        if not trip_details:
            return jsonify({'error': 'Viaje no encontrado.'}), 404

        # Crear el diccionario de los detalles del viaje
        trip_data = {
            'id': trip_details['id'],
            'ciudad_salida': trip_details['ciudad_salida'],
            'ciudad_destino': trip_details['ciudad_destino'],
            'fecha_salida': trip_details['fecha_salida'],
            'fecha_regreso': trip_details['fecha_regreso'],
            'comentarios': trip_details['comentarios'] if trip_details['comentarios'] else 'No hay comentarios disponibles.',
            'contenedor_caliente': trip_details['contenedor_caliente'] if trip_details['contenedor_caliente'] else 'No disponible',
            'contenedor_frio': trip_details['contenedor_frio'] if trip_details['contenedor_frio'] else 'No disponible',
            'conductor': {
                'nombre': trip_details['conductor_nombre'],
                'viajes_realizados': trip_details['viajes_realizados'],
                'calificacion': trip_details['calificacion'],
                'cantidad_calificaciones': trip_details['cantidad_calificaciones'],
                'imagen': trip_details['conductor_imagen']
            }
        }

        return jsonify(trip_data), 200

    except Exception as e:
        return jsonify({'error': f'Error al obtener los detalles del viaje: {str(e)}'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

@app.route('/calificarConductor', methods=['POST'])
@token_required
def rate_driver(current_user):
    if not current_user:
        return jsonify({'error': 'Usuario no autenticado.'}), 403
    data = request.json
    try:
        trip_id = data['tripId']
        rating = data['rating']  # Valor de calificación (por ejemplo, entre 1 y 5)

        # Conectar a la base de datos
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Obtener el usuario (conductor) que creó el viaje
        query_get_driver = """
            SELECT usuario_id
            FROM viajes
            WHERE id = %s
        """
        cursor.execute(query_get_driver, (trip_id,))
        driver_id = cursor.fetchone()

        if not driver_id:
            return jsonify({'error': 'Viaje no encontrado.'}), 404

        # Consultar el perfil del conductor
        query_get_profile = """
            SELECT rating, rating_count
            FROM profiles
            WHERE user_id = %s
        """
        cursor.execute(query_get_profile, (driver_id['usuario_id'],))
        profile = cursor.fetchone()

        if not profile:
            return jsonify({'error': 'Perfil de conductor no encontrado.'}), 404

        # Calcular nueva calificación promedio
        new_rating_count = profile['rating_count'] + 1
        new_rating = ((profile['rating'] * profile['rating_count']) + rating) / new_rating_count

        # Actualizar calificación y contador en la tabla profiles
        query_update_profile = """
            UPDATE profiles
            SET rating = %s, rating_count = %s
            WHERE user_id = %s
        """
        cursor.execute(query_update_profile, (new_rating, new_rating_count, driver_id['usuario_id']))
        connection.commit()

        return jsonify({'message': 'Calificación actualizada correctamente.'}), 200

    except Exception as e:
        return jsonify({'error': f'Error al calificar al conductor: {str(e)}'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()
            
@app.route('/get-tiendas', methods=['GET'])
def get_tiendas():
    try:
        # Obtener los parámetros de búsqueda de la solicitud
        search = request.args.get('search', '')
        city = request.args.get('city', '')
        rating = request.args.get('rating', '')

        # Conectar a la base de datos
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # Consulta básica para obtener tiendas
        query = "SELECT * FROM tiendas WHERE nombre LIKE %s"
        params = [f"%{search}%"]

        # Filtro por ciudad
        if city:
            query += " AND ciudad = %s"
            params.append(city)

        # Filtro por calificación promedio
        if rating:
            query += " AND promedio_calificacion >= %s"
            params.append(rating)

        # Ejecutar la consulta
        cursor.execute(query, params)
        shops = cursor.fetchall()

        # Cerrar la conexión
        cursor.close()
        connection.close()

        return jsonify(shops), 200

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    
@app.route('/store-details', methods=['GET'])
def get_store_details():
    try:
        store_id = request.args.get('store_id')
        if not store_id:
            return jsonify({'error': 'ID de tienda no proporcionado.'}), 400

        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        query = "SELECT * FROM tiendas WHERE id = %s"
        cursor.execute(query, (store_id,))
        store = cursor.fetchone()

        cursor.close()
        connection.close()

        if not store:
            return jsonify({'error': 'Tienda no encontrada.'}), 404

        return jsonify(store), 200

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500

@app.route('/products', methods=['GET'])
def get_products():
    try:
        store_id = request.args.get('store_id')
        if not store_id:
            return jsonify({'error': 'ID de tienda no proporcionado.'}), 400

        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        query = "SELECT * FROM productos WHERE tienda_id = %s"
        cursor.execute(query, (store_id,))
        products = cursor.fetchall()

        cursor.close()
        connection.close()

        return jsonify(products), 200

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    
@app.route('/cards/add', methods=['POST'])
@token_required
def add_card(current_user):
    data = request.json
    try:
        # Validar campos requeridos
        required_fields = ['cardName', 'cardNumber', 'expiryDate']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({'error': f'Campos faltantes: {", ".join(missing_fields)}'}), 400

        # Máscara el número de la tarjeta
        masked_card_number = '**** **** **** ' + data['cardNumber'][-4:]

        # Obtener tipo de tarjeta (Visa, MasterCard, etc.)
        tipo_tarjeta = get_card_type(data['cardNumber'])

        # Conectar a la base de datos
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Insertar tarjeta en la base de datos
        query_insert_card = """
            INSERT INTO tarjetas (usuario_id, nombre_en_tarjeta, numero_enmascarado, fecha_expiracion, tipo_tarjeta, estado)
            VALUES (%s, %s, %s, %s, %s);
        """
        cursor.execute(query_insert_card, (
            current_user,
            data['cardName'],
            masked_card_number,
            data['expiryDate'],
            tipo_tarjeta,
            'activo'  # Estado por defecto
        ))
        connection.commit()

        return jsonify({'message': 'Tarjeta añadida exitosamente.'}), 201

    except mysql.connector.Error as db_err:
        return jsonify({'error': f'Error en la base de datos: {str(db_err)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Error al añadir tarjeta: {str(e)}'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

# Función para determinar el tipo de tarjeta
def get_card_type(card_number):
    if card_number.startswith('4'):
        return 'Visa'
    elif card_number.startswith('5'):
        return 'MasterCard'
    # Agrega más validaciones según sea necesario
    return 'Desconocida'

@app.route('/cards', methods=['GET'])
@token_required
def list_cards(current_user):
    try:
        # Conectar a la base de datos
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # Seleccionar tarjetas del usuario
        query_select_cards = "SELECT id, nombre_en_tarjeta, numero_enmascarado, fecha_expiracion, tipo_tarjeta, estado FROM tarjetas WHERE usuario_id = %s"
        cursor.execute(query_select_cards, (current_user,))

        cards = cursor.fetchall()

        return jsonify(cards), 200

    except mysql.connector.Error as db_err:
        return jsonify({'error': f'Error en la base de datos: {str(db_err)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Error al obtener tarjetas: {str(e)}'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()
            
@app.route('/cards/delete/<int:card_id>', methods=['PUT'])
@token_required
def deactivate_card(current_user, card_id):
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # Comprobar que la tarjeta pertenece al usuario
        query_verify_card = """
            SELECT id 
            FROM tarjetas 
            WHERE id = %s AND usuario_id = %s AND estado = 'activo'
        """
        cursor.execute(query_verify_card, (card_id, current_user))
        card = cursor.fetchone()

        if not card:
            return jsonify({'error': 'Tarjeta no encontrada, ya está inactiva o no pertenece al usuario.'}), 404

        # Verificar si la tarjeta está asociada a pedidos en estado "En Proceso"
        query_check_pending_orders = """
            SELECT COUNT(*) AS pending_count
            FROM pedidos
            WHERE tarjeta_id = %s AND estado = 'En Proceso'
        """
        cursor.execute(query_check_pending_orders, (card_id,))
        result = cursor.fetchone()

        if result['pending_count'] > 0:
            return jsonify({
                'error': 'La tarjeta está asociada a un pedido en proceso y no se puede desactivar.'
            }), 400

        # Desactivar la tarjeta
        query_deactivate_card = "UPDATE tarjetas SET estado = 'inactivo' WHERE id = %s"
        cursor.execute(query_deactivate_card, (card_id,))
        connection.commit()

        return jsonify({'message': 'Tarjeta desactivada exitosamente.'}), 200

    except mysql.connector.Error as db_err:
        return jsonify({'error': f'Error en la base de datos: {str(db_err)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Error al desactivar la tarjeta: {str(e)}'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

            
@app.route('/enviarPedido', methods=['POST'])
@token_required
def enviar_pedido(current_user):
    data = request.json
    try:
        # Validación de los datos recibidos
        required_fields = ['userId', 'storeId', 'tripId', 'cardId', 'total', 'details', 'state']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({'error': f'Campos faltantes: {", ".join(missing_fields)}'}), 400

        # Conectar a la base de datos
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Insertar el pedido incluyendo los datos requeridos
        query_insert_order = """
            INSERT INTO pedidos (usuario_id, tienda_id, viaje_id, tarjeta_id, detalles, total, estado, fecha_pedido)
            VALUES (%s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP);
        """
        cursor.execute(query_insert_order, (
            data['userId'],
            data['storeId'],
            data['tripId'],
            data['cardId'],
            data['details'],
            data['total'],
            data['state']
        ))

        # Confirmar los cambios
        connection.commit()

        return jsonify({'message': 'Pedido enviado exitosamente.'}), 201
    except mysql.connector.Error as db_err:
        return jsonify({'error': f'Error en la base de datos: {str(db_err)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Error al enviar el pedido: {str(e)}'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()
            
@app.route('/pedidos/pendientes', methods=['GET'])
@token_required
def get_pending_orders(current_user):
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # Filtrar pedidos con estado 'En Proceso' y notificación activa
        query = """
            SELECT p.* 
            FROM pedidos p
            INNER JOIN viajes v ON p.viaje_id = v.id
            WHERE p.estado = 'En Proceso' 
              AND p.notification = 'activa'
              AND v.usuario_id = %s
        """
        cursor.execute(query, (current_user,))
        orders = cursor.fetchall()

        return jsonify({'orders': orders}), 200

    except mysql.connector.Error as db_err:
        return jsonify({'error': f'Error en la base de datos: {str(db_err)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Error en el servidor: {str(e)}'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


@app.route('/pedidos/aceptados', methods=['GET'])
@token_required
def get_accepted_orders(current_user):
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # Filtrar pedidos con estado 'Aceptado' y notificación activa
        query = """
            SELECT p.* 
            FROM pedidos p
            INNER JOIN viajes v ON p.viaje_id = v.id
            WHERE p.estado = 'Aceptado' 
              AND p.notification = 'activa'
              AND p.usuario_id = %s
        """
        cursor.execute(query, (current_user,))
        orders = cursor.fetchall()

        return jsonify({'orders': orders}), 200

    except mysql.connector.Error as db_err:
        return jsonify({'error': f'Error en la base de datos: {str(db_err)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Error en el servidor: {str(e)}'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


@app.route('/pedidos/rechazados', methods=['GET'])
@token_required
def get_rejected_orders(current_user):
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # Filtrar pedidos con estado 'Rechazado' y notificación activa
        query = """
            SELECT p.* 
            FROM pedidos p
            INNER JOIN viajes v ON p.viaje_id = v.id
            WHERE p.estado = 'Rechazado' 
              AND p.notification = 'activa'
              AND p.usuario_id = %s
        """
        cursor.execute(query, (current_user,))
        orders = cursor.fetchall()

        return jsonify({'orders': orders}), 200

    except mysql.connector.Error as db_err:
        return jsonify({'error': f'Error en la base de datos: {str(db_err)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Error en el servidor: {str(e)}'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()
            
@app.route('/pedidos/en-progreso', methods=['GET'])
@token_required
def get_orders_in_progress(current_user):
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # Filtrar pedidos donde entregado = False
        query = """
            SELECT p.* 
            FROM pedidos p
            INNER JOIN viajes v ON p.viaje_id = v.id
            WHERE p.entregado = 0 && p.estado = 'Aceptado'
              AND p.usuario_id = %s
        """
        cursor.execute(query, (current_user,))
        orders = cursor.fetchall()

        return jsonify({'orders': orders}), 200

    except mysql.connector.Error as db_err:
        return jsonify({'error': f'Error en la base de datos: {str(db_err)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Error en el servidor: {str(e)}'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()
            
@app.route('/viajes/en-progreso', methods=['GET'])
@token_required
def get_trips_in_progress(current_user):
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # Filtrar pedidos donde entregado = False
        query = """
            SELECT p.* 
            FROM pedidos p
            INNER JOIN viajes v ON p.viaje_id = v.id
            WHERE p.entregado = 0 && p.estado = 'Aceptado'
              AND v.usuario_id = %s
        """
        
        cursor.execute(query, (current_user,))
        orders = cursor.fetchall()

        return jsonify({'orders': orders}), 200

    except mysql.connector.Error as db_err:
        return jsonify({'error': f'Error en la base de datos: {str(db_err)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Error en el servidor: {str(e)}'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

@app.route('/notificaciones/descartar/<int:order_id>', methods=['PUT'])
@token_required
def discard_notification(current_user, order_id):
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Actualizar el campo notification a 'desactivado' para el pedido especificado
        query = """
            UPDATE pedidos 
            SET notification = 'desactivado'
            WHERE id = %s
        """
        cursor.execute(query, (order_id,))
        connection.commit()

        if cursor.rowcount == 0:
            return jsonify({'error': 'No se encontró el pedido o ya estaba desactivado'}), 404

        return jsonify({'message': 'Notificación descartada con éxito'}), 200

    except mysql.connector.Error as db_err:
        return jsonify({'error': f'Error en la base de datos: {str(db_err)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Error en el servidor: {str(e)}'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

@app.route('/pedidos/<int:order_id>/estado', methods=['PUT'])
@token_required
def update_order_state(current_user, order_id):
    data = request.json
    new_state = data.get('state')
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    query = "UPDATE pedidos SET estado = %s WHERE id = %s"
    cursor.execute(query, (new_state, order_id))
    connection.commit()

    return jsonify({'message': 'Estado actualizado correctamente'}), 200

@app.route('/pedidos/<int:order_id>/entregado', methods=['PUT'])
@token_required
def mark_order_as_delivered(current_user, order_id):
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Actualizar el campo entregado a True para el pedido especificado
        query = """
            UPDATE pedidos 
            SET entregado = 1
            WHERE id = %s
        """
        cursor.execute(query, (order_id,))
        connection.commit()
        
        # Incrementar el contador de viajes en la tabla `profiles`
        query_update_profile = """
            UPDATE profiles
            SET travels = travels + 1
            WHERE user_id = %s;
        """
        cursor.execute(query_update_profile, (current_user,))

        # Confirmar los cambios
        connection.commit()

        if cursor.rowcount == 0:
            return jsonify({'error': 'No se encontró el pedido o ya estaba marcado como entregado'}), 404

        return jsonify({'message': 'Pedido marcado como entregado con éxito'}), 200

    except mysql.connector.Error as db_err:
        return jsonify({'error': f'Error en la base de datos: {str(db_err)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Error en el servidor: {str(e)}'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

@app.route('/producto/<int:product_id>', methods=['GET'])
@token_required
def get_product_by_id(current_user, product_id):
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        query = "SELECT id, nombre FROM productos WHERE id = %s"
        cursor.execute(query, (product_id,))
        product = cursor.fetchone()

        if not product:
            return jsonify({'error': 'Producto no encontrado'}), 404

        return jsonify(product), 200

    except mysql.connector.Error as db_err:
        return jsonify({'error': f'Error en la base de datos: {str(db_err)}'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

@app.route('/usuario/<int:user_id>', methods=['GET'])
@token_required
def get_user_name_by_id(current_user, user_id):
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        query = "SELECT id, usuario FROM usuarios WHERE id = %s"
        cursor.execute(query, (user_id,))
        user = cursor.fetchone()

        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404

        return jsonify(user), 200

    except mysql.connector.Error as db_err:
        return jsonify({'error': f'Error en la base de datos: {str(db_err)}'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()
            
@app.route('/viaje/propietario/<int:trip_id>', methods=['GET'])
@token_required
def get_trip_owner(current_user, trip_id):
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        query = "SELECT usuario_id FROM viajes WHERE id = %s"
        cursor.execute(query, (trip_id,))
        trip = cursor.fetchone()

        if not trip:
            return jsonify({'error': 'Viaje no encontrado'}), 404

        return jsonify(trip), 200

    except mysql.connector.Error as db_err:
        return jsonify({'error': f'Error en la base de datos: {str(db_err)}'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()
         
## Proyecto Administracion Paso            
@app.route('/add-shop', methods=['POST'])
def add_shop():
    try:
        data = request.json
        name = data.get('name')
        address = data.get('address')
        state = data.get('state')
        city = data.get('city')
        schedule = data.get('schedule')  # El campo de horarios será solo un texto
        phone = data.get('phone')
        email = data.get('email')
        logo_url = data.get('logo_url')

        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        query = """
        INSERT INTO tiendas (nombre, direccion, estado, ciudad, horarios, telefono, email, logo_url)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (name, address, state, city, schedule, phone, email, logo_url))
        connection.commit()

        return jsonify({'message': 'Tienda registrada exitosamente'}), 201
    except mysql.connector.Error as err:
        return jsonify({'error': str(err)}), 500
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()
            
@app.route('/shops', methods=['GET'])
def get_shops():
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # Consultar todas las tiendas
        cursor.execute("SELECT * FROM tiendas")
        shops = cursor.fetchall()

        # Cerrar la conexión
        cursor.close()
        connection.close()

        return jsonify(shops), 200

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    
@app.route('/add-product', methods=['POST'])
def add_product():
    # Obtener los datos del cuerpo de la solicitud
    tienda_id = request.json.get('shop')
    nombre = request.json.get('name')
    descripcion = request.json.get('description')
    cantidad = request.json.get('quantity')
    unidad_medida = request.json.get('unit')
    precio_tienda = request.json.get('storePrice')
    precio_publico = request.json.get('publicPrice')
    imagen_url = request.json.get('image')  # Recibe la URL de la imagen
    
    # Validar que los campos requeridos están presentes
    if not all([tienda_id, nombre, cantidad, unidad_medida, precio_tienda, precio_publico, imagen_url]):
        return jsonify({"error": "Todos los campos son requeridos"}), 400
    
    # Conexión a la base de datos
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Insertar el nuevo producto en la base de datos
        insert_query = """
        INSERT INTO productos (tienda_id, nombre, descripcion, cantidad, unidad_medida, precio_tienda, precio_publico, imagen, fecha_creacion)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        # Fecha actual para la creación del producto
        fecha_creacion = datetime.now()

        # Ejecutar la consulta
        cursor.execute(insert_query, (tienda_id, nombre, descripcion, cantidad, unidad_medida, precio_tienda, precio_publico, imagen_url, fecha_creacion))
        connection.commit()
        
        # Cerrar la conexión
        cursor.close()
        connection.close()

        return jsonify({"message": "Producto agregado exitosamente"}), 201

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500

# Verificar que el servidor funcione correctamente
@app.route('/', methods=['GET'])
def health_check():
    return jsonify({'message': 'El servidor está funcionando correctamente.'})

if __name__ == '__main__':
    app.run(debug=True)
