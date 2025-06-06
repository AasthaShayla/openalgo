from flask import Blueprint, render_template, request, session, jsonify
from utils.session import check_session_validity
from database.auth_db import get_auth_token
import logging


logger = logging.getLogger(__name__)

manual_bp = Blueprint('manual_bp', __name__, url_prefix='/manualorder')

@manual_bp.route('/')
@check_session_validity
def manual_order():

    return render_template('manual_order.html')

@manual_bp.route('/place', methods=['POST'])
@check_session_validity
def place_manual_order():

    try:
        from services.place_order_service import place_order

        data = request.json
        login_username = session['user']
        auth_token = get_auth_token(login_username)
        broker_name = session.get('broker')

        if not auth_token or not broker_name:
            return jsonify({'status': 'error', 'message': 'Authentication error'}), 401

        success, response_data, status_code = place_order(
            order_data=data,
            auth_token=auth_token,
            broker=broker_name
        )
        return jsonify(response_data), status_code
    except Exception as e:
        logger.error(f"Error placing manual order: {str(e)}")
        return jsonify({'status': 'error', 'message': 'An error occurred'}), 500
