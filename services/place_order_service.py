import importlib
import logging
import traceback
import copy
from typing import Tuple, Dict, Any, Optional

from database.auth_db import get_auth_token_broker
from database.apilog_db import async_log_order, executor
from database.settings_db import get_analyze_mode
from database.analyzer_db import async_log_analyzer
from extensions import socketio
from utils.api_analyzer import analyze_request, generate_order_id
from utils.constants import (
    VALID_EXCHANGES,
    VALID_ACTIONS,
    VALID_PRICE_TYPES,
    VALID_PRODUCT_TYPES,
    REQUIRED_ORDER_FIELDS
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Will hold the lazily instantiated schema
order_schema = None

def get_order_schema():
    """Lazily import and instantiate the OrderSchema to avoid circular imports."""
    global order_schema
    if order_schema is None:
        from restx_api.schemas import OrderSchema
        order_schema = OrderSchema()
    return order_schema

def import_broker_module(broker_name: str) -> Optional[Any]:
    """
    Dynamically import the broker-specific order API module.

    Args:
        broker_name: Name of the broker.

    Returns:
        The imported module, or None if import fails.
    """
    try:
        module_path = f'broker.{broker_name}.api.order_api'
        return importlib.import_module(module_path)
    except ImportError as error:
        logger.error(f"Error importing broker module '{module_path}': {error}")
        return None

def emit_analyzer_error(request_data: Dict[str, Any], error_message: str) -> Dict[str, Any]:
    """
    Log and emit an analyzer error event.

    Args:
        request_data: Original request payload.
        error_message: Error message to emit.

    Returns:
        A standardized error-response dict for analysis mode.
    """
    error_response = {
        'mode': 'analyze',
        'status': 'error',
        'message': error_message
    }

    # Copy request, remove sensitive fields, and add metadata
    analyzer_request = request_data.copy()
    analyzer_request.pop('apikey', None)
    analyzer_request['api_type'] = 'placeorder'

    # Log to analyzer database
    executor.submit(async_log_analyzer, analyzer_request, error_response, 'placeorder')

    # Emit socket event for real-time update
    socketio.emit('analyzer_update', {
        'request': analyzer_request,
        'response': error_response
    })

    return error_response

def validate_order_data(
    data: Dict[str, Any],
    require_apikey: bool = True,
    require_strategy: bool = True
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """
    Validate order data against required fields and allowed values.

    Args:
        data: The raw order payload to validate.
        require_apikey: Whether 'apikey' must be present.
        require_strategy: Whether 'strategy' must be present.

    Returns:
        - True, loaded_data, None   if validation succeeds.
        - False, None, error_msg    if validation fails.
    """
    # Determine which fields are mandatory in this context
    required_fields = [
        field
        for field in REQUIRED_ORDER_FIELDS
        if (field != 'apikey' or require_apikey) and (field != 'strategy' or require_strategy)
    ]

    # Check for missing fields
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return False, None, f"Missing mandatory field(s): {', '.join(missing_fields)}"

    # Validate exchange value
    if 'exchange' in data and data['exchange'] not in VALID_EXCHANGES:
        return False, None, f"Invalid exchange. Must be one of: {', '.join(VALID_EXCHANGES)}"

    # Normalize and validate action
    if 'action' in data:
        data['action'] = data['action'].upper()
        if data['action'] not in VALID_ACTIONS:
            return False, None, f"Invalid action. Must be one of: {', '.join(VALID_ACTIONS)}"

    # Validate price_type if provided
    if 'price_type' in data and data['price_type'] not in VALID_PRICE_TYPES:
        return False, None, f"Invalid price type. Must be one of: {', '.join(VALID_PRICE_TYPES)}"

    # Validate product_type if provided
    if 'product_type' in data and data['product_type'] not in VALID_PRODUCT_TYPES:
        return False, None, f"Invalid product type. Must be one of: {', '.join(VALID_PRODUCT_TYPES)}"

    # Attempt to deserialize via schema
    try:
        schema = get_order_schema()
        loaded_data = schema.load(data)
        return True, loaded_data, None
    except Exception as err:
        return False, None, str(err)

def place_order_with_auth(
    order_data: Dict[str, Any],
    auth_token: str,
    broker: str,
    original_data: Dict[str, Any]
) -> Tuple[bool, Dict[str, Any], int]:
    """
    Execute an order placement using the broker's API and handle analyze mode.

    Args:
        order_data: The validated order data.
        auth_token: Broker-specific auth token.
        broker: Broker name.
        original_data: Original request payload for logging.

    Returns:
        - success (bool)
        - response payload (dict)
        - HTTP status code (int)
    """
    # Make a deep copy of original data for logging and stripping sensitive fields
    order_request_data = copy.deepcopy(original_data)
    order_request_data.pop('apikey', None)

    # If analyze-mode is on, run analysis and return a dummy response
    if get_analyze_mode():
        _, analysis = analyze_request(order_data, 'placeorder', True)

        analyzer_request = order_request_data.copy()
        analyzer_request['api_type'] = 'placeorder'

        if analysis.get('status') == 'success':
            response_data = {
                'mode': 'analyze',
                'orderid': generate_order_id(),
                'status': 'success'
            }
        else:
            response_data = {
                'mode': 'analyze',
                'status': 'error',
                'message': analysis.get('message', 'Analysis failed')
            }

        executor.submit(async_log_analyzer, analyzer_request, response_data, 'placeorder')
        socketio.emit('analyzer_update', {
            'request': analyzer_request,
            'response': response_data
        })

        return True, response_data, 200

    # Regular mode: import broker module
    broker_module = import_broker_module(broker)
    if broker_module is None:
        error_response = {'status': 'error', 'message': 'Broker-specific module not found'}
        executor.submit(async_log_order, 'placeorder', original_data, error_response)
        return False, error_response, 404

    try:
        # Call the broker's place_order_api function
        res, response_data, order_id = broker_module.place_order_api(order_data, auth_token)
    except Exception as e:
        logger.error(f"Error in broker_module.place_order_api: {e}")
        traceback.print_exc()
        error_response = {'status': 'error', 'message': 'Internal error placing order'}
        executor.submit(async_log_order, 'placeorder', original_data, error_response)
        return False, error_response, 500

    # If broker returns status 200, emit socket event and log success
    if res.status == 200:
        socketio.emit('order_event', {
            'symbol': order_data['symbol'],
            'action': order_data['action'],
            'orderid': order_id,
            'exchange': order_data.get('exchange', 'Unknown'),
            'price_type': order_data.get('price_type', 'Unknown'),
            'product_type': order_data.get('product_type', 'Unknown'),
            'mode': 'live'
        })
        success_payload = {'status': 'success', 'orderid': order_id}
        executor.submit(async_log_order, 'placeorder', order_request_data, success_payload)
        return True, success_payload, 200

    # If broker returns an error status
    error_message = (
        response_data.get('message', 'Failed to place order')
        if isinstance(response_data, dict)
        else 'Failed to place order'
    )
    error_response = {'status': 'error', 'message': error_message}
    executor.submit(async_log_order, 'placeorder', original_data, error_response)
    return False, error_response, res.status if res.status != 200 else 500

def place_order(
    order_data: Dict[str, Any],
    api_key: Optional[str] = None,
    auth_token: Optional[str] = None,
    broker: Optional[str] = None
) -> Tuple[bool, Dict[str, Any], int]:
    """
    Main entry point to place an order. Supports API-based and internal calls.

    Args:
        order_data: Raw order payload.
        api_key: OpenAlgo API key for external API calls.
        auth_token: Broker-specific auth token for internal calls.
        broker: Broker name for internal calls.

    Returns:
        - success (bool)
        - response payload (dict)
        - HTTP status code (int)
    """
    # Copy original for logging
    original_data = copy.deepcopy(order_data)

    # If API key provided, embed into both original_data and order_data
    if api_key:
        original_data['apikey'] = api_key
        order_data['apikey'] = api_key

    # Decide which fields are mandatory in validation
    require_api_key = not (auth_token and broker) or api_key is not None
    require_strategy = require_api_key

    is_valid, validated_data, error_msg = validate_order_data(
        order_data,
        require_apikey=require_api_key,
        require_strategy=require_strategy
    )

    if not is_valid:
        if get_analyze_mode():
            return False, emit_analyzer_error(original_data, error_msg), 400
        error_response = {'status': 'error', 'message': error_msg}
        executor.submit(async_log_order, 'placeorder', original_data, error_response)
        return False, error_response, 400

    # Case 1: External API call path
    if api_key and not (auth_token and broker):
        AUTH_TOKEN, broker_name = get_auth_token_broker(api_key)
        if AUTH_TOKEN is None:
            error_response = {'status': 'error', 'message': 'Invalid OpenAlgo API key'}
            if not get_analyze_mode():
                executor.submit(async_log_order, 'placeorder', original_data, error_response)
            return False, error_response, 403

        return place_order_with_auth(validated_data, AUTH_TOKEN, broker_name, original_data)

    # Case 2: Internal call with provided auth_token and broker
    if auth_token and broker:
        return place_order_with_auth(validated_data, auth_token, broker, original_data)

    # Case 3: Neither path is valid
    error_response = {
        'status': 'error',
        'message': 'Either api_key or both auth_token and broker must be provided'
    }
    return False, error_response, 400
