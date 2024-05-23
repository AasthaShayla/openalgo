#Mapping OpenAlgo API Request https://openalgo.in/docs
#Mapping Angel Broking Parameters https://smartapi.angelbroking.com/docs/Orders

from database.token_db import get_br_symbol

def transform_data(data,token):
    """
    Transforms the new API request structure to the current expected structure.
    """
    symbol = get_br_symbol(data["symbol"],data["exchange"])
    # Basic mapping
    transformed = {
        "OrderType": map_action(data["action"].upper()),
        "Exchange": map_exchange(data["exchange"]),
        "ExchangeType": map_exchange_type(data["exchange"]),
        "ScriCode": token,
        "ScriData": symbol,
        "Price": data.get("price", "0"), 
        "Qty": data["quantity"],
        "StopLossPrice": data.get("trigger_price", "0"), 
        "DisQty": data.get("disclosed_quantity", "0"),
        "IsIntraday": True if data.get("product") == "MIS" else False,
        "AHPlaced": "N",  # AMO Order by default NO
        "RemoteOrderID": "OpenAlgo",  
        "AppSource": "7044"
    }


    
    return transformed


def transform_modify_order_data(data, token):
    return {
        "variety": map_variety(data["pricetype"]),
        "orderid": data["orderid"],
        "ordertype": map_order_type(data["pricetype"]),
        "producttype": map_product_type(data["product"]),
        "duration": "DAY",
        "price": data["price"],
        "quantity": data["quantity"],
        "tradingsymbol": data["symbol"],
        "symboltoken": token,
        "exchange": data["exchange"],
        "disclosedquantity": data.get("disclosed_quantity", "0"),
        "stoploss": data.get("trigger_price", "0")
    }

def map_action(action):
    """
    Maps the new action to the existing order type.
    """
    action_mapping = {
        "BUY": "B",
        "SELL": "S"
    }
    return action_mapping.get(action)

def map_exchange(exchange):
    """
    Maps the new exchange to the existing exchange
    """
    exchange_mapping = {
        "NSE": "N",
        "BSE": "B",
        "NFO": "N",
        "BFO": "B",
        "CDS": "N",
        "BCD": "B",
        "MCX": "M"
    }
    return exchange_mapping.get(exchange) 


def map_exchange_type(exchange):
    """
    Maps the new exchange to the existing exchange type
    """
    exchange_mapping_type = {
        "NSE": "C",
        "BSE": "C",
        "NFO": "D",
        "BFO": "D",
        "CDS": "U",
        "BCD": "U",
        "MCX": "D"
    }
    return exchange_mapping_type.get(exchange) 

def map_order_type(pricetype):
    """
    Maps the new pricetype to the existing order type.
    """
    order_type_mapping = {
        "MARKET": "MARKET",
        "LIMIT": "LIMIT",
        "SL": "STOPLOSS_LIMIT",
        "SL-M": "STOPLOSS_MARKET"
    }
    return order_type_mapping.get(pricetype, "MARKET")  # Default to MARKET if not found

def map_product_type(product):
    """
    Maps the new product type to the existing product type.
    """
    product_type_mapping = {
        "CNC": "DELIVERY",
        "NRML": "CARRYFORWARD",
        "MIS": "INTRADAY",
    }
    return product_type_mapping.get(product, "INTRADAY")  # Default to DELIVERY if not found


def map_variety(pricetype):
    """
    Maps the pricetype to the existing order variety.
    """
    variety_mapping = {
        "MARKET": "NORMAL",
        "LIMIT": "NORMAL",
        "SL": "STOPLOSS",
        "SL-M": "STOPLOSS"
    }
    return variety_mapping.get(pricetype, "NORMAL")  # Default to DELIVERY if not found


def reverse_map_product_type(product):
    """
    Maps the new product type to the existing product type.
    """
    reverse_product_type_mapping = {
        "DELIVERY": "CNC",
        "CARRYFORWARD": "NRML",
        "INTRADAY": "MIS",
    }
    return reverse_product_type_mapping.get(product)  

