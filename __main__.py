from flask import Flask, render_template, request, abort
from flask.logging import create_logger
import bjoern
from exchangelib import Credentials, Account, Configuration
from exchangelib.errors import UnauthorizedError, TransportError
import requests.adapters
from exchangelib.protocol import BaseProtocol
from .awsfirewall import SecurityRules
import logging

fh = logging.FileHandler('./flask-auto-rule.log')
fh.setLevel(level=logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)

app = Flask(__name__)
logger = create_logger(app)
logger.addHandler(fh)
logger.setLevel(level=logging.INFO)
user_ip = ''
security_rule = SecurityRules()

# Faster authentication for outlook users
class ProxyAdapter(requests.adapters.HTTPAdapter):
    def send(self, *args, **kwargs):
        kwargs['proxies'] = {
            'http': 'http://172.16.23.2:3128',
            'https': 'http://172.16.23.2:3128',
        }
        return super().send(*args, **kwargs)
BaseProtocol.HTTP_ADAPTER_CLS = ProxyAdapter

@app.route('/user-ipaddress', methods=['PUT'])
def get_ip_address():
    global user_ip
    if not request.json or not 'ipAddress' in request.json:
        abort(400)
    user_ip = request.json['ipAddress']
    logger.info(user_ip)
    return 'Success', 200

@app.route('/authenticate', methods = ['POST'])
def authenticate_by_email():
    global user_ip
    if not request.json or not 'email' in request.json:
        abort(400)
    data = request.json
    email = data['email']
    password = data['password']
    username = data['username']
    try:
        credentials = Credentials(email, password)
        config = Configuration(server='email.msb.com.vn', credentials=credentials)
        account = Account(email, config=config, autodiscover=False)
        logger.info(str(security_rule.query_rules('(?i)Allow SEVPN for %s'% username)))
        logger.info(user_ip)
        security_rule.update_rule_by_description(
            description = '(?i)Allow SEVPN for %s'% username, 
            ipRanges = '%s/32'%user_ip
        )
        return 'Rule updated', 200
    except UnauthorizedError:
        return 'Unauthorized', 403
    except TransportError:
        return 'Server Not Found', 404
    except Exception as e:
        logger.info(type(e))
        logger.info(e)
        return 'Unknown Errors', 500

@app.route('/')
def index():
    return render_template('index.html')
    
if __name__ == '__main__':
    #app.run(host='0.0.0.0', port='5000', debug=True)
    bjoern.run(app, host='127.0.0.1', port = 5000)