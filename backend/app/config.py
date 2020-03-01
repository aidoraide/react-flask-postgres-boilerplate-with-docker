import os

class DevConfig(object):
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'postgresql+psycopg2://dev:mypassword@db/application'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_PRIVATE_KEY = """
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
""".lstrip()
    JWT_PUBLIC_KEY = """
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0l5r3gFotNNKg7N7tikj
8umiMnznIEE/QbreCIvU2o4jHlckjLRqfiBEf+I/795Ve2Uewcd7qq14FtZZ6Pdb
W+3kGZUn5Ox8LChS/RWdeLSkVQCNNJEO+oMTFqhKujJV7DWmPknDkFzBmYuCtYFm
1yaSimH1G4kF+Z0i7RATngwGRCxCRstSd2jAACVlpkztCUTVo8uWSHC0odPBIPC3
2pgRu7zSR0UWKXW4Rqbbh427j6X83sjQept5tI6tdWgQdThVaGTdpelTpyc9Efeo
IM+E8bH6kjKwmjzZcOF6iZ81CiZoJRhFINlP4Lpaxtd/8jSfbdJLdIL38qRDCEBN
K3Htwt+i6rm1WD+WkLjMDH4l88M2lhx0aOLMPYeVF8euD/1KoHFcPbUtUOQq87in
Aw20GWO2GQp0Kz6jDmbYQHW0V2xc6kvvzI5TMW7kgQhNwb71/HEEgdv+JqFz2XDw
FbkbBrCn5Ko5VrmIksZtEBE7ZgmbMUMdfrLwzxcHdm/Tuw/Y7ljmCf6qLZtskH/v
EHd1PdSj2WIECrXTAjNO0qO+vSXKyWsY9TurEENQDA9F7yLf5Mm+jhnTiOcgBXBY
jh41UXJZ2vO39Dp/D1lwmyjfSg/L/VqD/T5fwVaay9mvm3Mxjr90DNdRvu28oDpP
J6Rh1yVHtKocQBpQxS9HVGMCAwEAAQ==
-----END PUBLIC KEY-----
""".lstrip()

if os.environ.get('FLASK_ENV') == 'production':
    # TODO make a prod config
    raise Exception('No config for production yet')
else:
    Config = DevConfig
