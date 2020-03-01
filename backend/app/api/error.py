class APIException(Exception):
    def __init__(self):
        Exception.__init__(self)

    def to_dict(self):
        raise NotImplementedError('Subclasses must define to_dict')


class ClientError(APIException):
    STATUS_CODE = 400

    def __init__(self, message, status_code=None, payload=None):
        APIException.__init__(self)
        self.message = message
        self.status_code = status_code or ClientError.STATUS_CODE
        self.payload = payload or {}

    def to_dict(self):
        return {
            'message': self.message,
            **self.payload,
        }


class UnauthorizedError(ClientError):
    def __init__(self, message=None):
        message = message or 'Unauthorized'
        ClientError.__init__(self, message, status_code=401)
