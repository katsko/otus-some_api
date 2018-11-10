#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import json
import logging
import hashlib
import uuid
from datetime import datetime
from optparse import OptionParser
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from scoring import get_score, get_interests

SALT = 'Otus'
ADMIN_LOGIN = 'admin'
ADMIN_SALT = '42'
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: 'Bad Request',
    FORBIDDEN: 'Forbidden',
    NOT_FOUND: 'Not Found',
    INVALID_REQUEST: 'Invalid Request',
    INTERNAL_ERROR: 'Internal Server Error',
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: 'unknown',
    MALE: 'male',
    FEMALE: 'female',
}
MAX_AGE = 70

api_map = {}


def api(cls):
    name = cls.__name__.split('Request')[0]
    name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    name = re.sub('([a-z0-9])([A-Z])', r'\1_\2', name).lower()
    api_map[name] = cls
    return cls


class Undefined(object):
    pass


UNDEF = Undefined()


class Field(object):
    def __init__(self, required=False, nullable=False):
        self.value = UNDEF
        self.required = required
        self.nullable = nullable

    def __get__(self, obj, cls):
        return self.value

    def __set__(self, obj, value):
        self.value = value
        self._validate_first()

    def _validate_first(self):
        if self.required and self.value == UNDEF:
            raise ValueError('Field is required')
        if not self.nullable and self.value is None:
            raise ValueError('Expected not None')
        if self.value == UNDEF:
            self.value = None
        if self.value is not None:
            self._validate()

    def _validate(self):
        raise NotImplementedError('To be implemented')


class CharField(Field):

    def _validate(self):
        if not (isinstance(self.value, str) or
                isinstance(self.value, unicode)):
            raise TypeError('Expected str or unicode')


class ArgumentsField(Field):

    def _validate(self):
        if not isinstance(self.value, dict):
            raise TypeError('Expected dict (json)')


class EmailField(CharField):

    def _validate(self):
        super(EmailField, self)._validate()
        if '@' not in self.value:
            raise ValueError('Expected email')


class PhoneField(Field):

    def _validate(self):
        if not (isinstance(self.value, str) or
                isinstance(self.value, unicode) or
                isinstance(self.value, int)):
            raise TypeError('Expected str or unicode or int')
        self.value = str(self.value)
        if len(self.value) != 11:
            raise ValueError('Expected 11 symbols')
        if self.value[0] != '7':
            raise ValueError('Expected first symbol as 7')


class DateField(CharField):

    def _validate(self):
        super(DateField, self)._validate()
        # if re.match(r'^\d{2}\.\d{2}\.\d{4}$', self.value) is not None:
        #     raise ValueError('Expected date format: DD.MM.YYYY')
        self.value = datetime.strptime(self.value, '%d.%m.%Y')


class BirthDayField(DateField):

    def _validate(self):
        super(BirthDayField, self)._validate()
        current_date = datetime.now()
        before_date = current_date.replace(year=current_date.year - MAX_AGE)
        if self.value <= before_date:
            raise ValueError('Expected age less then %s' % MAX_AGE)


class GenderField(Field):

    def _validate(self):
        if self.value not in (1, 2, 3):
            raise ValueError('Expected value 1, 2 or 3')


class ClientIDsField(Field):

    def _validate(self):
        if not (isinstance(self.value, list) and
                all(isinstance(item, int) for item in self.value)):
            raise ValueError('Expected list of int')


class MethodNameField(CharField):

    def _validate(self):
        super(MethodNameField, self)._validate()
        if self.value not in api_map:
            raise ValueError('API method name not found')


class MetaBaseMethodRequest(type):

    def __new__(self, name, bases, namespace):
        cls = super(MetaBaseMethodRequest, self).__new__(
            self, name, bases, namespace)
        cls._fields = [key for key, val in namespace.items()
                       if isinstance(val, Field)]
        return cls


class BaseMethodRequest(object):
    __metaclass__ = MetaBaseMethodRequest

    def __init__(self, data, store, **kwargs):
        self.response = None
        self.error = None
        self.code = OK
        self.store = store
        for key, value in kwargs.items():
            setattr(self, key, value)
        for key in self._fields:
            try:
                setattr(self, key, data.get(key, UNDEF))
            except Exception, e:
                self._exception_result('{}: {}'.format(key, e))
        try:
            self.validate()
        except Exception, e:
            self._exception_result('{}'.format(e))

    def _exception_result(self, text):
            self.code = INVALID_REQUEST
            self.error = text
            logging.error(self.error)

    def validate(self):
        pass


@api
class ClientsInterestsRequest(BaseMethodRequest):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    @property
    def result(self):
        interests = {client_id: get_interests(self.store, client_id)
                     for client_id in self.client_ids}
        return self.error or interests, self.code, {
            'nclients': len(self.client_ids)}


@api
class OnlineScoreRequest(BaseMethodRequest):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def validate(self):
        if not ((self.first_name and self.last_name) or
                (self.email and self.phone) or
                (self.birthday and self.gender)):
            raise ValueError('arguments: Required fistname-lastname or '
                             'email-phone or birthday-gender')

    @property
    def result(self):
        if self.is_admin:
            score = 42
        else:
            score = get_score(
                self.store, self.phone, self.email, self.birthday, self.gender,
                self.first_name, self.last_name)
        has_fields = [field for field in self._fields
                      if getattr(self, field) is not None]
        return self.error or {'score': score}, self.code, {'has': has_fields}


class MethodRequest(BaseMethodRequest):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = MethodNameField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN

    @property
    def result(self):
        if not check_auth(self):
            self.code = FORBIDDEN
            logging.error(self.error)
            return self.error or self.response, self.code, {}
        if self.code is not OK:
            return self.error, self.code, {}
        return api_map[self.method](
            self.arguments, self.store, is_admin=self.is_admin).result


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(datetime.now().strftime(
            '%Y%m%d%H') + ADMIN_SALT).hexdigest()
    else:
        digest = hashlib.sha512(
            request.account + request.login + SALT).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    # response, code = None,  None
    # return response, code
    return MethodRequest(request.get('body'), store).result


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        'method': method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {'request_id': self.get_request_id(self.headers)}
        context_ext = {}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except Exception:
            code = BAD_REQUEST

        if request:
            path = self.path.strip('/')
            logging.info('%s: %s %s' % (
                self.path, data_string, context['request_id']))
            if path in self.router:
                try:
                    response, code, context_ext = self.router[path](
                        {'body': request, 'headers': self.headers},
                        context,
                        self.store)
                except Exception, e:
                    logging.exception('Unexpected error: %s' % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        if code not in ERRORS:
            r = {'response': response, 'code': code}
        else:
            r = {'error': response or ERRORS.get(code, 'Unknown Error'),
                 'code': code}
        context.update(r)
        context.update(context_ext)
        logging.info(context)
        self.wfile.write(json.dumps(r))
        return


if __name__ == '__main__':
    op = OptionParser()
    op.add_option('-p', '--port', action='store', type=int, default=8080)
    op.add_option('-l', '--log', action='store', default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s',
                        datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(('localhost', opts.port), MainHTTPHandler)
    logging.info('Starting server at %s' % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
