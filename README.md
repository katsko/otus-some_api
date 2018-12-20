Some API (otus)
===============

Декларативный язык описания и система валидации запросов к HTTP API сервиса скоринга.

Запуск сервера:
---------------

Запуск по адресу 127.0.0.1:8080, вывод логов в консоль

```
python ./api.py
```

Запуск по адресу 127.0.0.1:10000, вывод логов в файл /tmp/scoring.log

```
python ./api.py --port 10000 --log /tmp/scoring.log
```

Запуск тестов:
---------------

```
python ./test.py
```

Декларативный язык
------------------

Для описания api-методов используются классы, задекорированные через @api:

```
@api
class MyMethodRequest(object):
    ...
```

Название класса должно заканчиватся словом "Request". После декорирование такого класса в json-api становится доступным метод my_method:

```
{"method": "my_method",  "arguments": ...}
```

API-поля класса являются типами классов, унаследованных от класса Field:

```
@api
class MyMethodRequest(object):
    first_name = CharField(required=False, nullable=True)
    ...
```

Дополнительную валидацию для API-класса можно задать в методе "validate":


```
@api
class MyMethodRequest(object):
    first_name = CharField(required=False, nullable=True)

    def validate(self):
        if self.first_name == 'test':
            raise ValueError('first_name: Field must not be "test")
```

API-класс должен содержать поле result, которое содержит два значения: данные ответа и http-код ответа

```
@api
class MyMethodRequest(object):
    ...
    @property
    def result(self):
        return {'name': self.first_name}, api.OK
```

Реализация API скоринга, основная структура запроса
---------------------------------------------------

### Структура запроса

```
{"account": "<имя компании партнера>", "login": "<имя пользователя>", "method": "<имя метода>", "token": "<аутентификационный токен>", "arguments": {<словарь с аргументами вызываемого метода>}}
```

* account ‐ строка, опционально, может быть пустым
* login ‐ строка, обязательно, может быть пустым
* method ‐ строка, обязательно, может быть пустым
* token ‐ строка, обязательно, может быть пустым
* arguments ‐ словарь (объект в терминах json), обязательно, может быть пустым

### Валидация

Запрос валиден, если валидны все поля по отдельности

### Структура ответа

OK:

```
{"code": <числовой код>, "response": {<ответ вызываемого метода>}}
```

Ошибка:

```
{"code": <числовой код>, "error": {<сообщение об ошибке>}}
```

### Аутентификация:

Код находится в функции check_auth, если авторизация не пройдена, то возвращается ответ:

```
{"code": 403, "error": "Forbidden"}
```

Реализация API скоринга, методы
-------------------------------

### online_score

#### Аргументы

* phone ‐ строка или число, длиной 11, начинается с 7, опционально, может быть пустым
* email ‐ строка, в которой есть @, опционально, может быть пустым
* first_name ‐ строка, опционально, может быть пустым
* last_name ‐ строка, опционально, может быть пустым
* birthday ‐ дата в формате DD.MM. YYYY, с которой прошло не больше 70 лет, опционально, может быть пустым
* gender ‐ число 0, 1 или 2, опционально, может быть пустым

#### Валидация аругементов

Аргументы валидны, если валидны все поля по отдельности и если присутсвует хоть одна пара phone‐email, first name‐last name, gender‐birthday с непустыми значениями.

#### Контекст

В словарь контекста прописываться запись "has" ‐ список полей, которые были не пустые для данного запроса

#### Ответ

В ответ выдается число, полученное вызовом функции get_score (см. scoring.py). Но если пользователь админ (см. check_auth), то всегда будет 42.

```
{"score": <число>}
```

или если запрос пришел от валидного пользователя admin

```
{"score": 42}
```

или если произошла ошибка валидации

```
{"code": 422, "error": "<сообщение о том какое поле(я) невалидно(ы)>"}
```

#### Пример

```
$ curl -X POST -H "Content-Type: application/json" -d '{"account": "horns&hoofs", "login": "h&f", "method": "online_score", "token": "55cc9ce545bcd144300fe9efc28e65d415b923ebb6be1e19d2750a2c03e80dd209a27954dca045e5bb12418e7d89b6d718a9e35af3", "arguments": {"phone": "79175002040", "email": "test@server.ru", "first_name": "Имя", "last_name": "Фамилия", "birthday": "01.01.1990", "gender": 1}}' http://127.0.0.1:8080/method/
```

```
{"code": 200, "response": {"score": 5.0}}
```

### clients_interests

#### Аргументы

* client_ids ‐ массив чисел, обязательно, не пустое
* date ‐ дата в формате DD.MM.YYYY, опционально, может быть пустым

#### Валидация аругементов

Аргументы валидны, если валидны все поля по отдельности.

#### Контекст

В словарь контекста должна прописываться запись "nclients" ‐ количество id'шников, переденанных в запрос.

#### Ответ

В ответ выдается словарь `<id клиента>:<список интересов>`. Список генерировать вызовом функции get_interests (см. scoring.py).

```
{"client_id1": ["interest1", "interest2" ...], "client2": [...] ...}
```

или если произошла ошибка валидации

```
{"code": 422, "error": "<сообщение о том какое поле(я) невалидно(ы)>"}
```

#### Пример

```
$ curl -X POST -H "Content-Type: application/json" -d '{"account": "horns&hoofs", "login": "admin", "method": "clients_interests", "token": "d3573aff1555cd67dccf21b95fe8c4dc8732f33fd4e32461b7fe6a71d83c947688515e36774c00fb630b039fe2223c991f045f13f2", "arguments": {"client_ids": [1,2,3,4], "date": "20.07.2017"}}' http://127.0.0.1:8080/method/
```

```
{"code": 200, "response": {"1": ["books", "hi-tech"], "2": ["pets", "tv"], "3": ["travel", "music"], "4": ["cinema", "geek"]}}
```
