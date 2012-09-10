#!/usr/bin/env python

#  This software code is made available "AS IS" without warranties of any
#  kind.  You may copy, display, modify and redistribute the software
#  code either by itself or as incorporated into your code; provided that
#  you do not remove any proprietary notices.  Your use of this software
#  code is at your own risk and you waive any claim against Amazon
#  Digital Services, Inc. or its affiliates with respect to your use of
#  this software code. (c) 2006-2007 Amazon Digital Services, Inc. or its
#  affiliates.

import base64
import hmac
import httplib
import re
import hashlib
import sys
import time
import urllib
import urlparse
import xml.sax

DEFAULT_HOST = 'sqs.us-west-2.amazonaws.com'
PORTS_BY_SECURITY = { True: 443, False: 80 }
ISO8601_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

class AWSAuthConnection:

    VERSION = '2011-10-01'
    DEFAULT_EXPIRES_IN = 60

    def __init__(self, aws_access_key_id, aws_secret_access_key, is_secure=False,
            server=DEFAULT_HOST, port=None):

        if not port:
            port = PORTS_BY_SECURITY[is_secure]

        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.is_secure = is_secure
        self.server = server
        self.port = port
        self.accountids = {}

    def connect(self, queue):
        assert isinstance(queue, basestring)
        if queue not in self.accountids:
            response = self.get_queue_url(queue)
            url = response.url
            self.accountids[queue] = urlparse.urlparse(url).path.split('/')[1]
        return self

    def get_queue_url(self, queue):
        query_args = {
                        'Action'    : 'GetQueueUrl',
                        'QueueName' : queue,
                     }
        return GetQueueUrlResponse(self._make_request('GET', '', '', query_args))

    def send_message(self, queue, data, delay_seconds=0):
        assert isinstance(queue, basestring) and isinstance(data, str) and isinstance(delay_seconds, int)
        assert queue in self.accountids, 'must call connect(queue) first!'
        accountid = self.accountids[queue]
        query_args = {
                        'Action'       : 'SendMessage',
                        'MessageBody'  : urllib.quote_plus(data),
                     }
        if delay_seconds:
            query_args['DelaySeconds'] = str(delay_seconds)
        return Response(self._make_request('POST', accountid, queue, query_args))

    def delete_message(self, queue, message):
        assert isinstance(queue, basestring) and isinstance(message, (str, unicode, SQSMessage))
        assert queue in self.accountids, 'must call connect(queue) first!'
        accountid = self.accountids[queue]
        query_args = {
                        'Action'        : 'DeleteMessage',
                        'ReceiptHandle' : getattr(message, 'receipt_handle', message)
                     }
        return Response(self._make_request('GET', accountid, queue, query_args))

    def receive_message(self, queue, num_messages=1, visibility_timeout=None, attribute_name='All;'):
        assert isinstance(queue, basestring) and isinstance(num_messages, int)
        assert queue in self.accountids, 'must call connect(queue) first!'
        accountid = self.accountids[queue]
        query_args = {
                        'Action'       : 'ReceiveMessage',
                        'MaxNumberOfMessages'  : str(num_messages),
                        'AttributeName' : attribute_name,
                     }
        if visibility_timeout:
            query_args['VisibilityTimeout'] = str(visibility_timeout)
        return ReceiveMessageResponse(self._make_request('GET', accountid, queue, query_args))

    def get_queue_attributes(self, queue, attribute_name='All;'):
        assert isinstance(queue, basestring) and isinstance(num_messages, int)
        assert queue in self.accountids, 'must call connect(queue) first!'
        accountid = self.accountids[queue]
        query_args = {
                        'Action'       : 'GetQueueAttributes',
                        'AttributeName' : attribute_name,
                     }
        return GetQueueAttributesResponse(self._make_request('GET', accountid, queue, query_args))

    # end public methods

    def _make_request(self, method, accountid='', queue='', query_args={}, headers={}, data='', metadata={}):

        server = self.server
        path = ''

        if accountid != '':
            path += "/%s" % accountid

        # add the slash after the accountid regardless
        # the queue will be appended if it is non-empty
        path += "/%s" % urllib.quote_plus(queue)

        # build the path_argument string
        # add the ? in all cases since
        # signature and credentials follow path args
        if method == 'GET':
            if len(query_args):
                path += '?' + self._generate_query_with_signature(method, self.server, accountid, queue, query_args)
        elif method == 'POST':
            if len(query_args):
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
                data = self._generate_query_with_signature(method, self.server, accountid, queue, query_args)

        if 'Date' not in headers:
            headers['Date'] = time.strftime(ISO8601_FORMAT, time.gmtime())

        is_secure = self.is_secure
        host = "%s:%d" % (server, self.port)
        while True:
            if (is_secure):
                connection = httplib.HTTPSConnection(host)
            else:
                connection = httplib.HTTPConnection(host)

            final_headers = headers

            connection.request(method, path, data, final_headers)
            resp = connection.getresponse()
            if resp.status < 300 or resp.status >= 400:
                return resp
            # handle redirect
            location = resp.getheader('location')
            if not location:
                return resp
            # (close connection)
            resp.read()
            scheme, host, path, params, query, fragment \
                    = urlparse.urlparse(location)
            if scheme == "http":    is_secure = False
            elif scheme == "https": is_secure = True
            else: raise invalidURL("Not http/https: " + location)
            if query: path += "?" + query
            # retry with redirect

    def _generate_query_with_signature(self, method, server, accountid, queue, query_args, expires=''):
        query_args['AWSAccessKeyId'] = self.aws_access_key_id
        query_args['SignatureMethod'] = 'HmacSHA256'
        query_args['SignatureVersion'] = '2'
        query_args['Version'] = self.VERSION
        if expires:
            query_args['Expires'] = expires
        else:
            query_args['Expires'] = time.strftime(ISO8601_FORMAT, time.gmtime(time.time()+self.DEFAULT_EXPIRES_IN))

        params = query_args
        path = ''
        if accountid != '':
            path += "/%s" % accountid
        # add the slash after the accountid regardless
        # the queue will be appended if it is non-empty
        path += "/%s" % urllib.quote_plus(queue)
        query_string = '&'.join('%s=%s'%(urllib.quote_plus(key),urllib.quote_plus(params[key], safe='-_~')) for key in sorted(params.keys()))
        string_to_sign = '\n'.join([method, server, path, query_string])
        signature = urllib.quote_plus(base64.b64encode(hmac.new(self.aws_secret_access_key, string_to_sign, hashlib.sha256).digest()).strip())
        return query_string + '&Signature=%s' % signature


class SQSMessage:
    def __init__(self, body, id=None, receipt_handle=None, md5=None, attribute={}):
        self.body = body
        self.id = id
        self.receipt_handle = receipt_handle
        self.md5 = md5
        self.attribute = attribute

class Response:
    def __init__(self, http_response):
        self.http_response = http_response
        # you have to do this read, even if you don't expect a body.
        # otherwise, the next request fails.
        self.body = http_response.read()
        if http_response.status >= 300 and self.body:
            self.message = self.body
        else:
            self.message = "%03d %s" % (http_response.status, http_response.reason)

class GetQueueUrlResponse(Response):
    def __init__(self, http_response):
        Response.__init__(self, http_response)
        if http_response.status < 300:
            handler = GetQueueUrlHandler()
            xml.sax.parseString(self.body, handler)
            self.url = handler.url
        else:
            self.url = ''

class ReceiveMessageResponse(Response):
    def __init__(self, http_response):
        Response.__init__(self, http_response)
        if http_response.status < 300:
            handler = ReceiveMessageHandler()
            xml.sax.parseString(self.body, handler)
            self.messages = handler.messages
        else:
            self.messages = []

class GetQueueAttributesResponse(Response):
    def __init__(self, http_response):
        Response.__init__(self, http_response)
        if http_response.status < 300:
            handler = GetQueueAttributesHandler()
            xml.sax.parseString(self.body, handler)
            self.attributes = handler.attributes
        else:
            self.attributes = []

class GetQueueUrlHandler(xml.sax.ContentHandler):
    def __init__(self):
        self.url = ''
        self.state = 'init'

    def startElement(self, name, attrs):
        if name == 'QueueUrl' and self.state == 'init':
            self.state = 'tag_url'

    def endElement(self, name):
        if name == 'QueueUrl' and self.state == 'tag_url':
            self.state = 'end'

    def characters(self, content):
        if self.state == 'tag_url':
            self.url = content

class ReceiveMessageHandler(xml.sax.ContentHandler):
    def __init__(self):
        self.messages = []
        self.curr_msg = None
        self.curr_attribute = []
        self.states = ['', '', '']

    def startElement(self, name, attrs):
        if name == 'Message' and self.states[0] == '':
            self.states = ['msg', '', '']
            self.curr_msg = SQSMessage(body='')
        if name == 'MessageId' and self.states[0] == 'msg':
            self.states[1] = 'id'
        if name == 'ReceiptHandle' and self.states[0] == 'msg':
            self.states[1] = 'handle'
        if name == 'MD5OfBody' and self.states[0] == 'msg':
            self.states[1] = 'md5'
        if name == 'Body' and self.states[0] == 'msg':
            self.states[1] = 'body'
        if name == 'Attribute' and self.states[0] == 'msg':
            self.states[1] = 'attribute'
        if name == 'Name' and self.states[0] == 'msg' and self.states[1] == 'attribute':
            self.states[2] = 'name'
        if name == 'Value' and self.states[0] == 'msg' and self.states[1] == 'attribute':
            self.states[2] = 'value'

    def endElement(self, name):
        if name == 'Message' and self.states[0] == 'msg':
            self.states = ['', '', '']
            curr_msg = self.curr_msg
            curr_msg.body = urllib.unquote_plus(curr_msg.body)
            curr_attribute = self.curr_attribute
            curr_msg.attribute = dict([(curr_attribute[i], curr_attribute[i+1]) for i in xrange(0, len(curr_attribute), 2)])
            self.messages.append(curr_msg)
            self.curr_msg = None
            self.curr_attribute = []

    def characters(self, content):
        if self.states[0] == 'msg':
            if self.states[1] == 'id':
                self.curr_msg.id = content
            elif self.states[1] == 'handle':
                self.curr_msg.receipt_handle = content
            elif self.states[1] == 'md5':
                self.curr_msg.md5 = content
            elif self.states[1] == 'body':
                self.curr_msg.body = content
            elif self.states[1] == 'attribute':
                if self.states[2] in ('name', 'value'):
                    self.curr_attribute.append(content)
            else:
                pass

class GetQueueAttributesHandler(xml.sax.ContentHandler):
    def __init__(self):
        self.attributes = []
        self.curr_attribute = []
        self.state = ['', '']

    def startElement(self, name, attrs):
        if name == 'Attribute' and self.states[0] == '':
            self.states = ['attribute', '']
        if name == 'Name' and self.states[0] == 'attribute':
            self.states[1] = 'name'
        if name == 'Value' and self.states[0] == 'attribute':
            self.states[1] = 'value'

    def endElement(self, name):
        if name == 'Attribute' and self.states[0] == 'attribute':
            self.state = ['', '']
            curr_attribute = dict([(self.curr_attribute[i], self.curr_attribute[i+1]) for i in xrange(0, len(self.curr_attribute), 2)])
            self.attributes.append(curr_attribute)
            self.curr_attribute = []

    def characters(self, content):
        if self.states[0] == 'attribute':
            if self.states[1] in ('name', 'value'):
                self.curr_attribute.append(content)
        else:
            pass