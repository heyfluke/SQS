#!/usr/bin/env python
# coding:utf-8

__version__ = '1.0'
__author__  = 'phus_lu@trendmicro.com.cn'

import sys, os, re, time
import logging
import boto, boto.sqs.queue, boto.sqs.message
import S3
try:
    import ujson as json
except ImportError:
    import json

class AWSConnection(object):
    def __init__(self, awsid, awskey, region=None, is_secure=False):
        assert isinstance(awsid, basestring) and isinstance(awskey, basestring)
        self.awsid = awsid
        self.awskey = awskey
        self.region = region
        self.is_secure = is_secure
        self.__sqs_conn = boto.connect_sqs(awsid, awskey, is_secure=is_secure, region=region)
        self.__sqs = {}
        self.__s3 = S3.AWSAuthConnection(awsid, awskey, is_secure=is_secure)

    def s3(self):
        return self.__s3

    def sqs(self, queue_name):
        assert isinstance(queue_name, basestring)
        if queue_name not in self.__sqs:
            sqs_conn = self.__sqs_conn
            logging.info('connect SQS queue_name=%r', queue_name)
            queue = sqs_conn.get_queue(queue_name)
            logging.info('connect SQS queue_name=%r OK', queue_name)
            queue.set_message_class(boto.sqs.message.RawMessage)
            self.__sqs[queue_name] = queue
        return self.__sqs[queue_name]

    def s3_get(self, bucket, key):
        assert isinstance(bucket, basestring) and isinstance(key, basestring)
        s3object = self.__s3.get(bucket, key).object
        return s3object.data, s3object.metadata

    def s3_put(self, bucket, key, data, metadata={}):
        s3object = S3.S3Object(data, metadata)
        response = self.__s3.put(bucket, key, s3object)
        return response.message

    def s3_delete(self, bucket, key, headers={}):
        response = self.__s3.delete(bucket, key, headers)
        return response.message

    def s3_list_bucket(self, bucket, prefix=''):
        options = {'prefix':prefix} if prefix else {}
        response = self.__s3.list_bucket(bucket, options)
        return [entry.key for entry in response.entries]

    def sqs_get_messages(self, queue_name, num_messages=1, visibility_timeout=None, attributes=None):
        queue = self.sqs(queue_name)
        messages = self.__sqs_conn.receive_message(queue, num_messages, visibility_timeout, attributes)
        return [(m.receipt_handle, json.loads(m.get_body())) for m in messages]

    def sqs_read_message(self, queue_name, visibility_timeout=None, attributes=None, polling=2):
        num_messages = 1
        while 1:
            messages = self.sqs_get_messages(queue_name, num_messages, visibility_timeout, attributes)
            if len(messages) == 0:
                time.sleep(polling)
                continue
            return messages[0]

    def sqs_send_message(self, queue_name, message, delay_seconds=None):
        assert isinstance(queue_name, basestring) and isinstance(message, dict)
        queue = self.sqs(queue_name)
        message_content = json.dumps(message)
        response_message = self.__sqs_conn.send_message(queue, message_content, delay_seconds)
        return response_message.receipt_handle

    def sqs_delete_message(self, queue_name, message_handle):
        assert isinstance(queue_name, basestring) and isinstance(message_handle, basestring)
        queue = self.sqs(queue_name)
        return self.__sqs_conn.delete_message_from_handle(queue, message_handle)

def test():
    bucket = 'icsslogwriter'
    queue_name = 'icsslogwriter'
    conn = AWSConnection('AKIAJOL5JWRJIPDCJI4A', '9ZlKEzTCcUQOcxEq7SztGKl0iVAOjdHuXxb/nHl3')
    print conn.s3_list_bucket(bucket, '1')
    print conn.s3_put(bucket, '1.txt', 'OOPS!')
    print conn.s3_list_bucket(bucket, '1')
    print conn.s3_get(bucket, '1.txt')
    print conn.s3_delete(bucket, '1.txt')
    print conn.s3_list_bucket(bucket)

    print conn.sqs_send_message(queue_name, {'text':'hello world!'})
    message_handle, message_body = conn.sqs_read_message(queue_name)
    print message_handle, message_body
    print conn.sqs_delete_message(queue_name, message_handle)


if __name__ == '__main__':
    test()
