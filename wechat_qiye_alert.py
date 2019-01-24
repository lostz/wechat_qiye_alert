#! /usr/bin/env python
# -*- coding: utf-8 -*-

import json
from elastalert.alerts import Alerter, BasicMatchString
from staticconf.loader import yaml_loader
from requests.exceptions import RequestException
from elastalert.util import elastalert_logger,EAException,elastalert_logger
import requests
import sqlite3
import time
import os


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


class WeChatAlerter(Alerter):


    def __init__(self, *args):
        super(WeChatAlerter, self).__init__(*args)
        self.user_id= ""
        self.secret = ""
        self.agent_id = ""
        self.corp_id = ""
        self.party_id = ""
        self.tag_id = ""
        self.db_path = ""
        self.get_account(self.rule['weixin_auth_file'])

    def create_default_title(self, matches):
        subject = 'ElastAlert: {0}'.format(self.rule['name'])
        return subject

    def alert(self, matches):

        body = self.create_alert_body(matches)

        self.get_token()

        self.senddata(body)
    def check_token_table(self,conn):
        sql = "SELECT name  FROM sqlite_master where type='table' and name='token'"
        conn.row_factory = dict_factory
        cursor = conn.cursor()
        cursor.execute(sql)
        result = cursor.fetchall()
        cursor.close()
        if len(result):
            return True
        else:
            return False

    def init_token_table(self,conn):
        sql ="create table token (id integer primary key,token text,expires real)"
        cursor = conn.cursor()
        cursor.execute(sql)
        conn.commit()
        cursor.close()

    def get_account(self,account_file):
	if os.path.isabs(account_file):
           account_file_path = account_file
	else:
           account_file_path = os.path.join(os.path.dirname(self.rule['rule_file']), account_file)
        account_conf = yaml_loader(account_file_path)
        if 'api_secret' not in account_conf or 'agent_id' not in account_conf or 'corp_id' not in account_conf or 'db_path' not in account_conf:
            raise EAException('account file must have api_secret and agent_id and corp_id and db_path fields')
        self.user_id= account_conf['user_id']
        self.secret = account_conf['api_secret']
        self.agent_id = account_conf['agent_id']
        self.corp_id = account_conf['corp_id']
        self.party_id = account_conf['party_id']
        self.tag_id = account_conf['tag_id']
        self.db_path = account_conf['db_path']


    def get_token4db(self,conn):
        sql = "select token,expires from token where id =1"
        cursor = conn.cursor()
        cursor.execute(sql)
        result = cursor.fetchall()
        cursor.close()
        conn.close()
        if len(result)==0:
            return "",""
        else:
            return result[0]['token'],result[0]['expires']
    def get_fresh_token(self,now):
        token_url = 'https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={0}&corpsecret={1}'.format(self.corp_id,self.secret)
        try:
            response = requests.get(token_url)
            response.raise_for_status()
        except RequestException as e:
            raise EAException("get access_token failed , stacktrace:%s" % e)
        token_json = response.json()
        if 'access_token' not in token_json :
            raise EAException("get access_token failed , , the response is :{0}".format(response.text()))

        return token_json['access_token'],int(token_json['expires_in'])+now

    def update_token2db(self,conn,token,expires_in):
        cursor =conn.cursor()
        try:
            sql = ''' insert into token  (id,token,expires) values(1,"{0}",{1})'''.format(token,expires_in)
            cursor.execute(sql)
        except sqlite3.IntegrityError:
            sql = '''update token set token="{0}",expires={1} where id=1'''.format(token,expires_in)
            cursor.execute(sql)
        conn.commit()
        cursor.close()
        conn.close()



    def get_token(self):
        now = int(time.mktime(time.localtime()))
        try:
            conn  = sqlite3.connect(self.db_path,timeout=10)
            if not self.check_token_table(conn):
                self.init_token_table(conn)
            token,expires_in = self.get_token4db(conn)
        except sqlite3.Error as e:
            raise EAException("connect {0} , stacktrace:{1}".format(self.db_path,e))
        if now>expires_in or token=="":
            elastalert_logger.info("get fresh token")
            token,expires_in = self.get_fresh_token(now)
            conn  = sqlite3.connect(self.db_path,timeout=10)
            self.update_token2db(conn,token,expires_in)
        self.access_token = token
        return self.access_token

    def senddata(self, content):

        if len(content) > 2048:
            content = content[:2045] + "..."
        url="https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={0}".format(self.access_token)
        data={}
        data["touser"]= self.user_id
        data["toparty"] = self.party_id
        data["totag"] = self.party_id
        data["msgtype"]="text"
        data["agentid"]=self.agent_id
        data["text"] ={}
        data["text"]["content"] =content
        try:
            response = requests.post(url, json=data)
            response.raise_for_status()
        except RequestException as e:
            raise EAException("send message has error: {0}".format(e))

        elastalert_logger.info("send msg and response: {0}".format(response.text))


    def get_info(self):
        return {'type': 'WeChatAlerter'}
