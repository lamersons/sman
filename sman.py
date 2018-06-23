#!/usr/bin/python
##########################################################################################
# -*- coding: utf-8 -*-
##########################################################################################
#
# Application name: sman (ssh manager)
#
# Author: MiZo <misha3@gmail.com>
#
# Application manages ssh credentials and keys, stores data in Hashi Vault
# Usage: sman help
#
##########################################################################################

import os
import time
import ast
import getopt
import sys
import tempfile
import json
from operator import itemgetter, attrgetter
from sys import exit
# import re
from ast import literal_eval
from subprocess import Popen, PIPE, STDOUT
import subprocess
import socket
from fqdn import FQDN
try:
    import hvac
except ImportError:
    sys.exit("Please install hvoc module for python3+")
import pexpect

sys.path.append(os.path.dirname(__file__))

##########################################################################################
#
# Vault management class
#
##########################################################################################
class Vault():

    RUNNING = 0
    INITIALIZED = 0
    TOKEN = ""
    BUILD_ROOT = os.path.dirname(__file__)
    CONN_PATH = "secret/conn/"
    KEY_PATH = "secret/key/"

    c = hvac.Client(url="http://localhost:8200")

    def __init__(self):
        self.set_env()
        while self.is_ready() == "not_started":
            self.start_vault()
            time.sleep(1)
        while self.is_ready() == "not_init":
            self.c = self.init()
            time.sleep(1)
        while self.is_ready() == "sealed":
            self.c = self.unseal()
            time.sleep(1)
        if self.is_ready(): self.get_client()

    def start_consul(self):
        c = ["consul", "agent", "-dev &"]
        r = self.exec_cmd(c, 0)
        return r

    def start_vault(self):
        print("Starting Vault daemon")
        c = "vault server -config=" + self.BUILD_ROOT + "/vault/config.hcl  >/dev/null 2>&1 &"
        r = os.system(c)
        self.RUNNING = 1
        return r

    def is_ready(self):
        c = ["vault", "status", "-format=json"]
        r = self.exec_cmd(c)
        if "connection refused" in r[1]: return "not_started"
        if "not yet initialized" in r[1]: return "not_init"
        try:
            if json.loads(r[0])["sealed"]:
                return "sealed"
        except:
            return "not_started"
        if "Error" in r[1]: return "error"
        return 1

    def set_env(self):
        os.environ["VAULT_ADDR"]="http://localhost:8200"

    def get_token(self):
        c = ["vault", "token", "create", "-format=json"]
        r = self.exec_cmd(c)
        t = json.loads(r[0])["auth"]["client_token"]
        os.environ["VAULT_TOKEN"] = t
        return t

    def init(self):
        r = self.c.initialize(5, 3)
        self.TOKEN = r["root_token"]
        with open(self.BUILD_ROOT + "/vault/unseal", "w") as f:
            print("Writing tokens to vault/unseal")
            f.write(r["root_token"] + "\n")
            f.write(str(r["keys"]))
            f.close()

    def unseal(self):
        self.c = hvac.Client(url="http://localhost:8200")
        with open(self.BUILD_ROOT + "/vault/unseal", "r") as f:
            b = f.readlines()
            tlist = b[1]
            rt = b[0]
            self.c.unseal_multi(ast.literal_eval(tlist))
            c = "vault login " + rt
            r = os.system(c)

    def get_client(self):
        with open(self.BUILD_ROOT + "/vault/unseal", "r") as f:
            rt = f.readlines()[0]
            self.c = hvac.Client(url="http://localhost:8200", token=rt.strip("\n"))
            return self.c

    def writef(self, secret_path, file_path):
        c = ["vault", "write", "-f", secret_path, "priv_key=@" + file_path]
        r = self.exec_cmd(c)
        return r

    def deploy_vault(self):
        pass

    def exec_cmd(self, cmd, silent=True):
        try:
            x = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        except Exception as e:
            print(e)
        else:
            stdout = x.stdout.read()
            stderr = x.stderr.read()
            if not silent:
                print(cmd)
                print(stdout.decode("UTF-8"))
                print(stderr.decode("UTF-8"))
            return stdout.decode("UTF-8"), stderr.decode("UTF-8")
        return 0

##########################################################################################
#
# SMAN main class
# extended by Vault class
#
##########################################################################################
class Sman(Vault):
    def usage(self, keys=["usage", "basic"], msg={}):
        if msg == {}:
            msg = {
                "add":{
                    "validation":{
                        "name":"Name is limited to 30 alfa-numeric characters",
                        "host":"Host should be FQDN or IPv4",
                        "port":"Port should be integer in 65000 range",
                        "user":"Username is limited to 30 alfa-numeric characters"
                    }
                },
                "usage": {
                    "basic":"do this and that :)",
                    "empty_list":"\nList is empty, please add some hosts:\nsman add <name> <host> <port> <user> <password> <path_to_key>",
                    "connect":"\nConnect to host:\nsman <id>  or  sman <id> su"
                }
                }

        return self.usage(keys[1:], msg[keys[0]]) if keys else sys.exit(msg)

    @staticmethod
    def table(tbl, h = ' ', v = '|', c = '|'):
        cols = [list(x) for x in zip(*tbl)]
        lens = [max(map(len, map(str, col))) for col in cols]
        f = v + v.join(' {:>%d} ' % l for l in lens) + v
        s = c + c.join(h * (l + 2) for l in lens) + c

        print("\n")
        for row in tbl:
            print(f.format(*row))
            print(s)

    def validate(self, n, h, p, u, passw0rd="asdasd23", priv_key=""):
        #connection name validation
        if len(n) > 30:# and not n.isalnum():
            self.usage(["add", "validation", "name"])
            return False
        #username validation
        if len(u) > 30:# and not n.isalnum():
            self.usage(["add", "validation", "user"])
            return False
        #hostname validation
        try:
            socket.inet_aton(h)
        except:
            if not FQDN(h).is_valid:
                self.usage(["add", "validation", "host"])
                return False
        #port validation
        try:
            b = p.isdigit
            if int(p) > 65500:
                print(int(p), s.is_ready())
                return False
        except:
            self.usage(["add", "validation", "port"])
            return False

        return True

    def get_id(self):
        c = ["vault", "list", "-format=json", s.CONN_PATH]
        r = s.exec_cmd(c)
        if "No value found at" in r[1]: return([""], str(0))
        r = ast.literal_eval(r[0])
        max = []
        for x in range(0, len(r) + 1): max.append(str(x))
        l = sorted(list(set(max) - set(r)))
        return(r, str(l[0]))

    def sman_add(self, n, h, p, u, pwd, priv_key=""):
        id = self.get_id()[1]
        if self.validate(n, h, p, u):
            c.write(s.CONN_PATH + id, id=id, n=n, h=h, u=u, p=p, pwd=pwd)
            if priv_key != "": s.writef(s.KEY_PATH + id, priv_key)
        print("\nSaved %s %s %s with id: %s\n" % (h, p, u, id))

    def sman_ls(self):
        if s.is_ready():
            if self.get_id()[0][0] == "": self.usage(["usage", "empty_list"])
            l = [int(x) for x in self.get_id()[0]]
            t = [["ID", "NAME", "HOST", "PORT", "USERNAME", "SSH-KEY"]]
            for k in sorted(l):
                r = c.read(s.CONN_PATH + str(k))["data"]
                map = {"id": 1, "n":2, "h":3, "p":4, "u":5, "pwd":6}
                d = [r[i] for i in sorted(r, key=map.__getitem__)]
                if len(d[2]) > 30: d[2] = "..." + d[2][-30:]
                t.append(d)
            self.table(t)
            s.usage(["usage", "connect"])

    def sman_del(self, id):
        if input("(y/n) Are you sure you want to delete: " + id + "?\n") == "y":
            c.delete(s.CONN_PATH + id)
            c.delete(s.KEY_PATH + id)
            print("\nDeleted id: " + id + "\n")

    def sman_get_conn_by_id(self, id):
        r = c.read(s.CONN_PATH + id)
        return r

    def sman_get_key_by_id(self, id):
        r = c.read(s.KEY_PATH + id)
        return r

    def connect(self, id, su=False):
        r = self.sman_get_conn_by_id(id)
        k = self.sman_get_key_by_id(id)
        n = r["data"]["n"]
        h = r["data"]["h"]
        p = r["data"]["p"]
        u = r["data"]["u"]
        pwd = r["data"]["pwd"]
        try:
            key = k["data"]["priv_key"]
        except:
            c = "/usr/bin/sshpass -p " + pwd + " /usr/bin/ssh " + u + "@" + h
        else:
            f = tempfile.NamedTemporaryFile(mode="w+b",delete=True)
            f.write(key.encode("UTF-8"))
            f.seek(0)
            c = "ssh -i " + f.name + " " + u + "@" + h
            # print(c)
        pe = pexpect.spawn(c)
        if su:
            pe.expect("\~\]\$")
            pe.sendline("sudo su -")
        try:
            pe.interact()
            sys.exit(0)
        except:
            raise

    def switch(self, argv):
        cmd_list = ["add", "del", "ls"]
        if len(argv) == 1:
            self.sman_ls()
            exit()
### sman id
        if len(argv) == 2 and argv[1].isdigit():
            if argv[1] in self.get_id()[0]:
                self.connect(argv[1])
            else:
                self.usage()
### sman id su
        elif len(argv) == 3 and argv[1].isdigit() and argv[2] == "su":
            self.connect(argv[1], 1)
### sman list
        if argv[1] in cmd_list:
            if argv[1] in "ls": self.sman_ls()
### sman add
            elif argv[1] in "add":
                if len(argv) == 7:
                    self.sman_add(argv[2],argv[3],argv[4],argv[5],argv[6])
                    self.sman_ls()
                elif len(argv) == 8:
                    self.sman_add(argv[2],argv[3],argv[4],argv[5],argv[6],argv[7])
                    self.sman_ls()
                else:
                    self.usage()
            elif argv[1] in "del":
                if len(argv) == 3 and argv[2].isdigit():
                    if argv[2] in self.get_id()[0] or self.get_id()[0][0] == "":
                        self.sman_del(argv[2])
                        self.sman_ls()
                    else:
                        self.sman_ls()
                        self.usage()
                else:
                    self.sman_ls()
                    self.usage()
            else:
                self.usage()
        else:
            self.usage()

if __name__ == "__main__":
    s = Sman()
    if s.is_ready(): c = s.c
    else: exit("Vault server is not ready, something wrong")
    s.switch(sys.argv)
