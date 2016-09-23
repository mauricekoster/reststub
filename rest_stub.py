#!/usr/bin/python
from http.server import BaseHTTPRequestHandler,HTTPServer
import os, glob
from os.path import basename
import re, sys
import socket
import logging
import json
import argparse

# external dependancies
import pystache
import yaml

# === Configuration ========================================================================
argparser = argparse.ArgumentParser()
argparser.add_argument("--dir", help="Base directory.")
argparser.add_argument("--rules", help="Filename of rules.")
argparser.add_argument("--port", help="Listen on port (default=9999)")
args = argparser.parse_args()

if args.dir:
  base_dir = os.path.normpath(args.dir)
else:
  base_dir = os.path.dirname(os.path.abspath(__file__))

if args.port:
  PORT_NUMBER = int(args.port)
else:
  PORT_NUMBER = 9999

if args.rules:
  rules_filename = args.rules
else:
  rules_filename = 'rules.yaml'

rules = None
variables = {}
rules_modified = None

# store last request of ruleset, enabling to retrieve it to check its content
last_requests = {}

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.DEBUG)
logger = logging.getLogger(__name__)

logger.info("basedir: %s" % base_dir)

### = Reverse pystache (Mustache) =====================================================================

class MustacheException(Exception):
    pass

def reverse_pystache(template, content):
    
    g = re.findall('\{\{([^}]+)}}', template )
    s = template

    if g:
        for x in g:
            s = s.replace('{{%s}}' % x, '(.+)')
    else:
        return None

    g2_ret = re.match(s, content)
    if not g2_ret:
        return None

    g2 = g2_ret.groups()

    h = dict(zip(g, g2))
    return h

### =====================================================================================


def read_rules():
  global rules
  global rules_modified

  fn = os.path.join(base_dir, rules_filename)
  if not os.path.exists(fn):
    logger.error('Rules do not exists')
    return

  logger.info( "Reading ruleset '%s'" % fn )

  f = open( fn, 'r')
  rules = yaml.load(f)
  f.close()
  
  mt = os.path.getmtime(fn)
  rules_modified = mt

  logger.debug(json.dumps(rules))

def check_rule_file_modified():
  fn = os.path.join(base_dir, rules_filename)
  mt = os.path.getmtime(fn)
  if rules_modified:
    #logger.debug('rules last read: %f' % rules_modified)
    #logger.debug('rules file modified: %f' % mt)
    if mt > rules_modified:
      return True

  return False

### =====================================================================================

#This class will handles any incoming request from the browser
class myHandler(BaseHTTPRequestHandler):

  def send_last_request(self, ruleset, idx=-1):
    if ruleset in last_requests:
      content = last_requests[ruleset][idx]
      logger.debug('last request:')
      logger.debug(content)

      content = json.dumps(content)
      content = content.encode('UTF-8','replace')
      s = len(content)
      self.send_response(200)
      self.send_header('Content-type','text/json')
      self.send_header('Content-Length', s)
      self.end_headers()

      self.wfile.write(content)

    else:
      self.send_response(204, "No last request for: %s" % ruleset)
      self.end_headers()

    

  def send_reply(self, reply, values, uri_values, response_code=200, response_message=None):
    if reply:
      r = reply.replace('/', os.sep)
      fn = os.path.join(base_dir, r)
      logger.info("Returning reply %s" % fn)
      f = open( fn, 'r' )
      content = f.read()
      f.close()

      content = content.replace('\r\n','\n')
      content = content.replace('\n','\r\n')

      content = pystache.render(content, values)
      content = pystache.render(content, uri_values)

      body = content.encode('UTF-8','replace')

    else:
      logger.info("Returning empty content")
      body = None

    self.send_response(response_code, response_message)
    if body:
      ext = os.path.splitext(fn)[-1]
      self.send_header('Content-type','application/%s' % ext[1:])
      self.send_header('Content-Length', len(body))
    else:
      self.send_header('Content-Length', 0)
    self.end_headers()

    if body:
      self.wfile.write(body)

  

  def do_POST(self):
    self.handle_request('post')

  def do_PUT(self):
    self.handle_request('put')

  def do_GET(self):
    self.handle_request('get')

  def handle_request(self, method):  
    sendReply = False

    if check_rule_file_modified():
      #logger.debug('rules changed')
      read_rules()

    logger.debug("%s: %s" % (method, self.path))
    logger.debug(self.headers)

    if self.path.startswith('/@/'):
      logger.debug('Get last request')
      return self.send_last_request('%s %s' % (method.upper(), self.path[2:] ))

    # Get request content
    if 'Content-Length' in self.headers:
      l = self.headers['Content-Length']
      l = int(l)
      content = self.rfile.read(l)
      text = content.decode("utf-8")
      content_raw = text

      if 'Content-Type' in self.headers:
        if 'x-www-form-urlencoded' in self.headers['Content-Type']:
          c={}
          for p in text.split('&'):
            (k, v) = p.split('=')[:2]
            c[k] = v
          content = c

        elif 'application/json' in self.headers['Content-Type']:
          content = json.loads(text)
      else:
        content = text

      logger.debug("Content:")
      logger.debug(json.dumps(content, sort_keys=True, indent=4))

    else:
      content = None

    # Store last request
    ruleset = '%s %s' % (method.upper(), self.path)
    headers = {k: v for k, v in self.headers.items()}
    store = {'Method': method.upper(), 'Path': self.path, 'Body': content_raw, 'BodyParsed': content, 'Headers': headers}
    logger.debug(json.dumps(store,indent=4))

    if ruleset in last_requests:
      last_requests[ruleset].append(store)
    else:
      last_requests[ruleset] = [store]
    
    

    for rule in rules[method]:
      logger.debug("Rule: " + json.dumps(rule))

      
      if 'ResponseCode' in rule:
        response_code = int(rule['ResponseCode'])
      else:
        response_code = 200

      if 'ResponseMessage' in rule:
        response_msg = rule['ResponseMessage']
      else:
        response_msg = None

      if 'Reply' in rule:
        reply = rule['Reply']
      else:
        reply = None

      if 'Path' in rule:
        path = rule['Path']
        uri_values = reverse_pystache(path, self.path)
        logger.debug('uri_values: %s', uri_values)

        have_match = uri_values or (self.path == path)
        if have_match:
          if 'Criteria' in rule:
            match = True
            for criteria in rule['Criteria']:
              if criteria['Name'] in content:
                if criteria['Value'] != content[criteria['Name']]:
                  match = False

          else:
            match = True

          if match:
            logger.debug('Rule matched')
            sendReply = True
            break


      else:
        # No path, so just send reply
        logger.info("Matched default rule")
        
        sendReply = True


    if sendReply == True:
      if reply:
        reply = pystache.render(reply, content)
        reply = pystache.render(reply, uri_values)

      self.send_reply(reply, content, uri_values, response_code, response_msg)

    else:
      logger.info("No rules matched")

      self.send_error(404,'No rules matched')

  
### -----------------------------------------------------------------------------------------  

if __name__ == '__main__':
  try:
    read_rules()

    # Create a web server and define the handler to manage the
    #incoming request
    fqdn = '' # socket.getfqdn()
    server = HTTPServer((fqdn, PORT_NUMBER), myHandler)
    logger.info( 'Started httpserver on %s port %d' % (fqdn or 'localhost', PORT_NUMBER) )

    #Wait forever for incoming htto requests
    server.serve_forever()

  except KeyboardInterrupt:
    print('^C received, shutting down the web server')

    server.socket.close()
