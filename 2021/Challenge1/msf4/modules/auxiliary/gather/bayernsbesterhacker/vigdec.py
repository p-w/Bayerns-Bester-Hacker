#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# import standard modules
import logging
import sys
import re
from metasploit import module

# extra modules
dependencies_missing = False
try:
  # try to load additional dependencies
  pass
except ImportError:
  dependencies_missing = True

# metasploit metadata
metadata = {
  'name': 'Bayerns Bester Hacker - Challenge 2021/1',
  'description': '''
    Vigenère cipher python implementation to crack encrypted mail communication
  ''',
  'authors': [
    'PW'
  ],
  'date': '2021-08-01',
  'license': 'MSF_LICENSE',
  'references': [
    {'type': 'url', 'ref': 'https://bayerns-bester-hacker.de/'},
    {'type': 'url', 'ref': 'https://github.com/p-w/'},
    {'type': 'aka', 'ref': 'Bayerns Bester Hacker 2021/1'}
  ],
  'type': 'single_scanner',
  'options': {
    'RHOSTS': {'type': 'string', 'description': 'The default RHOSTS', 'required': True, 'default': '127.0.0.1'},
    'mail_enc': {'type': 'string', 'description': 'The file path to the Vignere encrypted email message', 'required': True, 'default': None},
    'keys_file': {'type': 'string', 'description': 'The path to the keys file containing the decryption keys', 'required': True, 'default': None},
    'plaintext_check': {'type': 'string', 'description': 'A plaintext word to verify successful decryption', 'required': True, 'default': 'charset'}
  }
}

# decode Vignere cipher
def run(args):
  module.LogHandler.setup(msg_prefix='BBH2021/1 ')
  logging.info('Encrypted Mail: {}'.format(args['mail_enc']))
  logging.info('Keys file: {}'.format(args['keys_file']))
  logging.info('Testing for keyword: {}'.format(args['plaintext_check']))

  if dependencies_missing:
    logging.error('Module dependency is missing, cannot continue')
    return

  # BBH Challenge 1 core
  try:
    # read keys file
    keys_file = open(args['keys_file'], 'r')
    keys_list = keys_file.readlines()
    if len(keys_list):
      logging.info('Loading {} keys'.format(len(keys_list)))
    else:
      logging.error('Keys file is missing, cannot continue')

    # read encrypted mail
    mail_enc = open(args['mail_enc'], 'r')
    mail_content = mail_enc.read()
    if len(mail_content):
      logging.info('Loading mail')
    else:
      logging.error('Mails file is missing, cannot continue')

    # brute forcing all keys in keys_list
    key_count = 1
    for key in keys_list:
      vig_dec = ''
      key_len = len(key)
      count = 0

      logging.info('Brute Forcing ... {}/{} with key {}'.format(key_count, len(keys_list), key))

      # Vignere deciphering each line from mail
      for line in mail_content:
        for char in line:
          # only encrypt/decrypt letters (A-Za-z)
          if char.isalpha():
            vig = chr(97+((ord(char.lower())-97) - (ord(key[count%key_len].lower())-97))%26)
            count += 1
          else:
            vig = char

          vig_dec += vig
      key_count += 1

      # Test if decrypted version contains plaintext keyword
      bbh_dec = re.findall(args['plaintext_check'], vig_dec)
      if bbh_dec:
        logging.info('Found decryption key: {}'.format(key))
        break
	
    return
  except (TypeError, AttributeError) as e:
    logging.error('{}'.format(e))
    return


if __name__ == '__main__':
  module.run(metadata, run)
