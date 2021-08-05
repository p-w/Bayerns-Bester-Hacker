#!/usr/bin/python
import sys
import re

### Vigenere Entschluesselung

# Funktion zur Entschluesselung 
# vgl. https://gist.github.com/2O4/cfa87e6ae1e0abd0afaee2722213c110
def vig( txt = "", key = "", typ = 'd' ):
  vig_dec = ''
  key_len = len(key)
  counter = 0
  
  for line in txt:
    for char in line:
      # only encrypt/decrypt letters (A-Za-z)
      if char.isalpha():
        if typ == 'd':
          vig = chr(97+((ord(char.lower())-97) - (ord(key[counter%key_len].lower())-97))%26)
        else:
          vig = chr(97+((ord(char.lower())-97 + ord(key[counter%key_len].lower())-97)%26))

        counter += 1
      else:
        vig = char

      vig_dec += vig
  return vig_dec


# Lese Keys
keys_file = open('keys.txt', 'r')
keys_list = keys_file.readlines()


# Lese Mail
mail_enc = open('mail.enc', 'r')
mail_content = mail_enc.read()
print(mail_content)


# Teste Keys und Suche nach Keywords
count = 1
for key in keys_list:
  print( "Teste Key {}: {}". format( count, key.strip() ) )
  count += 1
  test_dec = vig( mail_content, key.strip(), 'd' )

  bbh_dec = re.findall("charset", test_dec)
  if bbh_dec:
    print(test_dec)
    print( "Decryption Key fuer BBH Challenge 1: {}". format( key.strip() ) )
    break;
