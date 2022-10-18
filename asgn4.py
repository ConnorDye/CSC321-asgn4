from ast import Constant
from lib2to3.pgen2.token import NEWLINE
from random import randrange
from unittest import result
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto import Random
import os
import urllib
import json
from base64 import b64encode
from base64 import b64decode
from Crypto.Util.Padding import unpad
from Crypto.Util.Padding import pad
import codecs
from Crypto.Hash import SHA256
from Crypto.Util import number
import string
import random
import time
from bcrypt import *;
import nltk
nltk.download('words')
from nltk.corpus import words

def hash_inputs(sha_input):
    sha_input = sha_input.encode()
    h = SHA256.new()
    h.update(sha_input)
    return h.hexdigest()
    # print(h.hexdigest())

def truncate_hash_output(hash):
    truncated_output = bytearray(hash , "UTF-8" )
    truncated_output = truncated_output[0:1] 
    return truncated_output


def task1():
    # PART A) see function hash_inputs for: Write a program that uses SHA256 to hash arbitrary inputs and print
    # the resulting digests to the screen in hexadecimal format. 

    # PART B)Hash two strings (of any length) whose Hamming distance is exactly
    # 1 bit (i.e. differ in only 1 bit). Repeat this a few times.
    string1 = "Hello"
    string2 = "Fello"
    print("Two strings with Hamming distance of 1: ", string1, ",", string2)
    hash1 = hash_inputs(string1)
    hash2 = hash_inputs(string2)
    print(string1, "=", hash1)
    print(string2, "=", hash2)

    string1 = "Bob"
    string2 = "Cob"
    print("Two strings with Hamming distance of 1: ", string1, ",", string2)
    hash1 = hash_inputs(string1)
    hash2 = hash_inputs(string2)
    print(string1, "=", hash1)
    print(string2, "=", hash2)


    string1 = "Lob"
    string2 = "Mob"
    print("Two strings with Hamming distance of 1: ", string1, ",", string2)
    hash1 = hash_inputs(string1)
    hash2 = hash_inputs(string2)
    print(string1, "=", hash1)
    print(string2, "=", hash2)

    # PART C)
    # Modify your program to compute SHA256 hashes of arbitrary inputs, so that it is
    # able to truncate the digests to between 8 and 50 bits (it doesn’t matter
    # which bits of the output you choose, as long as you are consistent).
    print("\nTASK 1 PART C) FIND EQUAL HASH VALUES FROM TWO DIFFERENT STRINGS")
    string1 = "HELLOHELLO"
    num_bits = 8
    while(num_bits < 50):
        find_hash_collision(string1, num_bits)
        num_bits = num_bits + 2


def find_hash_collision(string1, num_bits):
    hash1 = hash_inputs(string1)
    # hash2 = hash_inputs(string2)
    truncated_hash1 = get_bits_from_hash(hash1, num_bits)
    truncated_hash2 = ""
    print("Finding string with hash equal to: ", string1, ",", truncated_hash1)
    string_len = 10
    # random_string = ''.join(random.choices(string.ascii_uppercase +
    #                                 string.digits, k=string_len))

    # print(random_string)
    start_time = time.time()
    num_inputs = 0
    while(truncated_hash1 != truncated_hash2):
        # initializing size of string
        # using random.choices()
        # generating random strings
        random_string = ''.join(random.choices(string.ascii_uppercase +
                                    string.digits, k=string_len))
        hash2 = hash_inputs(random_string)
        truncated_hash2 = get_bits_from_hash(hash2, num_bits)
        if(truncated_hash2 == truncated_hash1):
            print("Random string with same hash is: ", random_string, truncated_hash2)
            end_time = time.time()
            time_for_collision = end_time - start_time
            print("Time to find a collision for", num_bits, "bits is", time_for_collision, "seconds.")
            print("Number of inputs needed to find collision is: ", num_inputs, "\n")
        num_inputs = num_inputs + 1

def string_to_binary(st):
    bytes = ' '.join(format(ord(x), 'b') for x in st)
    bit_string = bytes.replace(" ","")
    return bit_string

def get_bits_from_hash(hash, num_bits):
    bit_hash = string_to_binary(hash)
    truncated_bit_hash = bit_hash[0:num_bits]
    # while(len(truncated_bit_hash) % 8 != 0):
    #     truncated_bit_hash = truncated_bit_hash + '0'
    return truncated_bit_hash

def task2():
    # hash_plaintext = '$2b$08$J9FW66ZdPI2nrIMcOxFYI.qx268uZn.ajhymLP/YHaAsfBGP3Fnmq'
    # byte_hash = hash_plaintext.encode("utf-8")
    # hash_list = [byte_hash]
    # words_list = words.words()
    # for w in words_list:
    #     password = w.encode("utf-8")
    #     if checkpw(password, byte_hash):
    #         print("Password for user is ", w)
    #         break
    #     else:
    #         print("Not a match!")

    # hash_plaintext = '$2b$08$J9FW66ZdPI2nrIMcOxFYI.qx268uZn.ajhymLP/YHaAsfBGP3Fnmq'
    # byte_hash = hash_plaintext.encode("utf-8")

    # hash_list = [b'$2b$08$J9FW66ZdPI2nrIMcOxFYI.qx268uZn.ajhymLP/YHaAsfBGP3Fnmq', b'$2b$08$J9FW66ZdPI2nrIMcOxFYI.q2PW6mqALUl2/uFvV9OFNPmHGNPa6YC',
    #              b'$2b$08$J9FW66ZdPI2nrIMcOxFYI.6B7jUcPdnqJz4tIUwKBu8lNMs5NdT9q', b'$2b$09$M9xNRFBDn0pUkPKIVCSBzuwNDDNTMWlvn7lezPr8IwVUsJbys3YZm',
    #              b'$2b$09$M9xNRFBDn0pUkPKIVCSBzuPD2bsU1q8yZPlgSdQXIBILSMCbdE4Im', b'$2b$10$xGKjb94iwmlth954hEaw3O3YmtDO/mEFLIO0a0xLK1vL79LA73Gom',
    #              b'$2b$10$xGKjb94iwmlth954hEaw3OFxNMF64erUqDNj6TMMKVDcsETsKK5be', b'$2b$10$xGKjb94iwmlth954hEaw3OcXR2H2PRHCgo98mjS11UIrVZLKxyABK',
    #              b'$2b$11$/8UByex2ktrWATZOBLZ0DuAXTQl4mWX1hfSjliCvFfGH7w1tX5/3q', b'$2b$11$/8UByex2ktrWATZOBLZ0Dub5AmZeqtn7kv/3NCWBrDaRCFahGYyiq',
    #              b'$2b$11$/8UByex2ktrWATZOBLZ0DuER3Ee1GdP6f30TVIXoEhvhQDwghaU12', b'$2b$12$rMeWZtAVcGHLEiDNeKCz8OiERmh0dh8AiNcf7ON3O3P0GWTABKh0O',
    #              b'$2b$12$rMeWZtAVcGHLEiDNeKCz8OMoFL0k33O8Lcq33f6AznAZ/cL1LAOyK', b'$2b$12$rMeWZtAVcGHLEiDNeKCz8Ose2KNe821.l2h5eLffzWoP01DlQb72O',
    #              b'$2b$13$6ypcazOOkUT/a7EwMuIjH.qbdqmHPDAC9B5c37RT9gEw18BX6FOay']
    # words_list = words.words()

    # # CRACK PASSWORDS FOR USERS
    # f = open("pass.txt", "a")
    # hash_index = 14
    # while(hash_index < len(hash_list)):
    #     for w in words_list:
    #         password = w.encode("utf-8")
    #         if checkpw(password, hash_list[hash_index]):
    #             print("Password for hash", hash_list[hash_index], "is", w)
    #             f.write("Password for hash", hash_list[hash_index], "is", w)
    #             hash_index = hash_index - 1
    #             break
    # f.close()
    
    #  b'$2b$12$rMeWZtAVcGHLEiDNeKCz8OiERmh0dh8AiNcf7ON3O3P0GWTABKh0O' was already found
    workforce_13 = [b'$2b$11$/8UByex2ktrWATZOBLZ0Dub5AmZeqtn7kv/3NCWBrDaRCFahGYyiq', b'$2b$11$/8UByex2ktrWATZOBLZ0DuER3Ee1GdP6f30TVIXoEhvhQDwghaU12', 
                    b'$2b$12$rMeWZtAVcGHLEiDNeKCz8OMoFL0k33O8Lcq33f6AznAZ/cL1LAOyK', 
                    b'$2b$12$rMeWZtAVcGHLEiDNeKCz8Ose2KNe821.l2h5eLffzWoP01DlQb72O', b'$2b$13$6ypcazOOkUT/a7EwMuIjH.qbdqmHPDAC9B5c37RT9gEw18BX6FOay']
    words_list = words.words()
    print("Length of words_list is ", len(words_list))
    f = open("pass.txt", "a")
    found_count = 0
    

    words_list = [ word for word in words_list if len(word) >= 6 or len(word) <= 10]
    # print(len(words_list))
    # print(len(words_nltk))
    words_list = list(filter(lambda x: len(x) >= 6, words_list))
    words_list = list(filter(lambda x: len(x) <= 10, words_list))
    index_to_start_at = words_list.index("corrosible")
    print("New length of list", len(words_list))
    
    words_list = words_list[index_to_start_at : len(words_list) - 1]
    # print(words_list[index_to_start_at])

    while (found_count < len(workforce_13)):
        for w in words_list:
            # print(w)
            password = w.encode("utf-8")
            for hash in workforce_13:
                if checkpw(password, hash):
                    print("Password for hash", hash, "is", w)
                    # str_to_write = "Password for hash" + hash + "is" + w
                    # f.write(str_to_write)
                    found_count = found_count + 1
                    break
    f.close()

def main():
    task1()
    task2()
   



main()