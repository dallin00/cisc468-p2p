import unittest
from unittest import mock
from unittest.mock import patch, MagicMock
from listener import *
from sender import *
from encryption import *
from certificates import *
from new_friends import *
from zeroconf_config import *

from prompts import *
import os
import time
#import signal
import sys
import threading
from json import dumps as _dumps


def bar():
    ans = input("enter yes or no")
    ans2 = input("")
    if ans == "yes" and ans2 == "no":
        print("yes")
    if ans == "no" and ans2 == "yes":
        print("")
        #return "you entered no"



    # add your assertions here

class Tests(unittest.TestCase):

    @patch('builtins.print')
    def test_myMethod(self, mock_print):

        mock_args = ['yes', 'no']
        with mock.patch('builtins.input') as mocked_input:
            mocked_input.side_effect = mock_args
            bar()
            self.assertEqual(mock_print.mock_calls, [mock.call("yes")])

    #def setUp(self):

class Test1(unittest.TestCase):
    #test certificate creation

    @patch('builtins.print')
    def test(self, mock_print):

        mock_args = ['test1']
        with mock.patch('builtins.input') as mocked_input:
            mocked_input.side_effect = mock_args
            prompt_user_new_cert()
            self.assertEqual(mock_print.mock_calls, [mock.call("Certificate created successfully")])
        

    def tearDown(self):
        time.sleep(0.5)
        os.remove("test1.crt")
        os.remove("test1.key")


class Test2(unittest.TestCase):
    #listener with certificate

    def setUp(self):
        create_self_certificate("listener")

    @patch('builtins.print')
    def test(self, mock_print):

        mock_args = ['listener.crt', 'listener.key', '1234567']
        with mock.patch('builtins.input') as mocked_input:
            mocked_input.side_effect = mock_args
            prompt_create_listener()
            self.assertEqual(mock_print.mock_calls, [mock.call("Listening on 8081")])

        print("Press ctrl-c to continue tests")

    def tearDown(self):
        #def signal_handler(signal, frame):

        time.sleep(0.5)
        os.remove("listener.crt")
        os.remove("listener.key")

    #def tearDown(self):

class Test3(unittest.TestCase):
    #listner with no certificate

    @patch('builtins.print')
    def test(self, mock_print):



        mock_args = ['listener2.crt', 'listener2.key', '1234567']
        with mock.patch('builtins.input') as mocked_input:
            mocked_input.side_effect = mock_args
            prompt_create_listener()
            self.assertEqual(mock_print.mock_calls, [mock.call('prompt_create_listener: listener2.crt does not exist')])
        

if __name__ == '__main__':
    unittest.main()