import unittest
from unittest import TestCase
import tempfile
import json
import math
import random

from util import *

class HelpTest(TestCase):

    def test_empty_argument(self):
        # Display javallier help menu if no command is provided
        out, err = run_jar_command([''])
        check_help_output(out)

    def test_help_command(self):
        # Display javallier help menu if --help is provided
        out, err = run_jar_command(['--help'])
        check_help_output(out)

    def test_help_short_command(self):
        # Display javallier help menu if -h is provided
        out, err = run_jar_command(['-h'])
        check_help_output(out)

    def test_help_commands_same_output(self):
        # --help and -h return the same help menu
        outLong, errLong = run_jar_command(['--help'])
        outShort, errShort = run_jar_command(['-h'])
        self.assertEqual(outLong, outShort, "-h and --help returns different result!")

    def test_genpkey_help(self):
        out, err = run_jar_command(['genpkey', '--help'])
        check_help_command_output(out, 'genpkey')

    def test_extract_help(self):
        out, err = run_jar_command(['extract', '--help'])
        check_help_command_output(out, 'extract')

    def test_encrypt_help(self):
        out, err = run_jar_command(['encrypt', '--help'])
        check_help_command_output(out, 'encrypt')

    def test_decrypt_help(self):
        out, err = run_jar_command(['decrypt', '--help'])
        check_help_command_output(out, 'decrypt')

    def test_add_help(self):
        out, err = run_jar_command(['add', '--help'])
        check_help_command_output(out, 'add')

    def test_addenc_help(self):
        out, err = run_jar_command(['addenc', '--help'])
        check_help_command_output(out, 'addenc')

    def test_multiply_help(self):
        out, err = run_jar_command(['multiply', '--help'])
        check_help_command_output(out, 'multiply')


class GenpkeyTest(TestCase):

    def test_genpkey(self):
        # Generate keypair with default key length (2048)
        def_keylength = 2048
        out, err = run_jar_command(['genpkey'])
        check_genpkey_output(out)
        priv_key = json.loads(out)
        self.assertEqual(get_keylength(priv_key), def_keylength, "Generated key length is not " + str(def_keylength))

    def test_genpkey_message_short(self):
        out, err = run_jar_command(['genpkey', '-m', 'Generate default key'])
        check_genpkey_message_output(out, '"kid":"Generate default key"')

    def test_genpkey_message(self):
        out, err = run_jar_command(['genpkey', '--message', 'Generate default key'])
        check_genpkey_message_output(out, '"kid":"Generate default key"')

    def test_genpkey_verbose_short(self):
        out, err = run_jar_command(['genpkey', '-v'])
        # Not sure why the output of verbose is redirected to stderr instead of stdout!
        check_genpkey_verbose_output(out, err)

    def test_genpkey_verbose(self):
        out, err = run_jar_command(['genpkey', '--verbose'])
        # Not sure why the output of verbose is redirected to stderr instead of stdout!
        check_genpkey_verbose_output(out, err)

    def test_genpkey_tofile(self):
        with tempfile.NamedTemporaryFile() as outfile:
            run_jar_command(['genpkey', outfile.name])

            outfile.seek(0)
            written_data = outfile.read()

            priv_key = json.loads(written_data.decode('utf-8'))
            check_genpkey_output(priv_key)
            self.assertEqual(get_keylength(priv_key), 2048, "Generated key length is not 2048")

    def test_genpkey_various_keylength(self):
        for kl in [256, 512, 1024, 2048, 4096, 8192]:
            out, err = run_jar_command(['genpkey', '-s', str(kl)])
            check_genpkey_output(out)
            priv_key = json.loads(out)
            self.assertEqual(get_keylength(priv_key), kl, "Generated key length is not " + str(kl))


class ExtractTest(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.private_keyfile = tempfile.NamedTemporaryFile()
        run_jar_command(['genpkey', cls.private_keyfile.name])

    @classmethod
    def tearDownClass(cls):
        cls.private_keyfile.close()

    def test_extract_pubkey(self):
        with tempfile.NamedTemporaryFile() as outpubfile:
            run_jar_command(['extract', self.private_keyfile.name, outpubfile.name])
            outpubfile.seek(0)
            written_data = outpubfile.read()

            pub_key = json.loads(written_data.decode('utf-8'))
            check_extracted_public_key(pub_key)


class JavallierTestHelper(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.private_keyfile = tempfile.NamedTemporaryFile()
        cls.public_keyfile = tempfile.NamedTemporaryFile()

        run_jar_command(['genpkey', cls.private_keyfile.name])
        run_jar_command(['extract', cls.private_keyfile.name, cls.public_keyfile.name])

    @classmethod
    def tearDownClass(cls):
        cls.private_keyfile.close()
        cls.public_keyfile.close()

    def encrypt(self, num, encr_out=None):
        try:
            if encr_out is None:
                out, err = run_jar_command(['encrypt', self.public_keyfile.name, '--', str(num)])
                check_encrypted_number(out)
            else:
                run_jar_command(['encrypt', '-o', encr_out.name, self.public_keyfile.name, '--', str(num)])
        except RuntimeError as r:
            print("Unable to encrypt {} : {}".format(str(num), r))

    def decrypt(self, num, encr_out, decr_out):
        try:
            run_jar_command(['decrypt', '-o', decr_out.name, self.private_keyfile.name, encr_out.name])
            decr_out.seek(0)
            decr_num =  decr_out.read().decode("utf-8")
            self.assertAlmostEqual(float(num), float(decr_num))
        except RuntimeError as r:
            print("Unable to decrypt : {}".format(r))

    def addencr(self, encr1_file, encr2_file, addencr_file):
        try:
            run_jar_command(['addenc', '-o', addencr_file.name, self.public_keyfile.name, encr1_file.name, encr2_file.name])
        except RuntimeError as r:
            print("Unable to add two encrypted numbers : {}".format(r))

    def addencode(self, encr1_file, num2, addencr_file):
        try:
            run_jar_command(['add', '-o', addencr_file.name, self.public_keyfile.name, encr1_file.name, '--', str(num2)])
        except RuntimeError as r:
            print("Unable to add two encrypted numbers : {}".format(r))

    def mulencode(self, encr1_file, num2, mulencr_file):
        try:
            run_jar_command(['multiply', '-o', mulencr_file.name, self.public_keyfile.name, encr1_file.name, '--', str(num2)])
        except RuntimeError as r:
            print("Unable to add two encrypted numbers : {}".format(r))

    def encrypt_decrypt(self, num):
        with tempfile.NamedTemporaryFile() as encr_file, tempfile.NamedTemporaryFile() as decr_file:
            self.encrypt(num, encr_file)
            self.decrypt(num, encr_file, decr_file)

    def encr_add_encr(self, num1, num2):
        with tempfile.NamedTemporaryFile() as encr1, tempfile.NamedTemporaryFile() as encr2, \
                tempfile.NamedTemporaryFile() as addEncr, tempfile.NamedTemporaryFile() as addDecr:
            self.encrypt(num1, encr1)
            self.encrypt(num2, encr2)
            self.addencr(encr1, encr2, addEncr)
            self.decrypt((num1 + num2), addEncr, addDecr)

    def encr_add_encode(self, num1, num2):
        with tempfile.NamedTemporaryFile() as encr1, tempfile.NamedTemporaryFile() as addEncr, \
                tempfile.NamedTemporaryFile() as addDecr:
            self.encrypt(num1, encr1)
            self.addencode(encr1, num2, addEncr)
            self.decrypt((num1 + num2), addEncr, addDecr)

    def encr_mul_encode(self, num1, num2):
        with tempfile.NamedTemporaryFile() as encr1, tempfile.NamedTemporaryFile() as mulEncr, \
                tempfile.NamedTemporaryFile() as mulDecr:
            self.encrypt(num1, encr1)
            self.mulencode(encr1, num2, mulEncr)
            self.decrypt((num1 * num2), mulEncr, mulDecr)


class EncryptDecryptTest(JavallierTestHelper):

    def test_encrypt_positive_integers(self):
        for num in [0, 1, 2, 5, 10, 17, 10550, 1E120, 2E78]:
            self.encrypt(num)

    def test_encrypt_negative_integers(self):
        for num in [-0, -1, -2, -5, -10, -17, -10550, -1E120, -2E78]:
            self.encrypt(num)

    def test_encrypt_positive_doubles(self):
        # TODO Should test large positive doubles too??
        for num in [0.0, (1/3), 1.0, 1.72, math.e, math.pi, 4.1185, 10.0, 17.287]:
            self.encrypt(num)

    def test_encrypt_negative_doubles(self):
        # TODO Should test large negative doubles too??
        for num in [-0.0, -(1/3), -1.0, -1.72, -math.e, -math.pi, -4.1185, -10.0, -17.287]:
            self.encrypt(num)

    def test_encrypt_decrypt_positive_integers(self):
        for num in [0, 1, 2, 5, 10, 17, 10550, 1E120, 2E78]:
            self.encrypt_decrypt(num)

    def test_encrypt_decrypt_negative_integers(self):
        for num in [-0, -1, -2, -5, -10, -17, -10550, -1E120, -2E78]:
            self.encrypt_decrypt(num)

    def test_encrypt_decrypt_positive_doubles(self):
        # TODO Should test large positive doubles too??
        for num in [0.0, (1/3), 1.0, 1.72, math.e, math.pi, 4.1185, 10.0, 17.287]:
            self.encrypt_decrypt(num)

    def test_encrypt_decrypt_negative_doubles(self):
        # TODO Should test large negative doubles too??
        for num in [-0.0, -(1/3), -1.0, -1.72, -math.e, -math.pi, -4.1185, -10.0, -17.287]:
            self.encrypt_decrypt(num)


class AddEncrTest(JavallierTestHelper):

    def test_encr_add_encr_0(self):
        self.encr_add_encr(0, 0)

    def test_encr_add_encr_1(self):
        self.encr_add_encr(0, 1)

    def test_encr_add_encr_2(self):
        self.encr_add_encr(1, 0)

    def test_encr_add_encr_3(self):
        self.encr_add_encr(1, 1)

    def test_encr_add_encr_neg(self):
        self.encr_add_encr(0, -1)

    def test_encr_neg_add_encr(self):
        self.encr_add_encr(-1, 0)

    def test_encr_neg_add_encr_neg(self):
        self.encr_add_encr(-1, -1)

    def test_encr_frac_add_encr(self):
        self.encr_add_encr(0.5, 1)

    def test_encr_add_encr_frac(self):
        self.encr_add_encr(1, 0.5)

    def test_encr_frac_add_encr_frac(self):
        self.encr_add_encr(0.5, 1.5)

    def test_encr_frac_add_encr_neg(self):
        self.encr_add_encr(0.5, -1)

    def test_encr_neg_frac_add_encr(self):
        self.encr_add_encr(-0.5, 1)

    def test_encr_neg_frac_add_encr_neg_frac(self):
        self.encr_add_encr(-1.5, -0.5)


class AddTest(JavallierTestHelper):

    def test_encr_add_encode_0(self):
        self.encr_add_encode(0, 0)

    def test_encr_add_encode_1(self):
        self.encr_add_encode(0, 1)

    def test_encr_add_encode_2(self):
        self.encr_add_encode(1, 0)

    def test_encr_add_encode_3(self):
        self.encr_add_encode(1, 1)

    def test_encr_add_encode_neg(self):
        self.encr_add_encode(0, -1)

    def test_encr_neg_add_encode(self):
        self.encr_add_encode(-1, 0)

    def test_encr_neg_add_encode_neg(self):
        self.encr_add_encode(-1, -1)

    def test_encr_frac_add_encode(self):
        self.encr_add_encode(0.5, 1)

    def test_encr_add_encode_frac(self):
        self.encr_add_encode(1, 0.5)

    def test_encr_frac_add_encode_frac(self):
        self.encr_add_encode(0.5, 1.5)

    def test_encr_frac_add_encode_neg(self):
        self.encr_add_encode(0.5, -1)

    def test_encr_neg_frac_add_encode(self):
        self.encr_add_encode(-0.5, 1)

    def test_encr_neg_frac_add_encode_neg_frac(self):
        self.encr_add_encode(-1.5, -0.5)


class MulTest(JavallierTestHelper):

    def test_encr_mul_encode_0(self):
        self.encr_mul_encode(0, 0)

    def test_encr_mul_encode_1(self):
        self.encr_mul_encode(0, 1)

    def test_encr_mul_encode_2(self):
        self.encr_mul_encode(1, 0)

    def test_encr_mul_encode_3(self):
        self.encr_mul_encode(1, 1)

    def test_encr_mul_encode_neg(self):
        self.encr_mul_encode(0, -1)

    def test_encr_neg_mul_encode(self):
        self.encr_mul_encode(-1, 0)

    def test_encr_neg_mul_encode_neg(self):
        self.encr_mul_encode(-1, -1)

    def test_encr_frac_mul_encode(self):
        self.encr_mul_encode(0.5, 1)

    def test_encr_mul_encode_frac(self):
        self.encr_mul_encode(1, 0.5)

    def test_encr_frac_mul_encode_frac(self):
        self.encr_mul_encode(0.5, 1.5)

    def test_encr_frac_mul_encode_neg(self):
        self.encr_mul_encode(0.5, -1)

    def test_encr_neg_frac_mul_encode(self):
        self.encr_mul_encode(-0.5, 1)

    def test_encr_neg_frac_mul_encode_neg_frac(self):
        self.encr_mul_encode(-1.5, -0.5)


class FuzzTest(JavallierTestHelper):

    def test_fuzz_encr_large_number(self):
        MAX_VALUE = 10 ** 100
        MIN_VALUE = -MAX_VALUE

        for _ in list(range(10)):
            self.encrypt(random.uniform(MIN_VALUE, MAX_VALUE))

    def test_fuzz_encr_medium_number(self):
        MAX_VALUE = 10 ** 50
        MIN_VALUE = -MAX_VALUE

        for _ in list(range(10)):
            self.encrypt(random.uniform(MIN_VALUE, MAX_VALUE))

    def test_fuzz_encr_small_number(self):
        MAX_VALUE = 1000
        MIN_VALUE = -MAX_VALUE

        for _ in list(range(10)):
            self.encrypt(random.uniform(MIN_VALUE, MAX_VALUE))

    def test_fuzz_encr_very_small_number(self):
        MAX_VALUE = 1
        MIN_VALUE = -MAX_VALUE

        for _ in list(range(10)):
            self.encrypt(random.uniform(MIN_VALUE, MAX_VALUE))

    def test_fuzz_encr_decr_large_number(self):
        MAX_VALUE = 10 ** 100
        MIN_VALUE = -MAX_VALUE

        for _ in list(range(10)):
            self.encrypt_decrypt(random.uniform(MIN_VALUE, MAX_VALUE))

    def test_fuzz_encr_decr_medium_number(self):
        MAX_VALUE = 10 ** 50
        MIN_VALUE = -MAX_VALUE

        for _ in list(range(10)):
            self.encrypt_decrypt(random.uniform(MIN_VALUE, MAX_VALUE))

    def test_fuzz_encr_decr_small_number(self):
        MAX_VALUE = 1000
        MIN_VALUE = -MAX_VALUE

        for _ in list(range(10)):
            self.encrypt_decrypt(random.uniform(MIN_VALUE, MAX_VALUE))

    def test_fuzz_encr_decr_very_small_number(self):
        MAX_VALUE = 1
        MIN_VALUE = -MAX_VALUE

        for _ in list(range(10)):
            self.encrypt_decrypt(random.uniform(MIN_VALUE, MAX_VALUE))

    def test_fuzz_add_encr_large_number(self):
        MAX_VALUE = 10 ** 100
        MIN_VALUE = -MAX_VALUE

        for _ in list(range(10)):
            self.encr_add_encr(random.uniform(MIN_VALUE, MAX_VALUE), random.uniform(MIN_VALUE, MAX_VALUE))

    def test_fuzz_add_encr_medium_number(self):
        MAX_VALUE = 10 ** 50
        MIN_VALUE = -MAX_VALUE

        for _ in list(range(10)):
            self.encr_add_encr(random.uniform(MIN_VALUE, MAX_VALUE), random.uniform(MIN_VALUE, MAX_VALUE))

    def test_fuzz_add_encr_small_number(self):
        MAX_VALUE = 1000
        MIN_VALUE = -MAX_VALUE

        for _ in list(range(10)):
            self.encr_add_encr(random.uniform(MIN_VALUE, MAX_VALUE), random.uniform(MIN_VALUE, MAX_VALUE))

    def test_fuzz_add_encr_very_small_number(self):
        MAX_VALUE = 1
        MIN_VALUE = -MAX_VALUE

        for _ in list(range(10)):
            self.encr_add_encr(random.uniform(MIN_VALUE, MAX_VALUE), random.uniform(MIN_VALUE, MAX_VALUE))

    def test_fuzz_add_large_number(self):
        MAX_VALUE = 10 ** 100
        MIN_VALUE = -MAX_VALUE

        for _ in list(range(10)):
            self.encr_add_encode(random.uniform(MIN_VALUE, MAX_VALUE), random.uniform(MIN_VALUE, MAX_VALUE))

    def test_fuzz_add_medium_number(self):
        MAX_VALUE = 10 ** 50
        MIN_VALUE = -MAX_VALUE

        for _ in list(range(10)):
            self.encr_add_encode(random.uniform(MIN_VALUE, MAX_VALUE), random.uniform(MIN_VALUE, MAX_VALUE))

    def test_fuzz_add_small_number(self):
        MAX_VALUE = 1000
        MIN_VALUE = -MAX_VALUE

        for _ in list(range(10)):
            self.encr_add_encode(random.uniform(MIN_VALUE, MAX_VALUE), random.uniform(MIN_VALUE, MAX_VALUE))

    def test_fuzz_add_very_small_number(self):
        MAX_VALUE = 1
        MIN_VALUE = -MAX_VALUE

        for _ in list(range(10)):
            self.encr_add_encode(random.uniform(MIN_VALUE, MAX_VALUE), random.uniform(MIN_VALUE, MAX_VALUE))

    def test_fuzz_mul_large_number(self):
        MAX_VALUE = 10 ** 100
        MIN_VALUE = -MAX_VALUE

        for _ in list(range(10)):
            self.encr_mul_encode(random.uniform(MIN_VALUE, MAX_VALUE), random.uniform(MIN_VALUE, MAX_VALUE))

    def test_fuzz_mul_medium_number(self):
        MAX_VALUE = 10 ** 20
        MIN_VALUE = -MAX_VALUE

        for _ in list(range(10)):
            self.encr_mul_encode(random.uniform(MIN_VALUE, MAX_VALUE), random.uniform(MIN_VALUE, MAX_VALUE))

    def test_fuzz_mul_small_number(self):
        MAX_VALUE = 1000
        MIN_VALUE = -MAX_VALUE

        for _ in list(range(10)):
            self.encr_mul_encode(random.uniform(MIN_VALUE, MAX_VALUE), random.uniform(MIN_VALUE, MAX_VALUE))

    def test_fuzz_mul_very_small_number(self):
        MAX_VALUE = 1
        MIN_VALUE = -MAX_VALUE

        for _ in list(range(10)):
            self.encr_mul_encode(random.uniform(MIN_VALUE, MAX_VALUE), random.uniform(MIN_VALUE, MAX_VALUE))


class ExceptionTest(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.private_keyfile = tempfile.NamedTemporaryFile()
        cls.public_keyfile = tempfile.NamedTemporaryFile()

        run_jar_command(['genpkey', cls.private_keyfile.name])
        run_jar_command(['extract', cls.private_keyfile.name, cls.public_keyfile.name])

    @classmethod
    def tearDownClass(cls):
        cls.private_keyfile.close()
        cls.public_keyfile.close()

    def test_unrecognized_option(self):
        with self.assertRaises(RuntimeError):
            run_jar_command(['-q'])

    def test_negative_keysize(self):
        with self.assertRaises(RuntimeError):
            run_jar_command(['genpkey', '-s', '--', '-1'])

    def test_odd_keysize(self):
        with self.assertRaises(RuntimeError):
            run_jar_command(['genpkey', '-s', '9'])

    def test_keysize_less_than_eight(self):
        with self.assertRaises(RuntimeError):
            run_jar_command(['genpkey', '-s', '4'])

    def test_keysize_not_multiply_of_eight(self):
        with self.assertRaises(RuntimeError):
            run_jar_command(['genpkey', '-s', '12'])

    def test_encrypt_negative_number_without_escape(self):
        with self.assertRaises(RuntimeError):
            run_jar_command(['encrypt', self.public_keyfile.name, '-1'])

    def test_add_with_negative_number_without_escape(self):
        with tempfile.NamedTemporaryFile() as encr_out, tempfile.NamedTemporaryFile() as decr_out:
            run_jar_command(['encrypt', '-o', encr_out.name, self.public_keyfile.name, '1'])

            with self.assertRaises(RuntimeError):
                run_jar_command(['add', self.public_keyfile.name, encr_out.name, '-1'])

    def test_mul_with_negative_number_without_escape(self):
        with tempfile.NamedTemporaryFile() as encr_out, tempfile.NamedTemporaryFile() as decr_out:
            run_jar_command(['encrypt', '-o', encr_out.name, self.public_keyfile.name, '1'])

            with self.assertRaises(RuntimeError):
                run_jar_command(['mul', self.public_keyfile.name, encr_out.name, '-1'])

    def test_missing_argument(self):
        with self.assertRaises(RuntimeError):
            run_jar_command(['encrypt', self.public_keyfile.name])

    def test_encrypt_invalid_input(self):
        with self.assertRaises(RuntimeError):
            run_jar_command(['encrypt', self.public_keyfile.name, 'm'])

    def test_encrypt_with_private_key(self):
        with self.assertRaises(RuntimeError):
            run_jar_command(['encrypt', self.private_keyfile.name, '1'])

    def test_decrypt_with_public_key(self):
        with tempfile.NamedTemporaryFile() as encr_out, tempfile.NamedTemporaryFile() as decr_out:
            run_jar_command(['encrypt', '-o', encr_out.name, self.public_keyfile.name, '1'])

            with self.assertRaises(RuntimeError):
                run_jar_command(['decrypt', '-o', decr_out.name, self.public_keyfile.name, encr_out.name])


if __name__ == "__main__":
    unittest.main()