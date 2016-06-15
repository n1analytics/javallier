import subprocess
import base64

# def execute_shell_command(cmd, stdout=None, stderr=None):
#     try:
#         ## start a process from the root of the project
#         return subprocess.Popen(cmd, cwd="../../target/scala-2.10/", shell=True, stdout=stdout, stderr=stderr, preexec_fn=os.setsid)
#     except OSError as e:
#         print("Execution failed:", e, file=sys.stderr)

def run_jar_command(cmd):
    proc = subprocess.Popen(['java', '-jar', 'javallier.jar'] + list(cmd), cwd="../../../../../../../target/scala-2.10/", universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()

    # print("cmd[" + str(cmd) + "] err: " + str(err))

    if('Exception' in err or 'Parsing failed' in err):
        raise RuntimeError("javallier.jar raises an exception: " + err)

    return out, err


def check_help_command_output(out, command):
    assert 'usage:' in out
    assert command in out
    assert 'Options:' in out


def check_help_output(out):
    check_help_command_output(out, 'Commands:')


def check_genpkey_output(out):
    assert 'pub' in out
    assert 'kty' in out
    assert 'lambda' in out
    assert 'mu' in out


def check_genpkey_message_output(out, msg):
    check_genpkey_output(out)
    assert msg in out


def check_genpkey_verbose_output(out, err):
    # 'genpkey' output is redirected to stdout
    check_genpkey_output(out)
    # But 'verbose' output is redirected to stderr
    assert 'INFO' in err


def get_keylength(priv_key):
    mod = priv_key['pub']['n']
    return int.from_bytes(base64.b64decode(mod),'big').bit_length()


def check_extracted_public_key(pub_key_json):
    assert 'n' in pub_key_json
    assert 'kty' in pub_key_json
    assert 'alg' in pub_key_json
    assert 'lambda' not in pub_key_json
    assert 'mu' not in pub_key_json


def check_encrypted_number(out):
    assert 'e' in out
    assert 'v' in out


def check_decrypted_number(out):
    assert 'e' in out
    assert 'v' in out