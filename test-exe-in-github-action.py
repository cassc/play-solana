import subprocess
import logging
import sys


logging.basicConfig(stream=sys.stdout, format='%(filename)s %(lineno)3d - %(message)s', level=logging.DEBUG)


def wrap_except(func):
    '''
    Capture any exception, print it and exit
    '''
    def wrapper(*args):
        try:
            return func(*args)
        except KeyboardInterrupt:
            sys.exit(0)
        except Exception as e:
            logging.error(f'{args} {e}')
            sys.exit(1)
    return wrapper


@wrap_except
def execute(command, cwd=None):
    '''
    Execute a shell command and return standard output as string
    '''
    logging.info(f'{cwd or "./"}> {command}')

    p = subprocess.Popen(command, shell=True, text=True, stdout=subprocess.PIPE, cwd=cwd)
    (out, err) = p.communicate()

    logging.info(out or err)

    if err or p.returncode:
        raise Exception(f'{command} failed with status {p.returncode} and error {err or ""}')
    else:
        return out.strip()


if __name__ == '__main__':
    poly = '$POLY_HOME/poly.jar'
    execute(f'java -jar {poly} info', '/home')
