import codecs

APP_DEBUG = 1

colors = {
"WARN"     : "\033[1;31m",
"PROC"    : "\033[1;34m",
"SALT"    : "\033[1;36m",
"SUCC"    : "\033[0;32m",
"RESET"   : "\033[0;0m",
"NOTE"    : "\033[;1m",
}


def blog(msg, tp=None, enc=None):
    if not APP_DEBUG:
        return
    cl = ''
    if enc:
        msg = codecs.encode(msg, 'hex')
    if tp in colors:
        cl = colors[tp]
    print(cl + f"{msg}" + colors["RESET"])