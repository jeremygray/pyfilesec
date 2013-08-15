"""Default encryption function for pyFileSec.
"""

@SetUmask
def _encrypt_rsa_aes256cbc(datafile, pub, OPENSSL=''):
    """Encrypt a datafile using openssl to do rsa pub-key + aes256cbc.
    """
    name = '_encrypt_rsa_aes256cbc'
    logging.debug('%s: start' % name)

    # Define file paths:
    data_enc = _uniq_file(abspath(datafile + AES_EXT))
    pwd_rsa = data_enc + RSA_EXT  # path to RSA-encrypted session key

    # Define command to RSA-PUBKEY-encrypt the pwd, save ciphertext to file:
    if use_rsautl:
        cmd_RSA = [OPENSSL, 'rsautl',
              '-out', pwd_rsa,
              '-inkey', pub,
              '-keyform', 'PEM',
              '-pubin',
              RSA_PADDING, '-encrypt']
    else:
        raise NotImplementedError

    # Define command to AES-256-CBC encrypt datafile using the password:
    cmd_AES = [OPENSSL, 'enc', '-aes-256-cbc',
              '-a', '-salt',
              '-in', datafile,
              '-out', data_enc,
              '-pass', 'stdin']

    # Generate a password (digital envelope "session" key):
    pwd = _printable_pwd(nbits=256)
    assert not whitespace_re.search(pwd)
    try:
        # encrypt the password:
        _sys_call(cmd_RSA, stdin=pwd)
        # encrypt the file, using password; takes a long time for large file:
        _sys_call(cmd_AES, stdin=pwd)
        # better to return immediately, del(pwd); using stdin blocks return
    finally:
        if 'pwd' in locals():
            del pwd  # might as well try

    return abspath(data_enc), abspath(pwd_rsa)


