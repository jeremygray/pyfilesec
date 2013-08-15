"""Default decryption function for pyFileSec.

Gets execfile()d into the main code. Being a file makes it easy to obtain
a hash of the function.
"""

@SetUmask
def _decrypt_rsa_aes256cbc(data_enc, pwd_rsa, priv, pphr=None,
                           outFile='', OPENSSL=''):
    """Decrypt a file that was encoded by _encrypt_rsa_aes256cbc()
    """
    name = '_decrypt_rsa_aes256cbc'
    logging.debug('%s: start' % name)

    # set the name for decrypted file:
    if outFile:
        data_dec = outFile
    else:
        data_dec = os.path.splitext(abspath(data_enc))[0]
    #else:
    #    data_dec = abspath(data_enc)

    # set up the command to retrieve password from pwdFileRsa
    if use_rsautl:
        cmdRSA = [OPENSSL, 'rsautl',
                  '-in', pwd_rsa,
                  '-inkey', priv]
        if pphr:
            if isfile(pphr):
                logging.warning(name + ': reading passphrase from file')
                pphr = open(pphr, 'rb').read()
            cmdRSA += ['-passin', 'stdin']
        cmdRSA += [RSA_PADDING, '-decrypt']
    else:
        raise NotImplementedError

    # set up the command to decrypt the data using pwd:
    cmdAES = [OPENSSL, 'enc', '-d', '-aes-256-cbc', '-a',
              '-in', data_enc,
              '-out', data_dec,
              '-pass', 'stdin']

    # decrypt pwd (digital envelope "session" key) to RAM using private key
    # then use pwd to decrypt the ciphertext file (data_enc):
    try:
        if pphr and not isfile(pphr):
            pwd, se_RSA = _sys_call(cmdRSA, stdin=pphr, stderr=True)  # want se
        else:
            pwd, se_RSA = _sys_call(cmdRSA, stderr=True)  # want se, parse
        __, se_AES = _sys_call(cmdAES, stdin=pwd, stderr=True)
    except:
        if isfile(data_dec):
            destroy(data_dec)
        _fatal('%s: Could not decrypt (exception in RSA or AES step)' % name,
               DecryptError)
    finally:
        if 'pwd' in locals():
            del pwd  # might as well try

    if sys.platform == 'win32':
        unhelpful_glop = "Loading 'screen' into random state - done"
        se_RSA = se_RSA.replace(unhelpful_glop, '')
    if se_RSA.strip():
        if 'unable to load Private Key' in se_RSA:
            _fatal('%s: unable to load Private Key' % name, PrivateKeyError)
        elif 'RSA operation error' in se_RSA:
            _fatal("%s: can't use Priv Key; wrong key?" % name, DecryptError)
        else:
            _fatal('%s: Bad decrypt (RSA) %s' % (name, se_RSA), DecryptError)
    if se_AES:
        if 'bad decrypt' in se_AES:
            _fatal('%s: openssl bad decrypt (AES step)' % name, DecryptError)
        else:
            _fatal('%s: Bad decrypt (AES) %s' % (name, se_AES), DecryptError)

    return abspath(data_dec)
