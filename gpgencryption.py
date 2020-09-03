#
# This is a helper script for python GPG encryption.
#
# The idea is to download a key by its fingerprint and to be able
# to use the key afterwards for encryption.
#
import os
import sys
import gnupg

class GPGEncryption:
    
    def __init__(self, home_dir, key_server='keys.openpgp.org',
                 sender_email_address=None, passphrase=None):

        self.debug_print = True
        self.key_server = key_server
        
        new_dir = self._check_and_create_homedir(home_dir)
    
        self.gpg = gnupg.GPG(gnupghome=home_dir)
        if sender_email_address:
            input_data = self.gpg.gen_key_input(name_email=sender_email_address,  passphrase=passphrase)
            if new_dir:
                # create a new key for signing                
                key = self.gpg.gen_key(input_data)
                        
    def _debug(self, message):
        if self.debug_print:            
            #print(message, file=sys.stderr)
            print(message, file=sys.stdout)
            
    def _check_and_create_homedir(self, home_dir):
        # if there is no directory, create one
        self._debug(f"+ Check home dir {home_dir}.")
        if not os.path.exists(home_dir):
            os.mkdir(home_dir)
            os.chmod(home_dir, 0o700)
            return True
        else:
            return False

    def _key_available(self, fingerprint):
        self._debug(f"+ Check if key {fingerprint} is locally available.")
        
        # check if recipient key is in keystore
        public_keys = self.gpg.list_keys()
        for k in public_keys:
            if k and k['fingerprint'] == fingerprint:
                self._debug("+ Yes")
                return k
        self._debug("+ No")
        return None

    def download_key(self, fingerprint, retries=3):
        if self._key_available(fingerprint):
            return True
        
        for i in range(0, retries):
            
            self._debug(f"+ Search for key {fingerprint} (retry #{i}).")
            found_keys = self.gpg.search_keys(fingerprint, self.key_server)
            self._debug(found_keys)
            for k in found_keys:
                if k and k['keyid'] == fingerprint:
                    self._debug("+ Key found. Importing key.")
                    return self.gpg.recv_keys(self.key_server, fingerprint) # returns an ImportResult                
        self._debug("+ Key not found.")
        return False

    def _prepare_encryption(self, recipient_fingerprint):
        if not self._key_available(recipient_fingerprint):
            # search and download missing key
            if not self.download_key(recipient_fingerprint):
                raise Exception('Recipient key is not available')
            
            if not self._key_available(recipient_fingerprint):
                # While we check the fprint on search result, there is no way to check the
                # fprint on the receive result directly. Therefore, we just look at the
                # fprint of the key in our keyring. If the right key is not yet there,
                # we stop here.
                raise Exception('Recipient key is not available')

        return True
    
    def encrypt_file(self, recipient_fprint, filename_in, filename_out):
        
        self._prepare_encryption(recipient_fprint)
        
        with open(filename_in, 'rb') as f:
            return self.encrypt_fh(recipient_fprint, f, filename_out)
        
    def encrypt_fh(self, recipient_fprint, fhandle, filename_out):
        
        self._prepare_encryption(recipient_fprint)
        
        # For the downloaded key, we checked the fingerprint.
        # Therefore, we can trust the key.
        status = self.gpg.encrypt_file(fhandle, recipients=[recipient_fprint],
                                       output=filename_out, always_trust=True, armor=False)
            
        if status.ok:
            return True
        else:
            self._debug('ok: ', status.ok)
            self._debug('status: ', status.status)
            self._debug('stderr: ', status.stderr)
            raise Exception("Can't encrypt file")
            
        return False

    def encrypt_text(self, recipient_fprint, text):
        self._prepare_encryption(recipient_fprint)
        
        status = self.gpg.encrypt(text, recipients=[recipient_fprint], always_trust=True)
            
        if status.ok:
            return str(status)
        else:
            self._debug('ok: ', status.ok)
            self._debug('status: ', status.status)
            self._debug('stderr: ', status.stderr)
            raise Exception("Can't encrypt text")
        
        return None
    
if __name__ == "__main__":
    home_dir = 'daten/gpg'
    recipient_key_fprint = '900611B00B54591F720E5BF656F9EDB79BE4CD06'
    passphrase = 'secret'

    enc = GPGEncryption(home_dir)
    enc.download_key(recipient_key_fprint)
    
    #enc = GPGEncryption(home_dir, recipient_key_fprint, passphrase)
    
    #status = enc.encrypt_file(recipient_key_fprint, '/etc/passwd', '/tmp/passwd.gpg')
    #cipher_text = enc.encrypt_text(recipient_key_fprint, 'hello')
    #print(cipher_text)
    
