import tempfile
import contextlib

from tpm2_pytss.fapi import FAPI, FAPIDefaultConfig
from tpm2_pytss.binding import *
from tpm2_pytss.util.simulator import Simulator

from hashlib import sha256

# Create context for TPM2 
def get_context():
    # Create a context stack
    ctx_stack = contextlib.ExitStack()
    
    # Create a simulator
    simulator = ctx_stack.enter_context(Simulator())
    
    # Create temporary directories to separate this example's state
    user_dir = ctx_stack.enter_context(tempfile.TemporaryDirectory())
    log_dir = ctx_stack.enter_context(tempfile.TemporaryDirectory())
    system_dir = ctx_stack.enter_context(tempfile.TemporaryDirectory())
    
    # Create the FAPI object
    fapi = FAPI(
        FAPIDefaultConfig._replace(
            user_dir=user_dir,
            system_dir=system_dir,
            log_dir=log_dir,
            tcti="mssim:port=%d" % (simulator.port,),
            tcti_retry=100,
            ek_cert_less=1,
        )
    )

    # Enter the context, create TCTI connection
    fapi_ctx = ctx_stack.enter_context(fapi)
    # Call Fapi_Provision
    fapi_ctx.Provision(None, None, None)
    
    return fapi_ctx
#  

# Providing context, path to key and document to sign
# return signature and public key (in pem format)
def sign(fapi_ctx, path_to_key, document):
    # Create pair of public, private keys
    fapi_ctx.CreateKey(path_to_key, None, None, None)
    
    # Get SHA256 digest of the document
    shaobj = sha256()
    shaobj.update(document)
    
    # Create an array of type UINT8 that will contain the hashlib
    # and will contain the signature 
    data = UINT8_ARRAY(nelements=shaobj.digest_size)
    for i, byte in enumerate(shaobj.digest()):
       data[i] = byte
    
    sig_der, pk_pem, cert_pem =\
        fapi_ctx.Sign(path_to_key, None, data.cast(), shaobj.digest_size)
    
    return sig_der, pk_pem
#

# Read document to be signed
doc_txt  = open("text.doc", "rb")
# Sign the document
sg, pk = sign(get_context(), "SRK/lab5_key", doc_txt.read())

# Write signature and public key to separate files
open('pub_key.pem', 'w').write(pk)
open('text.sig', 'wb').write(sg)
