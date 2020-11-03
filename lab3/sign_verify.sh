# Create primary key context
tpm2_createprimary -C o -g sha256 -G rsa -c context.out >> /dev/null

# Create public and private key objects
tpm2_create -G rsa -g sha256 -u rsa.pub -r rsa.priv -C context.out -c rsa.ctx >>/dev/null

# Load keypair into tpm
tpm2_load -C context.out -u rsa.pub -r rsa.priv -c rsa.ctx >>/dev/null

# Sign the document which name is specified by first arg to this script
tpm2_sign -Q -c rsa.ctx -g sha256 -f plain -o data.tpm2signed $1 >>/dev/null

# Export public key to be able to use it in openssl
tpm2_readpublic -c rsa.ctx -o public.pem -f pem >>/dev/null

# Verify the signature - should output Verified OK
openssl dgst -verify public.pem -keyform pem -sha256 -signature data.tpm2signed $1


