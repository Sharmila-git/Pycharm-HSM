import pkcs11

lib = pkcs11.lib("C:/Windows/System32/eps2003csp11v2.dll")
for slot in lib.get_slots():
    token = slot.get_token()
    # Check the parameters
    if token.label == 'ePass2003-Palagiris':
        break
for token in lib.get_tokens(token_label='ePass2003-Palagiris'):
    print(token)
try:
    lib.get_token(token_label='ePass2003-Palagiris')
except NoSuchToken(null):
    pass
except MultipleTokensReturned:
    pass