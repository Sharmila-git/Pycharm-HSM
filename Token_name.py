import pkcs11

from pkcs11 import mechanisms

class Identifytoken:
    def test():
        lib = pkcs11.lib("C:/Windows/System32/eps2003csp11v2.dll")
        token = lib.get_token(token_label='ePass2003-Palagiris')
        for slot in lib.get_slots():
            token = slot.get_token()
            print(token)

        if token.label == 'ePass2003-Palagiris':
           print(token)

        #with token.open(user_pin='Sharmi@123') as session:
        #  key=session.generate_key(pkcs11.KeyType)

Identifytoken.test()