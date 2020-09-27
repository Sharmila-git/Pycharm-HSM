import PyKCS11.LowLevel
import sys
import PyKCS11
import pkcs11


# Initialise our PKCS#11 library
lib = pkcs11.lib("C:/Windows/System32/eps2003csp11v2.dll")
token = lib.get_token(token_label='ePass2003-Palagiris')

pkcs11 = PyKCS11.PyKCS11Lib()
PyKCS11.CK_TOKEN_INFO()
i= PyKCS11.CK_SLOT_INFO()
PyKCS11.CK_SESSION_INFO()
#i = pkcs11.getSlotInfo(0)
#pkcs11.openSession(0)
#print("Library manufacturerID: ") + info.manufacturerID

for slots in lib.get_slots():
    token = slots.get_token()
    if token.label == 'ePass2003-Palagiris':
        break
slots = pkcs11.getSlotList()
print ("Available Slots:"), len(slots)
for s in slots:
    try:
        i = pkcs11.getSlotInfo(s)
        print ("Slot no:"), s
        print(format_normal % ("slotDescription", i.slotDescription.strip()))
        print (format_normal % ("manufacturerID", i.manufacturerID.strip()))

        t = pkcs11.getTokenInfo(s)
        print ("TokenInfo")
        print (format_normal % ("label", t.label.strip()))
        print (format_normal % ("manufacturerID", t.manufacturerID.strip()))
        print (format_normal % ("model", t.model.strip()))


        session = pkcs11.openSession(s)
        print("Opened session 0x%08X" % session.session.value())
        if token_available:
            try:
                session.login(pin='Sharmi@123')
            except:
                print ("login failed, exception:", str(sys.exc_info()[1]))

        objects = session.findObjects()

        print ("Found %d objects: %s" % (len(objects), [x.value() for x in objects]))
    except:
        print("test")