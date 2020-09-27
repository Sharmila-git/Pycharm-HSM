                    ###############Get token information#############
# importing print function from _future_
from __future__ import print_function
# importing PYKCS11 packages
import PyKCS11
import platform
import sys

# declaring Object getInfo class for detecting token
#class: getInfo
#Identification of object with color
class getInfo(object):
    red = blue = magenta = normal = ""

# Declaring a colosize function
# Identification of object with color and size
    def colorize(self, text, arg):
        #Printing the token object color as Magneta
        #<Because the epass token is in blue-magneta color>
        print(self.magenta + text + self.blue, arg, self.normal)

# Declaring the function for Key token display
    def display(self, obj, indent=""):
        dico = obj.to_dict()
        for key in sorted(dico.keys()):
            type = obj.fields[key]
            left = indent + key + ":"
            if type == "flags":
                self.colorize(left, ", ".join(dico[key]))
            elif type == "pair":
                self.colorize(left, "%d.%d" % dico[key])
            else:
                self.colorize(left, dico[key])
#calling the libraby functions(_init_) for particular token with its color
    def __init__(self, lib=None):
        if sys.stdout.isatty() and platform.system().lower() != 'windows':
            self.red = "\x1b[01;31m"
            self.blue = "\x1b[34m"
            self.magenta = "\x1b[35m"
            self.normal = "\x1b[0m"
#Loading Pykcs11 library
        self.pkcs11 = PyKCS11.PyKCS11Lib()
#Load the path of the token dll file(present in your system)
        self.pkcs11.load("C:/Windows/System32/eps2003csp11v2.dll")

#defining a function to get slotInfo of the token
    def getSlotInfo(self, slot, slot_index, nb_slots):
        #print()
        print(self.red + "Slot %d/%d (number %d):" % (slot_index, nb_slots,
            slot) + self.normal)
        self.display(self.pkcs11.getSlotInfo(slot), " ")

    # defining a function to get tokenInfo
    def getTokenInfo(self, slot):
        #print tokenInfo
        print(" TokenInfo")
        #Displaying the tokenInfo of the slot
        self.display(self.pkcs11.getTokenInfo(slot), "  ")

#defining get mechanism info(different classes with semantics) for key size, color and slot
    def getMechanismInfo(self, slot):
        print("  Mechanism list: ")
        m = self.pkcs11.getMechanismList(slot)
        for x in m:
            self.colorize("  ", x)
            i = self.pkcs11.getMechanismInfo(slot, x)
            if not i.flags & PyKCS11.CKF_DIGEST:
                if i.ulMinKeySize != PyKCS11.CK_UNAVAILABLE_INFORMATION:
                    self.colorize("    ulMinKeySize:", i.ulMinKeySize)
                if i.ulMaxKeySize != PyKCS11.CK_UNAVAILABLE_INFORMATION:
                    self.colorize("    ulMaxKeySize:", i.ulMaxKeySize)
            #flag: is comparing with max and min Key size and getting the text
            self.colorize("    flags:", ", ".join(i.flags2text()))

#getting Info from slot of a token
    def getInfo(self):
        self.display(self.pkcs11.getInfo())

#defining the session Info function of the slot
    #password/pin of the epass Auto token
    def getSessionInfo(self, slot, pin="Sharmi@123"):
        print(" SessionInfo", end=' ')
        #open the slot session
        session = self.pkcs11.openSession(slot)

    # Verifying slot with invalid pin
    # Session should not get login
        if pin != "Sharmi@123":
            if pin is None:
                print("(using pinpad)")

    # Verifying slot with valid pin
            else:
                print("(using pin: %s)" % pin)
            #Session should get login with valid pin
            session.login(pin)
    #After successful login, print Session Info
        else:
           # print()
            self.display(session.getSessionInfo(), "  ")
    #if the pin is invalid, session get logout
        if pin:
            session.logout()


def usage():
    print("Usage:", sys.argv[0], end=' ')
    print("[-a][--all]", end=' ')
    print("[-p pin][--pin=pin] (use 'NULL' for pinpad)", end=' ')
    print("[-s slot][--slot=slot]", end=' ')
    print("[-c lib][--lib=lib]", end=' ')
    print("[-m][--mechanisms]", end=' ')
    print("[-h][--help]")


#Declaring main function by importing getopt package
if __name__ == '__main__':
    import getopt

    #try to get the all mechanisms like, pin, slot, lib, help, opensession
    try:
        opts, args = getopt.getopt(sys.argv[1:], "p:s:c:hoam",
            ["pin=", "slot=", "lib=", "help", "opensession", "all",
             "mechanisms"])
    except getopt.GetoptError:
        # print help information and exit:
        usage()
        sys.exit(2)

    slot = None
    lib = None
    pin = ""
    token_present = True
    list_mechanisms = False
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        if o in ("-p", "--pin"):
            pin = a
            if pin == "NULL":
                pin = None
        if o in ("-s", "--slot"):
            slot = int(a)
        if o in ("-c", "--lib"):
            lib = a
        if o in ("-a", "--all"):
            token_present = False
        if o in ("-m", "--mechanisms"):
            list_mechanisms = True

# If the list mechanism is true
# declare the getInfo from PyKCS11 library
    gi = getInfo(lib)
    gi.getInfo()

#getting the list of number of available slots
    slots = gi.pkcs11.getSlotList(token_present)
    print("Available Slots:", len(slots), slots)

#If length of the slots=0 system get exit
    if len(slots) == 0:
        sys.exit(2)

# If the slot is !=0: print the zeroth slot info
    if slot is not None:
        slots = [slots[slot]]
        print("Using slot:", slots[0])

# If the slot index is 0:
    slot_index = 0
    #number of slots is slots count
    nb_slots = len(slots)
#Slot index should get increase with 1
    for slot in slots:
        slot_index += 1

# get the SlotInfo with slot, slot_index, number of slots
# get the session Info of slot and pin
# get token info in the token
        try:
            gi.getSlotInfo(slot, slot_index, nb_slots)
            gi.getSessionInfo(slot, pin)
            gi.getTokenInfo(slot)
        # getting the list_mechanism info of the slot
            if list_mechanisms:
                gi.getMechanismInfo(slot)

# catch PyKCS11 error: if the list_mechanism of the slot is not detecting
        except PyKCS11.PyKCS11Error as e:
            print("Error:", e)