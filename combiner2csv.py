# Combine swodecoder file into a csv,
# in this case, reading two lines at a time, and just keeping the _integer_
# portion.  You NEED to know what your files look like before using this
# AND you need to know how your ITM writes are scheduled!
import sys

def go(ifname):
    """
    read from iff, write to stdout
    """
    #off = open(ofname, "wb")
    with open(ifname) as iff:

        for i,l1 in enumerate(iff):
            l2 = iff.next()
            l1_vals = l1.split(":")
            #print("l1", l1_vals)
            l2_vals = l2.split(":")
            #print("l2", l2_vals)
            print("{},{},{}".format(i, l1_vals[4].strip(), l2_vals[4].strip()))


if __name__ == "__main__":
    go(sys.argv[1])



