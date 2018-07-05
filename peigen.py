
import re

alphabet = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']

first_cipher = ["aaaaa","aaaab","aaaba","aaabb","aabaa","aabab","aabba","aabbb","abaaa","abaab","ababa","ababb","abbaa","abbab","abbba","abbbb","baaaa","baaab","baaba","baabb","babaa","babab","babba","babbb","bbaaa","bbaab"]

second_cipher = ["aaaaa","aaaab","aaaba","aaabb","aabaa","aabab","aabba","aabbb","abaaa","abaaa","abaab","ababa","ababb","abbaa","abbab","abbba","abbbb","baaaa","baaab","baaba","baabb","baabb","babaa","babab","babba","babbb"]

def encode():
    upper_flag = False
    string = raw_input("please input string to encode:\n")
    if string.isupper():
        upper_flag = True
        string = string.lower()
    e_string1 = ""
    e_string2 = ""
    for index in string:
        for i in range(0,26):
            if index == alphabet[i]:
                e_string1 += first_cipher[i]
                e_string2 += second_cipher[i]
                break
    if upper_flag:
        e_string1 = e_string1.upper()
        e_string2 = e_string2.upper()
    print "first encode method result is:\n"+e_string1
    print "second encode method result is:\n"+e_string2
    return


def decode():
    upper_flag = False
    e_string = raw_input("please input string to decode:\n")
    if e_string.isupper():
        upper_flag = True
        e_string = e_string.lower()
    e_array = re.findall(".{5}",e_string)
    d_string1 = ""
    d_string2 = ""
    for index in e_array:
        for i in range(0,26):
            if index == first_cipher[i]:
                d_string1 += alphabet[i]
            if index == second_cipher[i]:
                d_string2 += alphabet[i]
    if upper_flag:
        d_string1 = d_string1.upper()
        d_string2 = d_string2.upper()
    print "first decode method result is:\n"+d_string1
    print "second decode method result is:\n"+d_string2
    return


if __name__ == '__main__':
    print "\t\tcoding by qux"
    while True:
        print "\t*******Bacon Encode_Decode System*******"
        print "input should be only lowercase or uppercase,cipher just include a,b(or A,B)"
        print "1.encode\n2.decode\n3.exit"
        s_number = raw_input("please input number to choose\n")
        if s_number == "1":
            encode()
            raw_input()
        elif s_number == "2":
            decode()
            raw_input()
        elif s_number == "3":
            break
        else:
            continue