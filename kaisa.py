def change(c,i):
    c = c.lower()
    num = ord(c)
    if num >= 97 and num <= 122:
        num = 97 + ((num - 97) + i) % 26
    return chr(num)


def kaisa_jiami(string,i):
    string_new = ''
    for s in string:
        string_new += change(s,i)
    print(string_new)
    return string_new

def kaisa_jiemi(string):
    for i in range(25):
        print(i)
        i += 1
        kaisa_jiami(string,i)


def main():
    print('please choose you want:')
    print('1:Caesar encode;')
    print('2:Caesar decode;')
    choice = raw_input()
    if choice == '1':
        string = raw_input('please input the string you want to encode:')
        num = int(raw_input('please input the number you want:'))
        kaisa_jiami(string,num)
    elif choice == '2':
        string = raw_input('please input the string you want to decode:')
        kaisa_jiemi(string)
    else:
        print('Wrong,please try again!')
        main()

if __name__ == '__main__':
    main()