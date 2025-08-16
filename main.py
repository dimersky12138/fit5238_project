import os
import time
import pyfiglet

def run_PE():
    file = input("Enter the path and name of the file : ")
    os.system("python Extract/PE_main.py {}".format(file))

def exit():
    os.system('exit')

def start():
    print(pyfiglet.figlet_format("Malware Detector"))
    print(" Welcome to antimalware detector \n")
    print(" 1. PE scanner")
    print(" 2. Exit\n")

    select = int(input("Enter your choice : "))

    if (select in [1,2,3]):

        if(select == 1):
            run_PE()
            choice = input("Do you want to search again? (y/n)")
            if(choice not in ['Y','N','n','y']):
                print("Bad input\nExiting...")
                time.sleep(3)
                exit()
            else:
                if(choice == 'Y' or 'y'):
                    start()
                elif(choice == 'N' or 'n'):
                    exit()
        else:
            exit()
    else:
        print("Bad input\nExiting...")
        time.sleep(3)
        exit()

start()