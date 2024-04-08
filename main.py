from io import StringIO
from prompts import *
import os


def main():

    if not os.path.exists("./certs/" ):
        os.mkdir("./certs")
    if not os.path.exists("./hist" ):
        os.mkdir("./hist")
    
    print("1. Create new certificate\n"
          "2. Listen\n"
          "3. Send\n"
          "4. Revoke Certificate\n"
          "5. Read past messages\n"
          "6. Accept new friends\n"
          "7. Send new friend request\n")

    line_reader = StringIO(input("Enter mode: "))
    mode = line_reader.readline().strip()

    if mode == "1":
        prompt_user_new_cert()
    elif mode == "2":
        prompt_create_listener()
    elif mode == "3":
        prompt_create_sender()
    elif mode == "4":
        prompt_revoke_certificate()
    elif mode == "5":
        prompt_read_past_messages()
    elif mode == "6":
        prompt_accept_new_friends()
    elif mode == "7":
        prompt_send_new_friend()    
    else:
        print("invalid mode input.\n")

if __name__ == "__main__":
    main()
