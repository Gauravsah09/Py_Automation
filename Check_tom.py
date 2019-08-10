#########################################################################################
# This Script will check for alert URL HTTP response code and connectivity with server. #
# If URL is not reachable, login to the server, check tomcat/java service status and    #
# start the tomcat/java service if not running.                                         #
# Validate and return status.                                                           #
# Developed by - Gaurav Sah                                                             #
#########################################################################################

import paramiko
import logging
import Cred
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Connect:
    # Configuring a logger. This configuration is for storing status of steps in a logfile.
    LOG_FORMAT = "%(levelname)s %(asctime)s - %(message)s"
    logging.basicConfig(filename="C://path//to//log//file//Logs//Log1.log",
                        level=logging.DEBUG,
                        format=LOG_FORMAT,
                        filemode='w')
    global logger1
    logger1 = logging.getLogger()

    print("starting...")
    print("Testing URL...")
    alert_url = "http://yourtomcatserver:port"
    logger1.info("Connecting to url..")

    try:
        response = urlopen(Request(alert_url))
        logger1.info("URL Connected successfully!!")

        # Fetching hostname from the Alert URL
        host = alert_url[7:18]  # Adjust the indexes as per hostname
        # Displaying the http response status code
        logger1.info(f'{host} => gives the response code : ' +
                     str(response.getcode()) + " Cheers!!!")
        print(f'{host} => gives the response code : ' +
              str(response.getcode()) + " Cheers!!!")

    ###### Handeling HTTP and URL Exceptions and taking action connect to host > check tomcat > start if stopped ######
    except (HTTPError, URLError) as e:
        print('We failed to reach a server!!!')
        logger1.critical("We failed to reach a server.")
        #print('Reason: ', e.reason)
        host = alert_url[7:18]
        print(f'Effected Host : {host}')
        logger1.critical(f'Effected Host : {host}')

        # Starting SSH login to host
        global ssh
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
# function to decrypt the encrypted password which has been taken from another file Cred.py

        def decrypt_pass():
            key_word = b'any_keyword'
            salt = b'salt_'
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            global psswd
            key = base64.urlsafe_b64encode(
                kdf.derive(key_word))
            f = Fernet(key)
            decrypted = f.decrypt(Cred.credentials["pswd"])
            psswd = decrypted.decode()
        print("Decrypting Password...")
        decrypt_pass()
        print("Password Decrypted")

        try:
            print("creating connection to :", host)
            logger1.info(f'creating connection to host:{host}')
            ssh.connect(
                host, username=Cred.credentials["user_name"], password=psswd)
            print("Connected")
            logger1.info("Connected")

        # Function check_tom() created to run the command
            def check_tom():
                print("Checking if Tomcat is up >>")
                #logger1.info("Checking if Tomcat is up >>")
                for i in range(3):
                    print("*"*20)
                    print(f'Test {i} :')

                    # Running command in shell to get the Process ID of Tomcat
                    Tomcat_processId = "ps -ef | awk '/[t]omcat/{print $2}'"
                    stdin, stdout, stderr = ssh.exec_command(Tomcat_processId)

                    # Creating a list to store output
                    Tom_PID_list = []
                    Tom_PID_list = stdout.readlines()
                    print(Tom_PID_list)

                    # Calculating the length of Tomcat Process ID list
                    global TomcatPID_Length
                    TomcatPID_Length = len(Tom_PID_list)
                    print('Tomcat PID List Length is: ', TomcatPID_Length)
                    print("*"*20)
                # Below flag logic is for 2nd time validation
                global flag1
                if TomcatPID_Length == 1:
                    flag1 = True
                else:
                    flag1 = False
                print(flag1)
            # function call to check tomcat
            check_tom()

            # Checking if the length of PID is > 0
            # if PID length is greater than zero,then Tomcat is running
            # else tomcat is not running. STARTING Tomcat ...
            if(TomcatPID_Length > 0):
                print("Tomcat is running fine on host :", host)
                logger1.info(f'tomcat is running fine on host: {host}')

            elif(TomcatPID_Length == 0):
                print(
                    f'Tomcat is not running on host : {host}, we are going to restart')
                logger1.critical(f'Tomcat is not running!!! on :{host}')
                logger1.info("Restarting Tomcat...")
                stdin, stdout, stderr = ssh.exec_command(
                    'cd /path/to/your/tomcat/directory/apache-tomcat-7.0.94;./bin/startup.sh')
                # print(stdout.readlines())
                print("Tomcat has been started")
                logger1.info("Tomcat has been started")

                print("Validating tomcat restart...")
                logger1.info("Validating tomcat restart...")
                # function call again to check tomcat
                check_tom()

                # status check after restart if it's successfull or again its a failure
                if flag1 is True:
                    print("Tomcat started successfully!!")
                    logger1.info("Tomcat started successfully!!")
                else:
                    print("Assign the ticket to DES WebOps Team")
                    logger1.critical("Assign the ticket to your_support_Team")
                    # Here you can Add the code logic as per your Organization Ticketing tool
        except Exception as e:
            print("something went wrong!!"+"\n", e)
            logger1.error(e)
            print("check the log file")
        finally:
            print("Closing connection")
            logger1.info("Closing connection")
            ssh.close()
            print("Connection closed")
            logger1.info("Connection closed")


if __name__ == '__main__':
    #print("Start of %s" % __file__)
    Connect()
