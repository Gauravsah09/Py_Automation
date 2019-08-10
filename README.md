# Py_Automation
Server Side Automation for alerts

#########################################################################################
# This Script will check for alert URL HTTP response code and connectivity with server. #
# If URL is not reachable, it wll login to the server, check tomcat/java service status # 
# and                                                                                   #
# start the tomcat/java service if not running.                                         #
# Validate and return status.                                                           #
# Developed by - Gaurav Sah                                                             #
#########################################################################################

You can remove the Password Decryption part(because I have not included the Encryption part) and directly fetch the password from a python file by importing it as a module in you code.

**Create a file anyname.py >>  create a dictionary credentials in it and store the hostname and password as key value pairs.

credentials = {
  "Username" = "your_tomcat_hostname",
  "Password" = "host_password"
            }

In paramiko ssh connection. import it as anyname.credentials["Username"] and anyname.credentials["Password"]
