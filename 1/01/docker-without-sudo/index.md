# 

# 如何使用非root用户执行docker命令


### Add the docker group if it doesn't already exist:

sudo groupadd docker

### Add the connected user "$USER" to the docker group. Change the user name to match your preferred user if you do not want to use your current user:

sudo gpasswd -a $USER docker

### Either do a newgrp docker or log out/in to activate the changes to groups.


