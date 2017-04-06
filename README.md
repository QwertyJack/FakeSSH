# Fake SSH
Forked from [tylermenezes/FakeSSH](https://github.com/tylermenezes/FakeSSH)

### What's new
* Add conf for `supervisor`
* Log ip address, username and password

### Usage
```sh
# checkout code and enter work directory
git clone https://github.com/QwertyJack/FakeSSH.git
cd FakeSSH

# copy config according to your need
cp data/config.json.sample data/config.json

# generate host key
ssh-keygen -t rsa -f data/rsa

# Optional: create the service
sudo cp ssh.conf /etc/supervisor/conf.d/
sudo sed -i 's#<.*>#'$(pwd)'#g' /etc/supervisor/conf.d/ssh.conf

# Optional: port forward 22 -> 8222
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 8222
```

See also '[README.md.orig](https://github.com/tylermenezes/FakeSSH#use)'
