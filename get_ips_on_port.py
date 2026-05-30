export SWITCH_USER='your_username'
export SWITCH_PASSWORD='your_password'
python get_ips_on_port.py \
    --host 192.168.1.1 \
    --interface GigabitEthernet1/0/17 \
    --subnet 192.168.1.0/24
