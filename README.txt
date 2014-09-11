To install launch_xml & tools and launchd, do:

make 
make install # (As superuser)
make clean

In the /boot/loader.conf set the init_path to the following:

init_path="/sbin/launchd"

For more documentation on how to use launch_xml see:

./launch_xml/README.txt


