prefix ?= /data/needlecraft
# TODO: install python and nmap from source
install:
	# Install system dependancies
	apt install -y curl unzip xvfb python3 python3-dev python3-venv git make gcc tor ffmpeg sslscan \
	libssl-dev g++ libnss3 libnss3-dev libnss3-tools build-essential cmake git \
	libexpat1-dev libssl-dev zlib1g-dev libncurses-dev libbz2-dev liblzma-dev \
	libsqlite3-dev libffi-dev tcl-dev linux-headers-generic libgdbm-dev libreadline-dev \
	tk tk-dev libgdbm-compat-dev libbluetooth-dev python3-pkgconfig libgirepository1.0-dev \
	mariadb-server libmariadb-dev iptables libcairo2-dev
	
	# setup application directories
	mkdir -p ${prefix}/opt
	mkdir -p ${prefix}/bin
	mkdir ${prefix}/reports
	mkdir -p ${prefix}/api_classes
	mkdir -p ${prefix}/bin/nmap/bin
	
	# setup a static version of chrome to run headless
	# https://googlechromelabs.github.io/chrome-for-testing/#stable
	curl -Lo "./chrome-linux.zip" "https://storage.googleapis.com/chrome-for-testing-public/132.0.6834.83/linux64/chrome-linux64.zip"
	curl -Lo "./chromedriver.zip" "https://storage.googleapis.com/chrome-for-testing-public/132.0.6834.83/linux64/chromedriver-linux64.zip"
	unzip ./chromedriver.zip -d ${prefix}/opt/
	unzip ./chrome-linux.zip -d ${prefix}/opt/
	
	# install python from source to support nmap and be optimized
	curl -Lo "./python3.tgz" "https://www.python.org/ftp/python/3.13.1/Python-3.13.1.tgz"
	tar zxvf ./python3.tgz
	cd Python-* && ./configure --enable-loadable-sqlite-extensions --prefix=${prefix}/opt/python3 --enable-optimizations && make &&	make install && cd ..
	
	# create virtual environment
	python3 -mvenv ${prefix}/env
	${prefix}/env/bin/pip install -r ./config/requirements.txt
	${prefix}/env/bin/pip install --upgrade pip build setuptools
	
	# setup nmap
	curl -Lo "./nmap.tgz" "https://nmap.org/dist/nmap-7.95.tgz"
	tar xvzf ./nmap.tgz
	export PYTHON=${prefix}/env/bin/python3 && cd nmap-* && ./configure --prefix=${prefix}/opt/nmap && make && make install
	# ln -s ${prefix}/opt/nmap/bin/nmap /usr/bin/nmap
	
	# setup masscan
	git clone https://github.com/robertdavidgraham/masscan.git
	cd masscan && make
	cp masscan/bin/masscan ${prefix}/opt/
	# ln -s ${prefix}/opt/masscan /usr/bin/masscan
	
	# setup needlecraft scanning
	cp -r api_classes ${prefix}/
	cp -r config ${prefix}/
	cp -r scripts ${prefix}/
	ln -s ${prefix}/scripts/exercism /usr/local/bin/exercism
	chmod 755 /usr/local/bin/exercism
	ln -s ${prefix}/scripts/salvare /usr/local/bin/salvare
	chmod 755 /usr/local/bin/salvare
	
	# setup tor
	cp -f config/torrc /etc/tor/torrc
	systemctl restart tor
	systemctl enable tor
	
	# clean up downloaded source code files
	rm -rf nmap-* nmap.tgz chromedriver.zip chrome-linux.zip python3.tgz Python-*

clean:
	rm -rf ${prefix}/
	rm -rf ./masscan
	rm -rf ./nmap-*
	rm -rf ./Python-*
	rm -rf ./python3.tgz
	rm -rf ./chrome*
	rm -rf /usr/local/bin/exercism
	rm -rf /usr/local/bin/salvare
	rm -rf /usr/bin/nmap
	rm -rf /usr/bin/masscan
