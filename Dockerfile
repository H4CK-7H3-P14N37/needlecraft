# Use the Kali rolling image as the base
FROM kalilinux/kali-rolling

# Set environment variables to minimize interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Update and upgrade system packages
RUN apt update && apt full-upgrade -y && apt autoremove -y && apt clean && apt install -y make iptables sudo

# Make directory for needlecraft build
RUN mkdir /root/needlecraft

# Copy contents
COPY . /root/needlecraft/

# Install needlecraft
RUN cd /root/needlecraft && make install