FROM ubuntu:24.04

# Install xinetd
RUN apt-get update && apt-get install -y \
    xinetd \
    && apt-get clean

# Add the xinetd configuration file
COPY xinetd.conf /etc/xinetd.conf

# Create xinetd log directory and file, adjust permissions
RUN mkdir -p /var/log && touch /var/log/xinetd.log
RUN chmod -R 755 /var/log/
RUN chown nobody:nogroup /var/log/xinetd.log

# Add the service-specific xinetd configuration
COPY very_normal_device.conf /etc/xinetd.d/very_normal_device

# Copy service binary to container
COPY very_normal_device_srv.bin /usr/local/bin/very_normal_device_srv.bin
# Set the binary as executable
RUN chmod +x /usr/local/bin/very_normal_device_srv.bin
# Add very-normal-device to /etc/services 
RUN echo "very-normal-device    41414/tcp   # Very Normal Device Service" >> /etc/services

# Add the greynoise user somewhere in the container, put a silly smileyface
# Dont use the account otherwise
RUN useradd -m greynoise
RUN echo ":)" > /home/greynoise/README.md

# Expose the port for the service
EXPOSE 41414

# Place flag
RUN echo "flag{r3m0t3-c0d3-3x3cut10n-g0-brrrr}" > /flag.txt
RUN echo "Challenge 2:" >> /flag.txt
RUN echo "13.222.128.121" >> /flag.txt
RUN echo "greynoise" >> /flag.txt
RUN echo 'u1J2&o2k(fy~-}n^k}*a%T]D' >> /flag.txt

# Start xinetd in the foreground
CMD /usr/sbin/xinetd -dontfork -filelog /var/log/xinetd.log