FROM python:3.8-bullseye

# Set wine architecture to x64
ENV WINEARCH=win64

# Install wine
RUN dpkg --add-architecture i386
RUN apt update
RUN apt -y install gnupg2 software-properties-common
RUN wget -nc https://dl.winehq.org/wine-builds/winehq.key
RUN apt-key add winehq.key
RUN add-apt-repository 'deb https://dl.winehq.org/wine-builds/debian/ bullseye main'
RUN apt update
RUN apt install -y --install-recommends winehq-stable

# Install latest poetry
RUN curl -sSL https://install.python-poetry.org | python3 -

# Install winetricks ins the same directory as poetry
RUN wget https://raw.githubusercontent.com/Winetricks/winetricks/master/src/winetricks -O /root/.local/bin/winetricks
RUN chmod +x /root/.local/bin/winetricks

# Add root home to path where poetry was installed
ENV PATH="/root/.local/bin:${PATH}"

WORKDIR /opt/squadlanes


