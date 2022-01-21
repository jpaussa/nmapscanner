FROM python:3

RUN mkdir -p /src
ADD setup.py /src
ADD nmapscanner.py /src
ADD nmapscanner_tests.py /src
ADD nmapscanner_tests_fixtures.py /src

RUN pip install --upgrade pip setuptools
RUN cd /src && pip install .

RUN apt-get update
RUN apt-get install -y nmap

CMD ["nmapscanner", "--help"]
