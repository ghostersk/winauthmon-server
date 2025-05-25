#!/bin/bash
openssl req -x509 -newkey rsa:4096 \
    -keyout instance/certs/key.pem \
    -out instance/certs/cert.pem \
    -sha256 -days 3650 \
    -nodes \
    -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"